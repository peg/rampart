// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	texttemplate "text/template"

	"github.com/spf13/cobra"
)

const plistLabel = "sh.rampart.serve"

var plistTmpl = htmltemplate.Must(htmltemplate.New("plist").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>sh.rampart.serve</string>
    <key>ProgramArguments</key>
    <array>
        <string>{{.Binary}}</string>
        <string>serve</string>{{range .Args}}
        <string>{{.}}</string>{{end}}
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RAMPART_TOKEN</key>
        <string>{{.Token}}</string>
    </dict>
    <key>WorkingDirectory</key>
    <string>{{.HomeDir}}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{{.LogPath}}</string>
    <key>StandardErrorPath</key>
    <string>{{.LogPath}}</string>
</dict>
</plist>
`))

var systemdTmpl = texttemplate.Must(texttemplate.New("unit").Funcs(texttemplate.FuncMap{
	"systemdQuote": systemdQuote,
}).Parse(`[Unit]
Description=Rampart Approval Server
After=network.target

[Service]
Type=simple
ExecStart={{systemdQuote .Binary}} serve{{range .Args}} {{systemdQuote .}}{{end}}
Environment={{systemdQuote (printf "RAMPART_TOKEN=%s" .Token)}}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
`))

// systemdQuote renders one systemd command/environment word without allowing
// whitespace, control characters, quotes, backslashes, or '%' specifiers to
// change the generated unit. Quoting every word also supports install paths
// and policy directories containing spaces.
func systemdQuote(value string) string {
	var b strings.Builder
	b.Grow(len(value) + 2)
	b.WriteByte('"')
	for _, r := range value {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '%':
			// systemd expands % specifiers even in quoted strings.
			b.WriteString("%%")
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\x%02x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// serviceConfig holds template data for service file generation.
type serviceConfig struct {
	Binary  string
	Args    []string
	Token   string
	LogPath string
	HomeDir string
}

// commandRunner abstracts exec.Command so we can mock in tests.
type commandRunner func(name string, args ...string) *exec.Cmd

var defaultRunner commandRunner = exec.Command

func buildServiceArgs(port int, configPath, configDir, auditDir, mode string, approvalTimeout string) []string {
	var args []string
	if port != 0 {
		args = append(args, "--port", fmt.Sprintf("%d", port))
	}
	if configPath != "" && configPath != "rampart.yaml" {
		args = append(args, "--config", configPath)
	}
	if configDir != "" {
		args = append(args, "--config-dir", configDir)
	}
	if auditDir != "" {
		args = append(args, "--audit-dir", auditDir)
	}
	if mode != "" && mode != "enforce" {
		args = append(args, "--mode", mode)
	}
	if approvalTimeout != "" && approvalTimeout != "5m" && approvalTimeout != "0s" {
		args = append(args, "--approval-timeout", approvalTimeout)
	}
	return args
}

func resolveServiceToken(tokenFlag string) (string, bool, error) {
	if tokenFlag != "" {
		return tokenFlag, false, nil
	}
	if tok, _ := resolveTokenValue(); tok != "" {
		return tok, false, nil
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", false, fmt.Errorf("generate token: %w", err)
	}
	return hex.EncodeToString(b), true, nil
}

// tokenFilePath returns the path to the persisted token file.
func tokenFilePath() (string, error) {
	dir, err := rampartDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "token"), nil
}

// persistToken writes the token to ~/.rampart/token with owner-only permissions.
// It secures a temporary file before writing the token, then atomically replaces
// the destination so a hardening failure cannot expose or destroy a valid token.
func persistToken(token string) error {
	p, err := tokenFilePath()
	if err != nil {
		return err
	}
	dir := filepath.Dir(p)
	if err := ensureRampartDirAccessible(dir); err != nil {
		return fmt.Errorf("prepare token directory: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create token directory: %w", err)
	}
	if err := secureDirPermissions(dir); err != nil {
		return fmt.Errorf("secure token directory: %w", err)
	}

	f, err := os.CreateTemp(dir, ".token-*")
	if err != nil {
		return fmt.Errorf("create temporary token file: %w", err)
	}
	tmpPath := f.Name()
	defer os.Remove(tmpPath)

	if err := secureFilePermissions(tmpPath); err != nil {
		_ = f.Close()
		return fmt.Errorf("secure temporary token file: %w", err)
	}
	if _, err := f.WriteString(token); err != nil {
		_ = f.Close()
		return fmt.Errorf("write temporary token file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temporary token file: %w", err)
	}
	if err := os.Rename(tmpPath, p); err != nil {
		return fmt.Errorf("replace token file: %w", err)
	}

	return nil
}

// readPersistedToken reads the token from ~/.rampart/token if it exists.
func readPersistedToken() (string, error) {
	p, err := tokenFilePath()
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func plistPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", plistLabel+".plist"), nil
}

func systemdUnitPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "systemd", "user", "rampart-serve.service"), nil
}

func logPath() string {
	home, _ := os.UserHomeDir()
	if home == "" {
		return "/tmp/rampart-serve.log"
	}
	return filepath.Join(home, ".rampart", "serve.log")
}

// stableServiceBinary prefers the PATH entry that resolves to the exact binary
// currently running. Package managers such as Homebrew expose a stable symlink
// while os.Executable can return a versioned Cellar path that is removed by the
// next upgrade. Identity checking prevents an unrelated PATH binary from being
// persisted into a trusted service definition.
func stableServiceBinary(binary string) string {
	name := filepath.Base(binary)
	candidate, err := execLookPath(name)
	if err != nil {
		return binary
	}
	candidate, err = filepath.Abs(candidate)
	if err != nil || samePath(candidate, binary) {
		return binary
	}

	currentInfo, currentErr := os.Stat(binary)
	candidateInfo, candidateErr := os.Stat(candidate)
	if currentErr != nil || candidateErr != nil || !os.SameFile(currentInfo, candidateInfo) {
		return binary
	}
	return candidate
}

// generatePlist returns the plist XML as a string.
func generatePlist(cfg serviceConfig) (string, error) {
	var b strings.Builder
	if err := plistTmpl.Execute(&b, cfg); err != nil {
		return "", err
	}
	return b.String(), nil
}

// generateSystemdUnit returns the systemd unit as a string.
func generateSystemdUnit(cfg serviceConfig) (string, error) {
	var b strings.Builder
	if err := systemdTmpl.Execute(&b, cfg); err != nil {
		return "", err
	}
	return b.String(), nil
}

func newServeInstallCmd(opts *rootOptions, runner commandRunner) *cobra.Command {
	var (
		port            int
		configDir       string
		auditDir        string
		mode            string
		approvalTimeout string
		tokenFlag       string
		force           bool
	)

	if runner == nil {
		runner = defaultRunner
	}

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install rampart serve as a system service",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if runtime.GOOS == "windows" {
				fmt.Fprintln(cmd.ErrOrStderr(), "Windows service installation is not supported.")
				fmt.Fprintln(cmd.ErrOrStderr(), "Use 'rampart serve --background' for this login, or Task Scheduler/NSSM for automatic startup.")
				return nil
			}

			binary, err := os.Executable()
			if err != nil {
				return fmt.Errorf("find rampart binary: %w", err)
			}
			binary, _ = filepath.Abs(binary)
			binary = stableServiceBinary(binary)

			token, generated, err := resolveServiceToken(tokenFlag)
			if err != nil {
				return err
			}

			// Warn only if a custom config path was given but the file doesn't exist.
			// When using the default path, rampart serve falls back to the embedded
			// standard policy automatically — no warning needed.
			if opts.configPath != "" && opts.configPath != "rampart.yaml" {
				if _, err := os.Stat(opts.configPath); os.IsNotExist(err) {
					fmt.Fprintf(cmd.ErrOrStderr(), "⚠ Warning: policy file not found: %s\n   The service may fail to start. Run `rampart init --detect` to create one.\n\n", opts.configPath)
				}
			}

			homeDir, _ := os.UserHomeDir()
			args := buildServiceArgs(port, opts.configPath, configDir, auditDir, mode, approvalTimeout)
			// Strip control characters from token before embedding in
			// service files. Newlines in a systemd Environment= directive
			// or plist <string> could inject arbitrary directives.
			safeToken := strings.NewReplacer("\n", "", "\r", "", "\t", "").Replace(token)
			cfg := serviceConfig{
				Binary:  binary,
				Args:    args,
				Token:   safeToken,
				LogPath: logPath(),
				HomeDir: homeDir,
			}

			switch runtime.GOOS {
			case "darwin":
				return installDarwin(cmd, cfg, force, generated, port, runner)
			case "linux":
				return installLinux(cmd, cfg, force, generated, port, runner)
			default:
				fmt.Fprintf(cmd.ErrOrStderr(), "Unsupported platform: %s. Run `rampart serve` manually.\n", runtime.GOOS)
				return nil
			}
		},
	}

	defaultAudit := ""
	if home, err := os.UserHomeDir(); err == nil {
		defaultAudit = filepath.Join(home, ".rampart", "audit")
	}

	cmd.Flags().IntVar(&port, "port", defaultServePort, "Port for the serve proxy")
	cmd.Flags().StringVar(&configDir, "config-dir", "", "Policy directory")
	cmd.Flags().StringVar(&auditDir, "audit-dir", defaultAudit, "Audit log directory")
	cmd.Flags().StringVar(&mode, "mode", "enforce", "Mode: enforce | monitor | disabled")
	cmd.Flags().StringVar(&approvalTimeout, "approval-timeout", "5m", "Approval timeout duration")
	cmd.Flags().StringVar(&tokenFlag, "token", "", "Override RAMPART_TOKEN for the service")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing service installation")

	return cmd
}

func installDarwin(cmd *cobra.Command, cfg serviceConfig, force, generated bool, port int, runner commandRunner) error {
	path, err := plistPath()
	if err != nil {
		return err
	}

	if _, err := os.Stat(path); err == nil && !force {
		fmt.Fprintf(cmd.ErrOrStderr(), "Service already installed at %s\nUse --force to overwrite.\n", path)
		return nil
	}

	_, existingErr := os.Stat(path)
	serviceExists := existingErr == nil

	content, err := generatePlist(cfg)
	if err != nil {
		return fmt.Errorf("generate plist: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// Ensure log directory exists.
	if err := os.MkdirAll(filepath.Dir(cfg.LogPath), 0o700); err != nil {
		return fmt.Errorf("create service log directory: %w", err)
	}

	// 0o600: plist contains RAMPART_TOKEN — must not be world-readable.
	// Chmod after write because os.WriteFile only applies the mode on creation;
	// an existing file with wrong permissions would not be updated otherwise.
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}
	_ = os.Chmod(path, 0o600)

	// Stop before rotating the shared token. Otherwise an old process can keep
	// authenticating with the previous token while hooks read the new one.
	if serviceExists {
		// A plist can exist while the job is already unloaded. Only unload a
		// job launchctl reports as loaded; a real unload failure is fatal.
		loaded, err := launchctlServiceLoaded(runner)
		if err != nil {
			return err
		}
		if loaded {
			if out, err := runner("launchctl", "unload", path).CombinedOutput(); err != nil {
				return fmt.Errorf("launchctl unload: %w\n%s", err, out)
			}
		}
	}
	if err := persistToken(cfg.Token); err != nil {
		return fmt.Errorf("persist service token: %w", err)
	}
	if out, err := runner("launchctl", "load", path).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl load: %w\n%s", err, out)
	}
	printSuccess(cmd, cfg.Token, generated, port, path)
	return nil
}

func installLinux(cmd *cobra.Command, cfg serviceConfig, force, generated bool, port int, runner commandRunner) error {
	path, err := systemdUnitPath()
	if err != nil {
		return err
	}

	if _, err := os.Stat(path); err == nil && !force {
		fmt.Fprintf(cmd.ErrOrStderr(), "Service already installed at %s\nUse --force to overwrite.\n", path)
		return nil
	}

	_, existingErr := os.Stat(path)
	serviceExists := existingErr == nil

	content, err := generateSystemdUnit(cfg)
	if err != nil {
		return fmt.Errorf("generate systemd unit: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	// 0o600: unit file contains RAMPART_TOKEN — must not be world-readable.
	// Chmod after write because os.WriteFile only applies the mode on creation.
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write unit: %w", err)
	}
	_ = os.Chmod(path, 0o600)

	// Fail closed during token rotation: stop the old process before changing
	// either the loaded unit or the token hooks will read.
	if serviceExists {
		if out, err := runner("systemctl", "--user", "stop", "rampart-serve.service").CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl stop: %w\n%s", err, out)
		}
	}
	if out, err := runner("systemctl", "--user", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w\n%s", err, out)
	}
	if err := persistToken(cfg.Token); err != nil {
		return fmt.Errorf("persist service token: %w", err)
	}
	if out, err := runner("systemctl", "--user", "enable", "rampart-serve.service").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl enable: %w\n%s", err, out)
	}
	if out, err := runner("systemctl", "--user", "start", "rampart-serve.service").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl start: %w\n%s", err, out)
	}
	printSuccess(cmd, cfg.Token, generated, port, path)
	return nil
}

func launchctlServiceLoaded(runner commandRunner) (bool, error) {
	out, err := runner("launchctl", "list", plistLabel).CombinedOutput()
	if err == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 113 {
		return false, nil
	}
	message := strings.ToLower(string(out))
	if strings.Contains(message, "could not find service") ||
		strings.Contains(message, "could not find specified service") {
		return false, nil
	}
	return false, fmt.Errorf("launchctl list %s: %w\n%s", plistLabel, err, out)
}

func printSuccess(cmd *cobra.Command, token string, generated bool, port int, path string) {
	w := cmd.ErrOrStderr()
	interactive := false
	if file, ok := w.(*os.File); ok {
		interactive = isTerminal(file)
	}
	fmt.Fprintf(w, "\n✅ Rampart service installed: %s\n", path)
	fmt.Fprintf(w, "   Dashboard: http://localhost:%d/dashboard/\n", port)
	if interactive {
		fmt.Fprintf(w, "   Token:     %s\n", token)
		fmt.Fprintf(w, "   (token also saved to ~/.rampart/token — hooks read it automatically)\n")
	} else {
		fmt.Fprintln(w, "   Token:     saved to ~/.rampart/token")
	}
	if generated && interactive {
		fmt.Fprintf(w, "\n   To persist across shell sessions:\n")
		fmt.Fprintf(w, "     echo 'export RAMPART_TOKEN=%s' >> ~/.zshrc\n", token)
	}
}
