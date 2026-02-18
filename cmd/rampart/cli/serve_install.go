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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"

	"github.com/spf13/cobra"
)

const plistLabel = "sh.rampart.serve"

var plistTmpl = template.Must(template.New("plist").Parse(`<?xml version="1.0" encoding="UTF-8"?>
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

var systemdTmpl = template.Must(template.New("unit").Parse(`[Unit]
Description=Rampart Approval Server
After=network.target

[Service]
Type=simple
ExecStart={{.Binary}} serve{{range .Args}} {{.}}{{end}}
Environment=RAMPART_TOKEN={{.Token}}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
`))

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
	if env := os.Getenv("RAMPART_TOKEN"); env != "" {
		return env, false, nil
	}
	// Check persisted token file written by a previous serve install.
	if tok, err := readPersistedToken(); err == nil && tok != "" {
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
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".rampart", "token"), nil
}

// persistToken writes the token to ~/.rampart/token (0600).
func persistToken(token string) error {
	p, err := tokenFilePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(token), 0o600)
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
				fmt.Fprintln(cmd.ErrOrStderr(), "Windows is not yet supported. Run `rampart serve` manually.")
				return nil
			}

			binary, err := os.Executable()
			if err != nil {
				return fmt.Errorf("find rampart binary: %w", err)
			}
			binary, _ = filepath.Abs(binary)

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
			cfg := serviceConfig{
				Binary:  binary,
				Args:    args,
				Token:   token,
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

	cmd.Flags().IntVar(&port, "port", 18275, "Port for the serve proxy")
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

	// Unload any existing service before writing new plist.
	// Best-effort: ignore errors if the service wasn't loaded.
	if _, err := os.Stat(path); err == nil {
		_, _ = runner("launchctl", "unload", path).CombinedOutput()
	}

	content, err := generatePlist(cfg)
	if err != nil {
		return fmt.Errorf("generate plist: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// Ensure log directory exists.
	_ = os.MkdirAll(filepath.Dir(cfg.LogPath), 0o755)

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}

	if out, err := runner("launchctl", "load", path).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl load: %w\n%s", err, out)
	}

	if err := persistToken(cfg.Token); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "⚠ Warning: could not save token to ~/.rampart/token: %v\n", err)
		fmt.Fprintf(cmd.ErrOrStderr(), "  Run: echo '%s' > ~/.rampart/token\n", cfg.Token)
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

	content, err := generateSystemdUnit(cfg)
	if err != nil {
		return fmt.Errorf("generate systemd unit: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// Ensure log directory exists.
	_ = os.MkdirAll(filepath.Dir(cfg.LogPath), 0o755)

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write unit: %w", err)
	}

	// Stop the old service before reload so the new binary/token take effect.
	_, _ = runner("systemctl", "--user", "stop", "rampart-serve.service").CombinedOutput()

	if out, err := runner("systemctl", "--user", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w\n%s", err, out)
	}
	if out, err := runner("systemctl", "--user", "enable", "--now", "rampart-serve.service").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl enable: %w\n%s", err, out)
	}

	if err := persistToken(cfg.Token); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "⚠ Warning: could not save token to ~/.rampart/token: %v\n", err)
		fmt.Fprintf(cmd.ErrOrStderr(), "  Run: echo '%s' > ~/.rampart/token\n", cfg.Token)
	}
	printSuccess(cmd, cfg.Token, generated, port, path)
	return nil
}

func printSuccess(cmd *cobra.Command, token string, generated bool, port int, path string) {
	w := cmd.ErrOrStderr()
	fmt.Fprintf(w, "\n✅ Rampart service installed: %s\n", path)
	fmt.Fprintf(w, "   Dashboard: http://localhost:%d/dashboard/\n", port)
	if generated {
		fmt.Fprintf(w, "\n🔑 Generated token (save this — you'll need it for hooks):\n")
		fmt.Fprintf(w, "   export RAMPART_TOKEN=%s\n\n", token)
		fmt.Fprintf(w, "   Add to your shell profile so it persists across sessions:\n")
		fmt.Fprintf(w, "     echo 'export RAMPART_TOKEN=%s' >> ~/.zshrc   # zsh (macOS default)\n", token)
		fmt.Fprintf(w, "     echo 'export RAMPART_TOKEN=%s' >> ~/.bashrc  # bash\n\n", token)
	} else {
		display := token
		if len(token) > 8 {
			display = token[:8] + "..."
		}
		fmt.Fprintf(w, "   Token: %s\n", display)
	}
}
