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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"time"

	ochardening "github.com/peg/rampart/internal/openclaw/hardening"
	ocplugin "github.com/peg/rampart/internal/plugin/openclaw"
	"github.com/peg/rampart/policies"
)

// openclawPluginDir is the well-known directory where the Rampart OpenClaw
// plugin is installed by `openclaw plugins install`.
const openclawPluginDir = "extensions/rampart"

// openclawMinVersion is the minimum OpenClaw version required for the
// before_tool_call hook used by the Rampart plugin.
const openclawMinVersion = "2026.3.28"

// The plugin is bundled inside the binary via //go:embed and extracted to a
// temp directory during setup. No external checkout or npm install required.

// runSetupOpenClawPlugin installs the Rampart native plugin into OpenClaw.
//
// Steps:
//  1. Locate the openclaw binary.
//  2. Verify the OpenClaw version is >= openclawMinVersion (requires before_tool_call hook).
//  3. Run: openclaw plugins install <plugin-path>
//  4. Set tools.exec.ask to "off" in ~/.openclaw/openclaw.json.
//     Native OpenClaw approvals remain the visible approval owner while
//     Rampart evaluates policy and persists allow-always behavior.
//  5. Copy the openclaw.yaml policy profile to ~/.rampart/policies/openclaw.yaml.
//  6. Run rampart doctor for a health summary.
//  7. Print success and next steps.
func runSetupOpenClawPlugin(w io.Writer, errW io.Writer) error {
	// 0. Ensure rampart serve is running (start as systemd service if needed).
	if err := ensureServeRunning(w, errW); err != nil {
		fmt.Fprintf(errW, "⚠ Could not start rampart serve: %v\n", err)
		fmt.Fprintln(errW, "  Start manually: rampart serve --background")
		// Non-fatal — continue setup, serve can be started later.
	}

	// 1. Locate openclaw.
	openclawBin, err := findOpenClawBinary()
	if err != nil {
		return fmt.Errorf("openclaw not found — is it installed?\n  Install: npm install -g openclaw\n  Error: %w", err)
	}
	fmt.Fprintf(w, "✓ Found OpenClaw: %s\n", openclawBin)
	if stateDir, configPath, err := resolveOpenClawStateDir(openclawBin); err == nil {
		fmt.Fprintf(w, "✓ Target OpenClaw state: %s (config: %s)\n", stateDir, configPath)
	} else {
		fmt.Fprintf(errW, "⚠ Could not resolve active OpenClaw state dir: %v\n", err)
	}

	// 2. Check version.
	version, err := getOpenClawVersion(openclawBin)
	if err != nil {
		fmt.Fprintf(errW, "⚠ Could not determine OpenClaw version: %v\n", err)
		fmt.Fprintln(errW, "  Continuing anyway — plugin install may fail if version is too old.")
	} else {
		ok, cmpErr := openclawVersionAtLeast(version, openclawMinVersion)
		if cmpErr != nil {
			fmt.Fprintf(errW, "⚠ Could not parse OpenClaw version %q: %v\n", version, cmpErr)
		} else if !ok {
			return fmt.Errorf("OpenClaw version %s is too old — need >= %s for before_tool_call hook\n  Upgrade: npm install -g openclaw@latest", version, openclawMinVersion)
		}
		fmt.Fprintf(w, "✓ OpenClaw version: %s (>= %s required)\n", version, openclawMinVersion)
	}

	// 3. Extract the bundled plugin to a temp dir and install it.
	pluginDir, err := os.MkdirTemp("", "rampart-openclaw-plugin-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir for plugin: %w", err)
	}
	defer os.RemoveAll(pluginDir)

	if err := ocplugin.Extract(pluginDir); err != nil {
		return fmt.Errorf("failed to extract bundled plugin: %w", err)
	}
	fmt.Fprintf(w, "Installing bundled plugin (v%s)...\n", ocplugin.Version())

	if err := removeExistingOpenClawRampartInstall(errW); err != nil {
		return err
	}

	installCmd := osexec.Command(openclawBin, "plugins", "install", pluginDir)
	installCmd.Stdout = w
	installCmd.Stderr = errW
	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("openclaw plugins install failed: %w\n  Try running manually: openclaw plugins install <extracted-plugin-path>", err)
	}
	fmt.Fprintln(w, "✓ Rampart plugin installed into OpenClaw")
	fmt.Fprintln(w, "  Note: OpenClaw may warn about suspicious code patterns — this is a false positive.")
	fmt.Fprintln(w, "  Rampart reads a local token file and talks to localhost:9090 only. See: https://docs.rampart.sh/integrations/openclaw#security-scanner")

	// 4. Set tools.exec.ask to "off" in openclaw.json.
	if err := setOpenClawExecAsk("off"); err != nil {
		fmt.Fprintf(errW, "⚠ Could not update tools.exec.ask in openclaw.json: %v\n", err)
		fmt.Fprintln(errW, "  Add manually: set tools.exec.ask to \"off\" in ~/.openclaw/openclaw.json")
	} else {
		fmt.Fprintln(w, "✓ Set tools.exec.ask = \"off\" (OpenClaw keeps native approval ownership; Rampart evaluates policy behind it)")
	}

	// 4b. Add rampart to plugins.allow. Existing plugins are preserved — we only append.
	if added, existing, err := addToOpenClawPluginsAllow("rampart"); err != nil {
		fmt.Fprintf(errW, "⚠ Could not update plugins.allow in openclaw.json: %v\n", err)
	} else if added {
		fmt.Fprintf(w, "✓ Added rampart to plugins.allow (existing: %v)\n", existing)
	} else {
		fmt.Fprintln(w, "✓ rampart already in plugins.allow (no changes to other plugins)")
	}

	// 4c. Harden OpenClaw approval semantics and align approval timeouts.
	if err := ensureOpenClawApprovalHardening(w, errW); err != nil {
		fmt.Fprintf(errW, "⚠ Could not harden OpenClaw approvals: %v\n", err)
		fmt.Fprintln(errW, "  Run `rampart doctor --fix` after reviewing the detected OpenClaw build shape.")
	} else {
		fmt.Fprintf(w, "✓ OpenClaw approval handling checked (plugin approvals aligned at %dms)\n", ochardening.DesiredApprovalTimeoutMs)
	}

	// 5. Copy openclaw.yaml policy profile.
	if err := installOpenClawPolicy(w, errW); err != nil {
		fmt.Fprintf(errW, "⚠ Could not install openclaw.yaml policy: %v\n", err)
	}

	// 6. Run rampart doctor.
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Running 'rampart doctor'...")
	doctorCmd := osexec.Command(os.Args[0], "doctor")
	doctorCmd.Stdout = w
	doctorCmd.Stderr = errW
	_ = doctorCmd.Run() // non-fatal — doctor output is informational

	// 7. Success message.
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "✅ Rampart is protecting your OpenClaw agent")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  Protected tools: exec, read, write, edit, web_fetch, browser, message")
	serveStatus := "http://localhost:9090"
	if isSetupServeReachable() {
		serveStatus += " (running)"
	} else {
		serveStatus += " (not running — start with: rampart serve --background)"
	}
	fmt.Fprintf(w, "  Policy engine:   %s\n", serveStatus)
	fmt.Fprintln(w, "  Audit log:       ~/.rampart/audit/")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  → Restart the gateway if it was not restarted automatically:  systemctl --user restart openclaw-gateway.service")
	fmt.Fprintln(w, "  → Run `rampart watch` to see policy decisions in real time")
	fmt.Fprintln(w, "  → Run `rampart doctor` to verify your setup")

	return nil
}

func ensureOpenClawApprovalHardening(w io.Writer, errW io.Writer) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home: %w", err)
	}
	configPath := filepath.Join(home, ".openclaw", "openclaw.json")
	if openclawBin, binErr := findOpenClawBinary(); binErr == nil {
		if _, resolvedConfigPath, stateErr := resolveOpenClawStateDir(openclawBin); stateErr == nil {
			configPath = resolvedConfigPath
		}
	}

	state, err := ochardening.InspectConfig(configPath, openclawDistCandidates())
	if err != nil {
		return fmt.Errorf("inspect current hardening state: %w", err)
	}
	if isOpenClawPluginInstalled() {
		updated, timeoutErr := ochardening.EnsurePluginApprovalTimeoutConfig(configPath)
		if timeoutErr != nil {
			return fmt.Errorf("align plugin approval timeout: %w", timeoutErr)
		}
		if updated {
			fmt.Fprintf(w, "  Set plugins.entries.rampart.config.approvalTimeoutMs = %d\n", ochardening.DesiredApprovalTimeoutMs)
		}
		fmt.Fprintln(w, "✓ Native OpenClaw plugin approvals configured; skipped legacy exec approval bundle patching")
		return nil
	}
	if state.ExecApprovalsPath == "" || state.BashToolsPath == "" {
		return fmt.Errorf("openclaw approval bundles not found under supported dist paths")
	}
	if !state.Supported {
		return fmt.Errorf("unsupported OpenClaw approval bundle shape; refusing blind legacy exec approval patch")
	}
	if state.FallbackSafe && state.CompletionAttributionSafe && state.ApprovalTimeoutAligned && state.PluginApprovalTimeoutAligned {
		fmt.Fprintln(w, "✓ OpenClaw approval semantics already hardened and timeout-aligned")
		return nil
	}
	result, err := ochardening.Apply(home, openclawDistCandidates())
	if err != nil {
		return fmt.Errorf("apply approval hardening: %w", err)
	}
	for _, path := range result.PatchedFiles {
		fmt.Fprintf(w, "  Hardened %s\n", filepath.Base(path))
	}
	if result.ConfigUpdated {
		fmt.Fprintf(w, "  Set plugins.entries.rampart.config.approvalTimeoutMs = %d\n", ochardening.DesiredApprovalTimeoutMs)
	}
	if result.RestartSuggested {
		if err := restartOpenClawGateway(); err != nil {
			fmt.Fprintf(errW, "⚠ Approval hardening applied, but automatic gateway restart failed: %v\n", err)
			fmt.Fprintln(errW, "  Restart manually: systemctl --user restart openclaw-gateway.service")
		} else {
			fmt.Fprintln(w, "  Restarted OpenClaw gateway to activate approval hardening")
		}
	}
	return nil
}

func restartOpenClawGateway() error {
	openclawBin, err := findOpenClawBinary()
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := osexec.CommandContext(ctx, openclawBin, "gateway", "restart")
		if out, runErr := cmd.CombinedOutput(); runErr == nil {
			return nil
		} else if len(out) > 0 {
			return fmt.Errorf("openclaw gateway restart: %w: %s", runErr, strings.TrimSpace(string(out)))
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := osexec.CommandContext(ctx, "systemctl", "--user", "restart", "openclaw-gateway.service")
	if out, runErr := cmd.CombinedOutput(); runErr != nil {
		if len(out) > 0 {
			return fmt.Errorf("systemctl restart: %w: %s", runErr, strings.TrimSpace(string(out)))
		}
		return fmt.Errorf("systemctl restart: %w", runErr)
	}
	return nil
}

// runSetupOpenClawMigrate migrates from the legacy dist-patch/bridge approach
// to the native plugin-based integration.
//
// Steps:
//  1. Remove old dist patches (restore .rampart-backup files if they exist).
//  2. Remove the old bridge config from openclaw.json.
//  3. Remove ask: on-miss if it exists.
//  4. Install the plugin (calls runSetupOpenClawPlugin).
//  5. Print migration summary.
func removeExistingOpenClawRampartInstall(errW io.Writer) error {
	openclawBin, err := findOpenClawBinary()
	if err != nil {
		return fmt.Errorf("find openclaw for plugin cleanup: %w", err)
	}

	stateDir, cfgPath, stateErr := resolveOpenClawStateDir(openclawBin)
	if stateErr != nil {
		return fmt.Errorf("resolve OpenClaw state for plugin cleanup: %w", stateErr)
	}

	cleanupRemainingInstallPaths := func() error {
		paths := []string{
			filepath.Join(stateDir, openclawPluginDir),
			filepath.Join(stateDir, "hooks", "rampart"),
		}
		for _, path := range paths {
			if _, err := os.Stat(path); err == nil {
				if rmErr := os.RemoveAll(path); rmErr != nil {
					return fmt.Errorf("remove existing OpenClaw Rampart install %s: %w", path, rmErr)
				}
				fmt.Fprintf(errW, "ℹ Removed existing OpenClaw Rampart install: %s\n", path)
			}
		}
		return nil
	}

	uninstallCmd := osexec.Command(openclawBin, "plugins", "uninstall", "rampart", "--force")
	uninstallCmd.Stdout = errW
	uninstallCmd.Stderr = errW
	if err := uninstallCmd.Run(); err == nil {
		fmt.Fprintln(errW, "ℹ Uninstalled existing OpenClaw Rampart plugin via managed OpenClaw uninstall")
		return cleanupRemainingInstallPaths()
	}

	if healErr := healOpenClawRampartPluginConfig(cfgPath, stateDir); healErr == nil {
		retryCmd := osexec.Command(openclawBin, "plugins", "uninstall", "rampart", "--force")
		retryCmd.Stdout = errW
		retryCmd.Stderr = errW
		if retryErr := retryCmd.Run(); retryErr == nil {
			fmt.Fprintln(errW, "ℹ Healed OpenClaw Rampart install records and uninstalled via managed OpenClaw uninstall")
			return cleanupRemainingInstallPaths()
		}
	}

	return cleanupRemainingInstallPaths()
}

func healOpenClawRampartPluginConfig(cfgPath, stateDir string) error {
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	plugins, _ := cfg["plugins"].(map[string]any)
	if plugins == nil {
		plugins = map[string]any{}
		cfg["plugins"] = plugins
	}
	entries, _ := plugins["entries"].(map[string]any)
	if entries == nil {
		entries = map[string]any{}
		plugins["entries"] = entries
	}
	if _, ok := entries["rampart"]; !ok {
		entries["rampart"] = map[string]any{"enabled": true}
	}
	installs, _ := plugins["installs"].(map[string]any)
	if installs == nil {
		installs = map[string]any{}
		plugins["installs"] = installs
	}
	if _, ok := installs["rampart"]; !ok {
		installs["rampart"] = map[string]any{
			"installPath": filepath.Join(stateDir, openclawPluginDir),
			"source":      "path",
			"sourcePath":  filepath.Join(stateDir, openclawPluginDir),
		}
	}
	allow, _ := plugins["allow"].([]any)
	found := false
	for _, v := range allow {
		if s, ok := v.(string); ok && s == "rampart" {
			found = true
			break
		}
	}
	if !found {
		plugins["allow"] = append(allow, "rampart")
	}
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return os.WriteFile(cfgPath, out, 0o600)
}

func runSetupOpenClawMigrate(w io.Writer, errW io.Writer) error {
	fmt.Fprintln(w, "Migrating from legacy OpenClaw integration to native plugin...")
	fmt.Fprintln(w, "")

	var removed []string

	// 1. Restore dist patch backups.
	for _, distDir := range openclawDistCandidates() {
		allJS, _ := filepath.Glob(filepath.Join(distDir, "*.js"))
		for _, file := range allJS {
			backup := file + ".rampart-backup"
			if data, err := os.ReadFile(backup); err == nil {
				if err := os.WriteFile(file, data, 0o644); err == nil {
					_ = os.Remove(backup)
					removed = append(removed, filepath.Base(file)+" (dist patch restored)")
				} else {
					fmt.Fprintf(errW, "⚠ Could not restore %s: %v\n", file, err)
				}
			}
		}
	}
	if len(removed) > 0 {
		fmt.Fprintf(w, "✓ Restored %d dist file(s) from backup\n", len(removed))
	} else {
		fmt.Fprintln(w, "  No dist patch backups found (already clean or not applied)")
	}

	// 2 & 3. Update openclaw.json: remove bridge config, remove ask: on-miss.
	if err := cleanOpenClawConfig(w, errW); err != nil {
		fmt.Fprintf(errW, "⚠ Could not clean openclaw.json: %v\n", err)
	}

	// 4. Install the plugin.
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Installing Rampart native plugin...")
	if err := runSetupOpenClawPlugin(w, errW); err != nil {
		return fmt.Errorf("plugin install failed during migration: %w", err)
	}

	// 5. Migration summary.
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Migration complete!")
	if len(removed) > 0 {
		for _, r := range removed {
			fmt.Fprintf(w, "  Cleaned: %s\n", r)
		}
	}
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "The legacy dist patches and bridge are no longer needed.")
	fmt.Fprintln(w, "The native before_tool_call hook intercepts all OpenClaw tool calls.")
	fmt.Fprintln(w, "Sensitive-vs-fail-open behavior still depends on tool class and plugin configuration.")

	return nil
}

// findOpenClawBinary returns the path to the openclaw binary.
func findOpenClawBinary() (string, error) {
	if override := strings.TrimSpace(os.Getenv("RAMPART_OPENCLAW_BIN")); override != "" {
		if err := validateExecutableFile(override); err != nil {
			return "", fmt.Errorf("RAMPART_OPENCLAW_BIN=%q is not usable: %w", override, err)
		}
		return override, nil
	}

	// Try PATH first. This usually matches the OpenClaw install the human uses.
	if p, err := execLookPath("openclaw"); err == nil {
		return p, nil
	}
	// Try common install paths.
	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, ".local", "bin", "openclaw"),
		"/usr/local/bin/openclaw",
		"/usr/bin/openclaw",
		filepath.Join(home, ".npm-global", "bin", "openclaw"),
		"/opt/homebrew/bin/openclaw",
	}
	for _, p := range candidates {
		if err := validateExecutableFile(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("openclaw binary not found in PATH or common locations; set RAMPART_OPENCLAW_BIN=/path/to/openclaw if you use a custom install")
}

func validateExecutableFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("is a directory")
	}
	if info.Mode()&0o111 == 0 {
		return fmt.Errorf("not executable")
	}
	return nil
}

func resolveOpenClawStateDir(openclawBin string) (stateDir string, configPath string, err error) {
	if override := strings.TrimSpace(os.Getenv("OPENCLAW_STATE_DIR")); override != "" {
		stateDir = expandHomePath(override)
		return stateDir, filepath.Join(stateDir, "openclaw.json"), nil
	}
	if override := strings.TrimSpace(os.Getenv("OPENCLAW_CONFIG_PATH")); override != "" {
		configPath = expandHomePath(override)
		return filepath.Dir(configPath), configPath, nil
	}
	if strings.TrimSpace(openclawBin) != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := osexec.CommandContext(ctx, openclawBin, "config", "file")
		cmd.Env = append(os.Environ(), "OPENCLAW_HIDE_BANNER=1", "OPENCLAW_SUPPRESS_NOTES=1")
		out, runErr := cmd.Output()
		if runErr == nil {
			configPath = expandHomePath(strings.TrimSpace(string(out)))
			if configPath != "" {
				return filepath.Dir(configPath), configPath, nil
			}
		}
	}
	home, homeErr := os.UserHomeDir()
	if homeErr != nil {
		return "", "", homeErr
	}
	stateDir = filepath.Join(home, ".openclaw")
	return stateDir, filepath.Join(stateDir, "openclaw.json"), nil
}

func expandHomePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
	}
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}

// getOpenClawVersion runs `openclaw --version` and returns the version string.
func getOpenClawVersion(openclawBin string) (string, error) {
	out, err := osexec.Command(openclawBin, "--version").Output()
	if err != nil {
		// Try version subcommand.
		out, err = osexec.Command(openclawBin, "version").Output()
		if err != nil {
			return "", fmt.Errorf("run %s --version: %w", openclawBin, err)
		}
	}
	version := strings.TrimSpace(string(out))
	// Strip common prefixes like "openclaw v2026.3.28" or "v2026.3.28".
	for _, prefix := range []string{"openclaw ", "OpenClaw ", "v", "V"} {
		version = strings.TrimPrefix(version, prefix)
	}
	// Take the first line/word only.
	fields := strings.Fields(version)
	if len(fields) > 0 {
		version = fields[0]
	}
	return version, nil
}

// openclawVersionAtLeast returns true if gotVersion >= minVersion.
// Version format: YYYY.M.D (e.g. 2026.3.28).
func openclawVersionAtLeast(gotVersion, minVersion string) (bool, error) {
	got := parseCalVer(gotVersion)
	min := parseCalVer(minVersion)
	if got == nil || min == nil {
		return false, fmt.Errorf("could not parse versions: got=%q min=%q", gotVersion, minVersion)
	}
	for i := range min {
		if i >= len(got) {
			return false, nil
		}
		if got[i] > min[i] {
			return true, nil
		}
		if got[i] < min[i] {
			return false, nil
		}
	}
	return true, nil
}

// parseCalVer splits a CalVer string like "2026.3.28" into []int{2026, 3, 28}.
func parseCalVer(v string) []int {
	parts := strings.Split(v, ".")
	result := make([]int, 0, len(parts))
	for _, p := range parts {
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err != nil {
			return nil
		}
		result = append(result, n)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// setOpenClawExecAsk sets tools.exec.ask in the active OpenClaw config.
// addToOpenClawPluginsAllow adds pluginID to the plugins.allow list in openclaw.json
// if it is not already present. Returns (added, existingIDs, error).
// NEVER removes or overwrites existing entries — only appends.
func addToOpenClawPluginsAllow(pluginID string) (added bool, existing []string, err error) {
	bin, berr := findOpenClawBinary()
	if berr != nil {
		return false, nil, berr
	}
	_, configPath, serr := resolveOpenClawStateDir(bin)
	if serr != nil {
		return false, nil, serr
	}
	data, rerr := os.ReadFile(configPath)
	if rerr != nil {
		return false, nil, rerr
	}
	var cfg map[string]any
	if jerr := json.Unmarshal(data, &cfg); jerr != nil {
		return false, nil, jerr
	}
	plugins, _ := cfg["plugins"].(map[string]any)
	if plugins == nil {
		plugins = map[string]any{}
		cfg["plugins"] = plugins
	}
	allowRaw, _ := plugins["allow"].([]any)
	// Collect existing string entries and check for duplicates.
	for _, v := range allowRaw {
		if s, ok := v.(string); ok {
			existing = append(existing, s)
			if s == pluginID {
				return false, existing, nil // already present, no change
			}
		}
	}
	// Append only — preserve all existing entries.
	plugins["allow"] = append(allowRaw, pluginID)
	out, merr := json.MarshalIndent(cfg, "", "  ")
	if merr != nil {
		return false, existing, merr
	}
	return true, existing, os.WriteFile(configPath, out, 0o600)
}

func setOpenClawExecAsk(value string) error {
	bin, err := findOpenClawBinary()
	if err != nil {
		return fmt.Errorf("find openclaw: %w", err)
	}
	_, configPath, err := resolveOpenClawStateDir(bin)
	if err != nil {
		return fmt.Errorf("resolve OpenClaw config: %w", err)
	}

	// Load existing config or start fresh.
	var cfg map[string]any
	if data, err := os.ReadFile(configPath); err == nil {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("parse %s: %w", configPath, err)
		}
	} else if os.IsNotExist(err) {
		cfg = make(map[string]any)
		// Ensure parent directory exists.
		if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
			return fmt.Errorf("create .openclaw dir: %w", err)
		}
	} else {
		return fmt.Errorf("read %s: %w", configPath, err)
	}

	// Navigate to tools.exec and set ask.
	tools, ok := cfg["tools"].(map[string]any)
	if !ok {
		tools = make(map[string]any)
		cfg["tools"] = tools
	}
	execCfg, ok := tools["exec"].(map[string]any)
	if !ok {
		execCfg = make(map[string]any)
		tools["exec"] = execCfg
	}
	execCfg["ask"] = value

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	data = append(data, '\n')

	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", configPath, err)
	}
	return nil
}

// installOpenClawPolicy copies the embedded openclaw.yaml policy to ~/.rampart/policies/.
func installOpenClawPolicy(w io.Writer, errW io.Writer) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home: %w", err)
	}

	policyDir := filepath.Join(home, ".rampart", "policies")
	if err := os.MkdirAll(policyDir, 0o700); err != nil {
		return fmt.Errorf("create policy dir: %w", err)
	}

	policyData, err := policies.Profile("openclaw")
	if err != nil {
		return fmt.Errorf("load embedded openclaw.yaml: %w", err)
	}

	destPath := filepath.Join(policyDir, "openclaw.yaml")
	if err := os.WriteFile(destPath, versionStampedPolicyContent(policyData), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", destPath, err)
	}

	fmt.Fprintf(w, "✓ OpenClaw policy profile installed at %s\n", destPath)
	return nil
}

// cleanOpenClawConfig removes legacy bridge config and ask: on-miss from openclaw.json.
func cleanOpenClawConfig(w io.Writer, errW io.Writer) error {
	bin, err := findOpenClawBinary()
	if err != nil {
		return fmt.Errorf("find openclaw: %w", err)
	}
	_, configPath, err := resolveOpenClawStateDir(bin)
	if err != nil {
		return fmt.Errorf("resolve OpenClaw config: %w", err)
	}
	data, err := os.ReadFile(configPath)
	if os.IsNotExist(err) {
		fmt.Fprintln(w, "  No openclaw.json found — nothing to clean")
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", configPath, err)
	}

	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse %s: %w", configPath, err)
	}

	changed := false

	// Remove top-level ask: on-miss (legacy; Rampart plugin handles it now).
	if askVal, ok := cfg["ask"].(string); ok && (askVal == "on-miss" || askVal == "always") {
		delete(cfg, "ask")
		changed = true
		fmt.Fprintf(w, "  Removed top-level ask: %s\n", askVal)
	}

	// Remove tools.exec.ask: on-miss if present (plugin hook replaces this).
	if tools, ok := cfg["tools"].(map[string]any); ok {
		if execCfg, ok := tools["exec"].(map[string]any); ok {
			if askVal, ok := execCfg["ask"].(string); ok && (askVal == "on-miss" || askVal == "always") {
				delete(execCfg, "ask")
				changed = true
				fmt.Fprintf(w, "  Removed tools.exec.ask: %s\n", askVal)
			}
		}
	}

	// Remove legacy rampart bridge config keys if present.
	bridgeKeys := []string{"rampart", "rampartBridge", "rampart_bridge", "rampartUrl", "rampart_url"}
	for _, k := range bridgeKeys {
		if _, ok := cfg[k]; ok {
			delete(cfg, k)
			changed = true
			fmt.Fprintf(w, "  Removed legacy bridge config key: %s\n", k)
		}
	}

	if !changed {
		fmt.Fprintln(w, "  openclaw.json is already clean")
		return nil
	}

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	out = append(out, '\n')

	if err := os.WriteFile(configPath, out, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", configPath, err)
	}

	return nil
}

// isOpenClawInstalled returns true if the openclaw binary can be found.
func isOpenClawInstalled() bool {
	_, err := findOpenClawBinary()
	return err == nil
}

type openClawPluginState struct {
	Installed       bool
	Allowed         bool
	Enabled         bool
	Dir             string
	ManifestVersion string
	RuntimeVersion  string
	StartupExplicit bool
}

func getOpenClawPluginState() openClawPluginState {
	bin, err := findOpenClawBinary()
	if err != nil {
		return openClawPluginState{}
	}
	stateDir, configPath, err := resolveOpenClawStateDir(bin)
	if err != nil {
		return openClawPluginState{}
	}

	pluginDir := filepath.Join(stateDir, openclawPluginDir)
	info, err := os.Stat(pluginDir)
	if err != nil || !info.IsDir() {
		return openClawPluginState{}
	}

	state := openClawPluginState{Installed: true, Enabled: true, Dir: pluginDir}
	state.readInstalledPluginMetadata()
	data, err := os.ReadFile(configPath)
	if err != nil {
		return state
	}

	var cfg struct {
		Plugins struct {
			Allow   []string `json:"allow"`
			Entries map[string]struct {
				Enabled *bool `json:"enabled"`
			} `json:"entries"`
		} `json:"plugins"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return state
	}

	state.Allowed = false
	for _, id := range cfg.Plugins.Allow {
		if id == "rampart" {
			state.Allowed = true
			break
		}
	}
	if entry, ok := cfg.Plugins.Entries["rampart"]; ok && entry.Enabled != nil {
		state.Enabled = *entry.Enabled
	}
	return state
}

func (s *openClawPluginState) readInstalledPluginMetadata() {
	manifestPath := filepath.Join(s.Dir, "openclaw.plugin.json")
	data, err := os.ReadFile(manifestPath)
	if err == nil {
		var manifest struct {
			Version    string `json:"version"`
			Activation struct {
				OnStartup *bool `json:"onStartup"`
			} `json:"activation"`
		}
		if json.Unmarshal(data, &manifest) == nil {
			s.ManifestVersion = strings.TrimSpace(manifest.Version)
			s.StartupExplicit = manifest.Activation.OnStartup != nil && *manifest.Activation.OnStartup
		}
	}
	indexData, err := os.ReadFile(filepath.Join(s.Dir, "index.js"))
	if err != nil {
		return
	}
	s.RuntimeVersion = extractOpenClawPluginRuntimeVersion(string(indexData))
}

func extractOpenClawPluginRuntimeVersion(js string) string {
	marker := "export const version = \""
	idx := strings.Index(js, marker)
	if idx < 0 {
		return ""
	}
	start := idx + len(marker)
	end := strings.Index(js[start:], "\"")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(js[start : start+end])
}

// isOpenClawPluginInstalled returns true if the Rampart plugin directory
// exists under the active OpenClaw state directory.
func isOpenClawPluginInstalled() bool {
	return getOpenClawPluginState().Installed
}

func isOpenClawPluginConfigured() bool {
	state := getOpenClawPluginState()
	if !state.Installed {
		return false
	}
	return state.Allowed && state.Enabled
}

// detectOpenClawVersion finds the OpenClaw binary and returns its version string.
// Returns an error if OpenClaw is not installed or version cannot be determined.
func detectOpenClawVersion() (string, error) {
	bin, err := findOpenClawBinary()
	if err != nil {
		return "", err
	}
	return getOpenClawVersion(bin)
}

// ensureServeRunning checks whether rampart serve is reachable, and if not,
// installs and starts it as a systemd/launchd service via `rampart serve install`.
func ensureServeRunning(w io.Writer, errW io.Writer) error {
	if isSetupServeReachable() {
		fmt.Fprintln(w, "✓ Rampart serve is running")
		return nil
	}

	fmt.Fprintln(w, "Starting rampart serve...")
	rampartBin, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find rampart binary: %w", err)
	}

	installCmd := osexec.Command(rampartBin, "serve", "install")
	installCmd.Stdout = w
	installCmd.Stderr = errW
	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("rampart serve install failed: %w", err)
	}

	// Wait up to 3 seconds for serve to come up.
	for i := 0; i < 6; i++ {
		time.Sleep(500 * time.Millisecond)
		if isSetupServeReachable() {
			fmt.Fprintln(w, "✓ Rampart serve started (systemd service)")
			return nil
		}
	}

	return fmt.Errorf("rampart serve installed but not reachable after 3s")
}

// isSetupServeReachable does a quick healthz check against the default serve port.
func isSetupServeReachable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost:9090/healthz", nil)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}
