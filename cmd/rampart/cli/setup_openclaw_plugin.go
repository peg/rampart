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
	"encoding/json"
	"fmt"
	"io"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"

	"github.com/peg/rampart/policies"
)

// openclawPluginDir is the well-known directory where the Rampart OpenClaw
// plugin is installed by `openclaw plugins install`.
const openclawPluginDir = "extensions/rampart"

// openclawMinVersion is the minimum OpenClaw version required for the
// before_tool_call hook used by the Rampart plugin.
const openclawMinVersion = "2026.3.28"

// TODO: bundle the plugin inside the rampart binary and extract to a temp dir.
// For now, point at the development checkout path.
const openclawPluginDevPath = "/home/clap/.openclaw/workspace/rampart-openclaw-plugin"

// runSetupOpenClawPlugin installs the Rampart native plugin into OpenClaw.
//
// Steps:
//  1. Locate the openclaw binary.
//  2. Verify the OpenClaw version is >= openclawMinVersion (requires before_tool_call hook).
//  3. Run: openclaw plugins install <plugin-path>
//  4. Set tools.exec.ask to "off" in ~/.openclaw/openclaw.json
//     (Rampart handles all decisions now — no need for OpenClaw's own ask prompt).
//  5. Copy the openclaw.yaml policy profile to ~/.rampart/policies/openclaw.yaml.
//  6. Run rampart doctor for a health summary.
//  7. Print success and next steps.
func runSetupOpenClawPlugin(w io.Writer, errW io.Writer) error {
	// 1. Locate openclaw.
	openclawBin, err := findOpenClawBinary()
	if err != nil {
		return fmt.Errorf("openclaw not found — is it installed?\n  Install: npm install -g openclaw\n  Error: %w", err)
	}
	fmt.Fprintf(w, "✓ Found OpenClaw: %s\n", openclawBin)

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

	// 3. Install the plugin.
	pluginPath := openclawPluginDevPath
	if _, err := os.Stat(pluginPath); os.IsNotExist(err) {
		return fmt.Errorf("Rampart OpenClaw plugin not found at %s\n  Build it first: cd %s && npm install && npm run build", pluginPath, pluginPath)
	}
	fmt.Fprintf(w, "Installing plugin from: %s\n", pluginPath)

	installCmd := osexec.Command(openclawBin, "plugins", "install", pluginPath)
	installCmd.Stdout = w
	installCmd.Stderr = errW
	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("openclaw plugins install failed: %w\n  Try running manually: openclaw plugins install %s", err, pluginPath)
	}
	fmt.Fprintln(w, "✓ Rampart plugin installed into OpenClaw")

	// 4. Set tools.exec.ask to "off" in openclaw.json.
	if err := setOpenClawExecAsk("off"); err != nil {
		fmt.Fprintf(errW, "⚠ Could not update tools.exec.ask in openclaw.json: %v\n", err)
		fmt.Fprintln(errW, "  Add manually: set tools.exec.ask to \"off\" in ~/.openclaw/openclaw.json")
	} else {
		fmt.Fprintln(w, "✓ Set tools.exec.ask = \"off\" (Rampart now handles all decisions)")
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
	fmt.Fprintln(w, "✓ Rampart OpenClaw plugin setup complete!")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Next steps:")
	fmt.Fprintln(w, "  1. Restart the OpenClaw gateway:")
	fmt.Fprintln(w, "       systemctl --user restart openclaw-gateway")
	fmt.Fprintln(w, "  2. Verify the hook is active:")
	fmt.Fprintln(w, "       rampart doctor")
	fmt.Fprintln(w, "  3. Watch live tool calls:")
	fmt.Fprintln(w, "       rampart watch")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "The Rampart before_tool_call hook now intercepts ALL OpenClaw tool calls")
	fmt.Fprintln(w, "natively — no dist patching or LD_PRELOAD needed.")

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
	fmt.Fprintln(w, "The native before_tool_call hook provides full coverage.")

	return nil
}

// findOpenClawBinary returns the path to the openclaw binary.
func findOpenClawBinary() (string, error) {
	// Try PATH first.
	if p, err := osexec.LookPath("openclaw"); err == nil {
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
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("openclaw binary not found in PATH or common locations")
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
	version = strings.Fields(version)[0]
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

// setOpenClawExecAsk sets tools.exec.ask in ~/.openclaw/openclaw.json.
func setOpenClawExecAsk(value string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home: %w", err)
	}

	configPath := filepath.Join(home, ".openclaw", "openclaw.json")

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
	if err := os.WriteFile(destPath, policyData, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", destPath, err)
	}

	fmt.Fprintf(w, "✓ OpenClaw policy profile installed at %s\n", destPath)
	return nil
}

// cleanOpenClawConfig removes legacy bridge config and ask: on-miss from openclaw.json.
func cleanOpenClawConfig(w io.Writer, errW io.Writer) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home: %w", err)
	}

	configPath := filepath.Join(home, ".openclaw", "openclaw.json")
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

// isOpenClawPluginInstalled returns true if the Rampart plugin directory
// exists under ~/.openclaw/extensions/rampart/.
func isOpenClawPluginInstalled() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	pluginDir := filepath.Join(home, ".openclaw", openclawPluginDir)
	info, err := os.Stat(pluginDir)
	return err == nil && info.IsDir()
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
