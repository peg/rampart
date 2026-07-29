// Copyright 2026 The Rampart Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

func fileContains(path, marker string) bool {
	data, err := os.ReadFile(path)
	return err == nil && strings.Contains(string(data), marker)
}

func claudeRampartHooksPresent(home string) bool {
	path := claudeSettingsPath(home)
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var settings claudeSettings
	return json.Unmarshal(data, &settings) == nil && hasRampartHook(settings)
}

func clineManagedHooksPresentInDir(hookDir string) bool {
	for _, event := range clineHookEvents {
		for _, goos := range []string{"linux", "windows"} {
			path := clineHookPath(hookDir, event, goos)
			info, err := os.Lstat(path)
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				continue
			}
			if info.IsDir() {
				legacyName := "rampart-policy"
				if event == "PostToolUse" {
					legacyName = "rampart-audit"
				}
				path = filepath.Join(path, legacyName)
			}
			if data, err := os.ReadFile(path); err == nil && clineHookScriptManaged(data) {
				return true
			}
		}
	}
	return false
}

func codexRampartIntegrationPresent(home string) bool {
	hooksPath := filepath.Join(codexHomeDir(home), "hooks.json")
	if data, err := os.ReadFile(hooksPath); err == nil {
		var settings map[string]any
		if json.Unmarshal(data, &settings) == nil {
			if hooks, ok := settings["hooks"].(map[string]any); ok {
				for _, event := range []string{"PreToolUse", "PostToolUse"} {
					entries, _ := hooks[event].([]any)
					for _, entry := range entries {
						if matcher, ok := entry.(map[string]any); ok && isRampartCodexMatcher(matcher) {
							return true
						}
					}
				}
			}
		}
	}
	wrapper := filepath.Join(home, ".local", "bin", "codex")
	data, err := os.ReadFile(wrapper)
	return err == nil && containsRampartPreload(string(data))
}

func openClawRampartIntegrationPresent(home string) bool {
	stateDir, configPath, _ := resolveOpenClawStateDir("")
	if bin, err := findOpenClawBinary(); err == nil {
		if resolvedState, resolvedConfig, resolveErr := resolveOpenClawStateDir(bin); resolveErr == nil {
			stateDir, configPath = resolvedState, resolvedConfig
		}
	}
	if _, err := os.Stat(filepath.Join(stateDir, openclawPluginDir)); err == nil || openClawConfigHasRampart(configPath) || fileContains(configPath, `"rampart"`) {
		return true
	}
	for _, path := range []string{
		filepath.Join(home, ".local", "bin", "rampart-shim"),
		filepath.Join(home, ".config", "systemd", "user", "openclaw-gateway.service.d", "rampart.conf"),
	} {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	for _, dir := range openclawToolsCandidates() {
		for _, tool := range []string{"read", "write", "edit", "grep"} {
			if _, err := os.Stat(filepath.Join(dir, tool+".js.rampart-backup")); err == nil {
				return true
			}
		}
	}
	return false
}

func hermesRampartIntegrationPresent(home string) bool {
	hermesHome := hermesHomeDir(home)
	pluginDir := filepath.Join(hermesHome, "plugins", "rampart")
	if _, err := os.Lstat(pluginDir); err == nil {
		return true
	}
	cfg, _, err := readHermesDoctorConfig(hermesHome)
	if err != nil {
		return false
	}
	if containsString(cfg.Plugins.Enabled, "rampart") || containsString(cfg.Plugins.Disabled, "rampart") {
		return true
	}
	_, exists := cfg.Plugins.Entries["rampart"]
	return exists
}

func runSetupRemove(parent *cobra.Command, setup *cobra.Command, flags ...string) error {
	setup.SetIn(parent.InOrStdin())
	setup.SetOut(parent.OutOrStdout())
	setup.SetErr(parent.ErrOrStderr())
	if err := setup.Flags().Set("remove", "true"); err != nil {
		return err
	}
	for _, flag := range flags {
		if err := setup.Flags().Set(flag, "true"); err != nil {
			return err
		}
	}
	if setup.RunE == nil {
		return fmt.Errorf("setup removal command %s has no implementation", setup.Name())
	}
	return setup.RunE(setup, nil)
}

// removeManagedAgentIntegrations removes only configuration entries and files
// whose ownership can be attributed to Rampart. Agent workspaces, transcripts,
// memories, credentials, and unrelated hook/plugin entries remain untouched.
func removeManagedAgentIntegrations(cmd *cobra.Command, opts *rootOptions, home string) (removed, failed []string) {
	type removal struct {
		label   string
		present func() bool
		run     func() error
	}
	removals := []removal{
		{
			label:   "Claude Code hooks",
			present: func() bool { return claudeRampartHooksPresent(home) },
			run:     func() error { return runSetupRemove(cmd, newSetupClaudeCodeCmd(opts)) },
		},
		{
			label:   "Codex hooks",
			present: func() bool { return codexRampartIntegrationPresent(home) },
			run:     func() error { return runSetupRemove(cmd, newSetupCodexCmd(opts)) },
		},
		{
			label: "GitHub Copilot hooks",
			present: func() bool {
				_, err := os.Stat(filepath.Join(copilotHomeDir(home), "hooks", copilotRampartHookFile))
				return err == nil
			},
			run: func() error { return runSetupRemove(cmd, newSetupCopilotCmd()) },
		},
		{
			label: "GitHub Copilot machine policy",
			present: func() bool {
				_, err := os.Stat(copilotPolicyHookPathForRuntime())
				return err == nil
			},
			run: func() error { return runSetupRemove(cmd, newSetupCopilotCmd(), "policy") },
		},
		{
			label: "Antigravity plugin",
			present: func() bool {
				_, err := os.Stat(antigravityPluginDir(home))
				return err == nil
			},
			run: func() error { return runSetupRemove(cmd, newSetupAntigravityCmd()) },
		},
		{
			label: "Gemini CLI hooks",
			present: func() bool {
				path := filepath.Join(home, ".gemini", "settings.json")
				return geminiHooksConfiguredForHome(home) || fileContains(path, "hook --format gemini")
			},
			run: func() error { return runSetupRemove(cmd, newSetupGeminiCmd()) },
		},
		{
			label:   "Hermes plugin",
			present: func() bool { return hermesRampartIntegrationPresent(home) },
			run:     func() error { return runSetupRemove(cmd, newSetupHermesCmd()) },
		},
		{
			label:   "OpenClaw integration",
			present: func() bool { return openClawRampartIntegrationPresent(home) },
			run: func() error {
				if runtime.GOOS != "windows" {
					return runSetupRemove(cmd, newSetupOpenClawCmd(opts))
				}
				stateDir, configPath, _ := resolveOpenClawStateDir("")
				var hostUninstall func() error
				if openclawBin, findErr := findOpenClawBinary(); findErr == nil {
					if resolvedState, resolvedConfig, resolveErr := resolveOpenClawStateDir(openclawBin); resolveErr == nil {
						stateDir, configPath = resolvedState, resolvedConfig
						hostUninstall = func() error {
							return runOpenClawPluginUninstall(openclawBin, cmd.OutOrStdout(), cmd.ErrOrStderr())
						}
					}
				}
				_, err := removeOpenClawNativePluginWithHostAt(stateDir, configPath, hostUninstall)
				return err
			},
		},
	}

	for _, hookDir := range clineKnownHookDirs(home) {
		dir := hookDir
		removals = append(removals, removal{
			label:   "Cline hooks at " + dir,
			present: func() bool { return clineManagedHooksPresentInDir(dir) },
			run:     func() error { return removeClineHooksFromDir(cmd, dir) },
		})
	}

	for _, item := range removals {
		if !item.present() {
			continue
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Removing %s...\n", item.label)
		if err := item.run(); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", item.label, err))
			continue
		}
		removed = append(removed, item.label)
	}
	return removed, failed
}
