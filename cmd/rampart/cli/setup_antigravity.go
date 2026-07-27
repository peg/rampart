// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

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

const antigravityRampartPlugin = "rampart"

func newSetupAntigravityCmd() *cobra.Command {
	var force bool
	var remove bool

	cmd := &cobra.Command{
		Use:     "antigravity",
		Aliases: []string{"agy"},
		Short:   "Install Rampart's Antigravity CLI and IDE policy plugin",
		Long: `Installs a global Rampart plugin in ~/.gemini/config/plugins/rampart.
Antigravity CLI and the Antigravity IDE both load this plugin's native
PreToolUse hook.

Rampart evaluates tool calls before execution. Antigravity's current
PostToolUse payload does not include the tool result, so this integration does
not claim post-result secret scanning. Run 'rampart setup antigravity --remove'
to uninstall.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("setup antigravity: resolve home: %w", err)
			}
			pluginDir := antigravityPluginDir(home)
			if remove {
				removed, err := removeAntigravityPlugin(pluginDir)
				if err != nil {
					return err
				}
				if !removed {
					fmt.Fprintln(cmd.OutOrStdout(), "No Rampart Antigravity integration found. Nothing to remove.")
					return nil
				}
				fmt.Fprintf(cmd.OutOrStdout(), "✓ Rampart Antigravity plugin removed from %s\n", pluginDir)
				return nil
			}

			hookBin := resolveRampartHookBinary()
			hookCommand := shellQuoteCodexHookArg(hookBin) + " hook --format antigravity"
			if runtime.GOOS == "windows" {
				hookCommand = windowsQuoteCodexHookArg(hookBin) + " hook --format antigravity"
			}
			if err := installAntigravityPlugin(pluginDir, hookCommand, force); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "✓ Rampart Antigravity policy plugin installed at %s\n", pluginDir)
			fmt.Fprintln(cmd.OutOrStdout(), "  Covers Antigravity CLI and IDE tool calls exposed through PreToolUse.")
			fmt.Fprintln(cmd.OutOrStdout(), "  Approval rules use force_ask so cached host permissions cannot bypass Rampart prompts.")
			fmt.Fprintln(cmd.OutOrStdout(), "  Restart active Antigravity sessions to load the plugin.")
			fmt.Fprintln(cmd.OutOrStdout(), "  Uninstall: rampart setup antigravity --remove")
			printFirstRunTest(cmd.OutOrStdout())
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Replace an existing non-Rampart plugin directory")
	cmd.Flags().BoolVar(&remove, "remove", false, "Remove the Rampart Antigravity plugin")
	return cmd
}

func antigravityPluginDir(home string) string {
	return filepath.Join(home, ".gemini", "config", "plugins", antigravityRampartPlugin)
}

func installAntigravityPlugin(pluginDir, hookCommand string, force bool) error {
	if entries, err := os.ReadDir(pluginDir); err == nil && len(entries) > 0 {
		if !antigravityPluginManaged(pluginDir) && !force {
			return fmt.Errorf("setup antigravity: existing %s is not managed by Rampart (use --force to replace)", pluginDir)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("setup antigravity: read %s: %w", pluginDir, err)
	}
	if force && !antigravityPluginManaged(pluginDir) {
		if err := os.RemoveAll(pluginDir); err != nil {
			return fmt.Errorf("setup antigravity: replace %s: %w", pluginDir, err)
		}
	}

	manifest, err := json.MarshalIndent(map[string]any{"name": antigravityRampartPlugin}, "", "  ")
	if err != nil {
		return fmt.Errorf("setup antigravity: marshal manifest: %w", err)
	}
	hooks, err := json.MarshalIndent(map[string]any{
		"rampart-policy": map[string]any{
			"enabled": true,
			"PreToolUse": []any{map[string]any{
				"matcher": "*",
				"hooks": []any{map[string]any{
					"type": "command", "command": hookCommand, "timeout": 330,
				}},
			}},
		},
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("setup antigravity: marshal hooks: %w", err)
	}
	if err := atomicWritePrivateFile(filepath.Join(pluginDir, "plugin.json"), append(manifest, '\n')); err != nil {
		return fmt.Errorf("setup antigravity: write plugin manifest: %w", err)
	}
	if err := atomicWritePrivateFile(filepath.Join(pluginDir, "hooks.json"), append(hooks, '\n')); err != nil {
		return fmt.Errorf("setup antigravity: write hooks: %w", err)
	}
	return nil
}

func antigravityPluginManaged(pluginDir string) bool {
	manifest, err := os.ReadFile(filepath.Join(pluginDir, "plugin.json"))
	if err != nil {
		return false
	}
	var plugin map[string]any
	if json.Unmarshal(manifest, &plugin) != nil || plugin["name"] != antigravityRampartPlugin {
		return false
	}
	hooks, err := os.ReadFile(filepath.Join(pluginDir, "hooks.json"))
	return err == nil && antigravityHookDataManaged(hooks)
}

func antigravityHookDataManaged(data []byte) bool {
	var config map[string]any
	if json.Unmarshal(data, &config) != nil {
		return false
	}
	policy, ok := config["rampart-policy"].(map[string]any)
	if !ok {
		return false
	}
	entries, ok := policy["PreToolUse"].([]any)
	if !ok || len(entries) != 1 {
		return false
	}
	matcher, ok := entries[0].(map[string]any)
	if !ok || matcher["matcher"] != "*" {
		return false
	}
	handlers, ok := matcher["hooks"].([]any)
	if !ok || len(handlers) != 1 {
		return false
	}
	handler, ok := handlers[0].(map[string]any)
	if !ok || handler["type"] != "command" {
		return false
	}
	command, _ := handler["command"].(string)
	return strings.Contains(command, "hook --format antigravity")
}

func antigravityPluginConfiguredForHome(home string) bool {
	return antigravityPluginManaged(antigravityPluginDir(home))
}

func removeAntigravityPlugin(pluginDir string) (bool, error) {
	if _, err := os.Stat(pluginDir); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("setup antigravity: inspect %s: %w", pluginDir, err)
	}
	if !antigravityPluginManaged(pluginDir) {
		return false, fmt.Errorf("setup antigravity: refusing to remove non-Rampart plugin directory %s", pluginDir)
	}
	if err := os.RemoveAll(pluginDir); err != nil {
		return false, fmt.Errorf("setup antigravity: remove %s: %w", pluginDir, err)
	}
	return true, nil
}
