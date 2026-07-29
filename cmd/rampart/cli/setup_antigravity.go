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

			hookCommand := currentAntigravityHookCommand()
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
	return installAntigravityPluginWithRename(pluginDir, hookCommand, force, os.Rename)
}

func installAntigravityPluginWithRename(
	pluginDir, hookCommand string,
	force bool,
	rename func(string, string) error,
) error {
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

	pluginDir = filepath.Clean(pluginDir)
	parent := filepath.Dir(pluginDir)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("setup antigravity: create plugin parent: %w", err)
	}
	hadPrior := false
	managedPrior := false
	if info, statErr := os.Lstat(pluginDir); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("setup antigravity: refusing to replace symlinked plugin directory %s", pluginDir)
		}
		if !info.IsDir() {
			return fmt.Errorf("setup antigravity: refusing to replace non-directory plugin path %s", pluginDir)
		}
		managedPrior = antigravityPluginManaged(pluginDir)
		if !managedPrior && !force {
			return fmt.Errorf("setup antigravity: existing %s is not managed by Rampart (use --force to replace)", pluginDir)
		}
		hadPrior = true
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("setup antigravity: inspect %s: %w", pluginDir, statErr)
	}
	if managedPrior {
		// Keep an enforcing plugin present throughout routine upgrades. Each file
		// replacement is atomic and hooks.json is refreshed first, so a crash can
		// leave only a harmless old manifest rather than an absent plugin.
		if err := atomicWritePrivateFile(filepath.Join(pluginDir, "hooks.json"), append(hooks, '\n')); err != nil {
			return fmt.Errorf("setup antigravity: update hooks: %w", err)
		}
		if err := atomicWritePrivateFile(filepath.Join(pluginDir, "plugin.json"), append(manifest, '\n')); err != nil {
			return fmt.Errorf("setup antigravity: update plugin manifest: %w", err)
		}
		if !antigravityPluginManaged(pluginDir) {
			return fmt.Errorf("setup antigravity: updated plugin failed integrity validation")
		}
		return nil
	}

	txnDir, err := os.MkdirTemp(parent, ".rampart-antigravity-install-*")
	if err != nil {
		return fmt.Errorf("setup antigravity: create transaction: %w", err)
	}
	preserveTxn := false
	defer func() {
		if !preserveTxn {
			_ = os.RemoveAll(txnDir)
		}
	}()
	stageDir := filepath.Join(txnDir, "stage")
	backupDir := filepath.Join(txnDir, "backup")
	if err := os.Mkdir(stageDir, 0o700); err != nil {
		return fmt.Errorf("setup antigravity: create staged plugin: %w", err)
	}
	if err := atomicWritePrivateFile(filepath.Join(stageDir, "plugin.json"), append(manifest, '\n')); err != nil {
		return fmt.Errorf("setup antigravity: write plugin manifest: %w", err)
	}
	if err := atomicWritePrivateFile(filepath.Join(stageDir, "hooks.json"), append(hooks, '\n')); err != nil {
		return fmt.Errorf("setup antigravity: write hooks: %w", err)
	}
	if !antigravityPluginManaged(stageDir) {
		return fmt.Errorf("setup antigravity: staged plugin failed integrity validation")
	}

	rollback := func(cause error) error {
		var rollbackErrs []string
		if info, statErr := os.Lstat(pluginDir); statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || !antigravityPluginManaged(pluginDir) {
				rollbackErrs = append(rollbackErrs, fmt.Sprintf("refusing to remove unowned replacement at %s", pluginDir))
			} else if removeErr := os.RemoveAll(pluginDir); removeErr != nil {
				rollbackErrs = append(rollbackErrs, fmt.Sprintf("remove replacement: %v", removeErr))
			}
		} else if !os.IsNotExist(statErr) {
			rollbackErrs = append(rollbackErrs, fmt.Sprintf("inspect replacement: %v", statErr))
		}
		if hadPrior {
			if _, statErr := os.Lstat(pluginDir); statErr == nil {
				rollbackErrs = append(rollbackErrs, "restore target is occupied")
			} else if !os.IsNotExist(statErr) {
				rollbackErrs = append(rollbackErrs, fmt.Sprintf("inspect restore target: %v", statErr))
			} else if restoreErr := rename(backupDir, pluginDir); restoreErr != nil {
				rollbackErrs = append(rollbackErrs, fmt.Sprintf("restore prior plugin: %v", restoreErr))
			}
		}
		if len(rollbackErrs) > 0 {
			preserveTxn = true
			return fmt.Errorf("%w (rollback incomplete: %s; backup preserved at %s)", cause, strings.Join(rollbackErrs, "; "), txnDir)
		}
		return cause
	}

	if hadPrior {
		if err := rename(pluginDir, backupDir); err != nil {
			return fmt.Errorf("setup antigravity: back up existing plugin: %w", err)
		}
	}
	if err := rename(stageDir, pluginDir); err != nil {
		return rollback(fmt.Errorf("setup antigravity: activate staged plugin: %w", err))
	}
	if !antigravityPluginManaged(pluginDir) {
		return rollback(fmt.Errorf("setup antigravity: installed plugin failed integrity validation"))
	}
	if err := os.RemoveAll(txnDir); err != nil {
		preserveTxn = true
		return fmt.Errorf("setup antigravity: plugin installed but transaction cleanup failed at %s: %w", txnDir, err)
	}
	return nil
}

func antigravityPluginManaged(pluginDir string) bool {
	info, err := os.Lstat(pluginDir)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false
	}
	entries, err := os.ReadDir(pluginDir)
	if err != nil || len(entries) != 2 {
		return false
	}
	for _, entry := range entries {
		if entry.Name() != "plugin.json" && entry.Name() != "hooks.json" {
			return false
		}
	}
	manifestPath := filepath.Join(pluginDir, "plugin.json")
	manifestInfo, err := os.Lstat(manifestPath)
	if err != nil || manifestInfo.Mode()&os.ModeSymlink != 0 || !manifestInfo.Mode().IsRegular() {
		return false
	}
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return false
	}
	var plugin map[string]any
	if json.Unmarshal(manifest, &plugin) != nil || plugin["name"] != antigravityRampartPlugin {
		return false
	}
	hooksPath := filepath.Join(pluginDir, "hooks.json")
	hooksInfo, err := os.Lstat(hooksPath)
	if err != nil || hooksInfo.Mode()&os.ModeSymlink != 0 || !hooksInfo.Mode().IsRegular() {
		return false
	}
	hooks, err := os.ReadFile(hooksPath)
	return err == nil && antigravityHookDataManaged(hooks)
}

func antigravityHookDataManaged(data []byte) bool {
	command, ok := antigravityHookCommand(data)
	return ok && hasRampartHookFormat(command, "antigravity")
}

func antigravityHookCommand(data []byte) (string, bool) {
	var config map[string]any
	if json.Unmarshal(data, &config) != nil {
		return "", false
	}
	policy, ok := config["rampart-policy"].(map[string]any)
	if !ok {
		return "", false
	}
	entries, ok := policy["PreToolUse"].([]any)
	if !ok || len(entries) != 1 {
		return "", false
	}
	matcher, ok := entries[0].(map[string]any)
	if !ok || matcher["matcher"] != "*" {
		return "", false
	}
	handlers, ok := matcher["hooks"].([]any)
	if !ok || len(handlers) != 1 {
		return "", false
	}
	handler, ok := handlers[0].(map[string]any)
	if !ok || handler["type"] != "command" {
		return "", false
	}
	command, _ := handler["command"].(string)
	return command, command != ""
}

func antigravityPluginConfiguredForHome(home string) bool {
	pluginDir := antigravityPluginDir(home)
	if !antigravityPluginManaged(pluginDir) {
		return false
	}
	hooks, err := os.ReadFile(filepath.Join(pluginDir, "hooks.json"))
	if err != nil {
		return false
	}
	command, ok := antigravityHookCommand(hooks)
	return ok && command == currentAntigravityHookCommand()
}

func currentAntigravityHookCommand() string {
	hookBin := resolveRampartHookBinary()
	if runtime.GOOS == "windows" {
		return windowsQuoteCodexHookArg(hookBin) + " hook --format antigravity"
	}
	return shellQuoteCodexHookArg(hookBin) + " hook --format antigravity"
}

func removeAntigravityPlugin(pluginDir string) (bool, error) {
	info, err := os.Lstat(pluginDir)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("setup antigravity: inspect %s: %w", pluginDir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, fmt.Errorf("setup antigravity: refusing to remove linked or non-directory plugin path %s", pluginDir)
	}
	if !antigravityPluginManaged(pluginDir) {
		return false, fmt.Errorf("setup antigravity: refusing to remove non-Rampart plugin directory %s", pluginDir)
	}
	if err := os.RemoveAll(pluginDir); err != nil {
		return false, fmt.Errorf("setup antigravity: remove %s: %w", pluginDir, err)
	}
	return true, nil
}
