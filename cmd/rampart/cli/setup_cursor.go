// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"
)

const cursorHookTimeoutSeconds = 330

func cursorConfigDir(home string) string {
	return filepath.Join(home, ".cursor")
}

func cursorHooksPath(home string) string {
	return filepath.Join(cursorConfigDir(home), "hooks.json")
}

func newSetupCursorCmd(_ *rootOptions) *cobra.Command {
	var remove bool
	var force bool

	cmd := &cobra.Command{
		Use:   "cursor",
		Short: "Install Rampart's native Cursor Agent hook",
		Long: `Installs a user-level preToolUse hook in ~/.cursor/hooks.json.

The hook covers local Cursor Agent and Cmd+K tool calls, preserves Cursor's
own permission decisions when Rampart allows an action, and fails closed when
the managed hook crashes, times out, or returns invalid output. Cursor Tab and
user-level Cloud Agent execution are separate host surfaces and are not covered.

Existing non-Rampart hooks are preserved. Run 'rampart setup cursor --remove'
to uninstall the managed entry.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("setup cursor: resolve home: %w", err)
			}
			path := cursorHooksPath(home)
			if remove {
				removed, err := removeCursorHooks(path)
				if err != nil {
					return err
				}
				if !removed {
					fmt.Fprintln(cmd.OutOrStdout(), "No Rampart Cursor hook found. Nothing to remove.")
					return nil
				}
				fmt.Fprintf(cmd.OutOrStdout(), "✓ Rampart Cursor hook removed from %s\n", path)
				return nil
			}

			if err := installCursorHooks(path, currentCursorHookCommand(), force); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "✓ Rampart Cursor Agent hook installed in %s\n", path)
			fmt.Fprintln(cmd.OutOrStdout(), "  Covers local Agent and Cmd+K pre-tool calls; Cursor Tab and Cloud Agent are separate surfaces.")
			fmt.Fprintln(cmd.OutOrStdout(), "  Approval policies require the local Rampart service used by `rampart protect cursor`.")
			fmt.Fprintln(cmd.OutOrStdout(), "  Cursor watches hooks.json and reloads changes automatically.")
			fmt.Fprintln(cmd.OutOrStdout(), "  Uninstall: rampart setup cursor --remove")
			printFirstRunTest(cmd.OutOrStdout())
			return nil
		},
	}
	cmd.Flags().BoolVar(&remove, "remove", false, "Remove only Rampart's Cursor hook")
	cmd.Flags().BoolVar(&force, "force", false, "Replace invalid Cursor hook configuration instead of refusing")
	return cmd
}

func currentCursorHookCommand() string {
	bin := resolveRampartHookBinary()
	if runtime.GOOS == "windows" {
		return windowsQuoteCodexHookArg(bin) + " hook --format cursor"
	}
	return shellQuoteCodexHookArg(bin) + " hook --format cursor"
}

func installCursorHooks(path, command string, force bool) error {
	settings, err := readCursorHooks(path, force)
	if err != nil {
		return err
	}
	if version, exists := settings["version"]; exists && !cursorVersionOne(version) && !force {
		return fmt.Errorf("setup cursor: existing %s has unsupported version %v (use --force to replace)", path, version)
	}
	settings["version"] = 1

	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		if _, exists := settings["hooks"]; exists && !force {
			return fmt.Errorf("setup cursor: existing %s has a non-object hooks value (use --force to replace)", path)
		}
		hooks = make(map[string]any)
	}
	entries, ok := hooks["preToolUse"].([]any)
	if !ok {
		if _, exists := hooks["preToolUse"]; exists && !force {
			return fmt.Errorf("setup cursor: existing %s preToolUse value is not an array (use --force to replace)", path)
		}
		entries = nil
	}
	kept, _ := removeRampartCursorEntries(entries)
	hooks["preToolUse"] = append(kept, map[string]any{
		"command":    command,
		"timeout":    cursorHookTimeoutSeconds,
		"failClosed": true,
	})
	settings["hooks"] = hooks
	return writeCursorHooks(path, settings)
}

func readCursorHooks(path string, force bool) (map[string]any, error) {
	settings := make(map[string]any)
	exists, err := regularConfigFileExists(path)
	if err != nil {
		return nil, fmt.Errorf("setup cursor: inspect %s: %w", path, err)
	}
	if !exists {
		return settings, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("setup cursor: read %s: %w", path, err)
	}
	if err := decodeUserJSON(data, &settings); err != nil {
		if !force {
			return nil, fmt.Errorf("setup cursor: existing %s has invalid JSON (use --force to replace): %w", path, err)
		}
		return make(map[string]any), nil
	}
	return settings, nil
}

func cursorVersionOne(value any) bool {
	switch typed := value.(type) {
	case json.Number:
		return typed.String() == "1"
	case float64:
		return typed == 1
	case int:
		return typed == 1
	default:
		return false
	}
}

func cursorHookTimeoutCurrent(value any) bool {
	switch typed := value.(type) {
	case json.Number:
		return typed.String() == fmt.Sprint(cursorHookTimeoutSeconds)
	case float64:
		return typed == cursorHookTimeoutSeconds
	case int:
		return typed == cursorHookTimeoutSeconds
	default:
		return false
	}
}

func isRampartCursorEntry(entry map[string]any) bool {
	command, _ := entry["command"].(string)
	return hasRampartHookFormat(command, "cursor")
}

func removeRampartCursorEntries(entries []any) ([]any, bool) {
	kept := make([]any, 0, len(entries))
	removed := false
	for _, raw := range entries {
		entry, ok := raw.(map[string]any)
		if ok && isRampartCursorEntry(entry) {
			removed = true
			continue
		}
		kept = append(kept, raw)
	}
	return kept, removed
}

func cursorRampartHooksPresent(home string) bool {
	path := cursorHooksPath(home)
	if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return true
	}
	settings, err := readCursorHooks(path, false)
	if err != nil {
		return fileContains(path, "hook --format cursor")
	}
	hooks, _ := settings["hooks"].(map[string]any)
	entries, _ := hooks["preToolUse"].([]any)
	for _, raw := range entries {
		if entry, ok := raw.(map[string]any); ok && isRampartCursorEntry(entry) {
			return true
		}
	}
	return false
}

func cursorHooksConfiguredForHome(home string) bool {
	settings, err := readCursorHooks(cursorHooksPath(home), false)
	if err != nil || !cursorVersionOne(settings["version"]) {
		return false
	}
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		return false
	}
	entries, ok := hooks["preToolUse"].([]any)
	if !ok {
		return false
	}
	owned := 0
	for _, raw := range entries {
		entry, ok := raw.(map[string]any)
		if !ok || !isRampartCursorEntry(entry) {
			continue
		}
		owned++
		if entry["command"] != currentCursorHookCommand() || entry["failClosed"] != true || !cursorHookTimeoutCurrent(entry["timeout"]) {
			return false
		}
	}
	return owned == 1
}

func removeCursorHooks(path string) (bool, error) {
	settings, err := readCursorHooks(path, false)
	if err != nil {
		return false, err
	}
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		return false, nil
	}
	entries, ok := hooks["preToolUse"].([]any)
	if !ok {
		return false, nil
	}
	kept, removed := removeRampartCursorEntries(entries)
	if !removed {
		return false, nil
	}
	if len(kept) == 0 {
		delete(hooks, "preToolUse")
	} else {
		hooks["preToolUse"] = kept
	}
	settings["hooks"] = hooks
	return true, writeCursorHooks(path, settings)
}

func writeCursorHooks(path string, settings map[string]any) error {
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("setup cursor: marshal hooks: %w", err)
	}
	data = append(data, '\n')
	if err := atomicWritePrivateFile(path, data); err != nil {
		return fmt.Errorf("setup cursor: write hooks file: %w", err)
	}
	return nil
}

func cursorInstalledForHome(home string) bool {
	if _, err := execLookPath("cursor"); err == nil {
		return true
	}
	if _, err := execLookPath("cursor-agent"); err == nil {
		return true
	}
	info, err := os.Stat(cursorConfigDir(home))
	return err == nil && info.IsDir()
}
