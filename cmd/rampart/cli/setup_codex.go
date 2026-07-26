// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func newSetupCodexCmd(_ *rootOptions) *cobra.Command {
	var remove bool
	var force bool

	cmd := &cobra.Command{
		Use:   "codex",
		Short: "Install Rampart lifecycle hooks for Codex",
		Long: `Installs user-level PreToolUse and PostToolUse lifecycle hooks in
~/.codex/hooks.json. The hooks protect Codex CLI, the IDE extension, and the
desktop app without replacing the codex executable.

Existing non-Rampart hooks are preserved. A legacy Rampart preload wrapper is
removed during migration to avoid evaluating shell commands twice.

Run 'rampart setup codex --remove' to uninstall.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()

			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("setup codex: resolve home: %w", err)
			}

			hooksPath := filepath.Join(codexHomeDir(home), "hooks.json")
			wrapperDir := filepath.Join(home, ".local", "bin")
			wrapperPath := filepath.Join(wrapperDir, "codex")

			if remove {
				removedHooks, err := removeCodexHooks(hooksPath)
				if err != nil {
					return err
				}
				removedWrapper, err := removeManagedCodexWrapper(wrapperPath)
				if err != nil {
					return err
				}
				if !removedHooks && !removedWrapper {
					fmt.Fprintln(out, "No Rampart Codex integration found. Nothing to remove.")
					return nil
				}
				if removedHooks {
					fmt.Fprintf(out, "✓ Rampart hooks removed from %s\n", hooksPath)
				}
				if removedWrapper {
					fmt.Fprintf(out, "✓ Legacy Rampart wrapper removed from %s\n", wrapperPath)
				}
				return nil
			}

			hookBin := resolveRampartHookBinary()
			hookCommand := shellQuoteCodexHookArg(hookBin) + " hook --format codex"
			hookCommandWindows := windowsQuoteCodexHookArg(hookBin) + " hook --format codex"

			if err := installCodexHooks(hooksPath, hookCommand, hookCommandWindows, force); err != nil {
				return err
			}
			removedWrapper, err := removeManagedCodexWrapper(wrapperPath)
			if err != nil {
				return err
			}

			fmt.Fprintf(out, "✓ Rampart lifecycle hooks installed in %s\n", hooksPath)
			fmt.Fprintln(out, "  Covers Codex CLI, IDE extension, and desktop local tool calls.")
			fmt.Fprintln(out, "  Codex will require review of this hook definition before first use.")
			fmt.Fprintln(out, "  Open `/hooks` in Codex and trust the Rampart hooks.")
			if removedWrapper {
				fmt.Fprintf(out, "✓ Removed legacy preload wrapper at %s to prevent duplicate checks.\n", wrapperPath)
			}
			fmt.Fprintln(out, "  Uninstall: rampart setup codex --remove")
			printFirstRunTest(out)
			return nil
		},
	}

	cmd.Flags().BoolVar(&remove, "remove", false, "Remove Rampart Codex hooks and any managed legacy wrapper")
	cmd.Flags().BoolVar(&force, "force", false, "Replace invalid hooks.json instead of refusing")
	return cmd
}

func installCodexHooks(path, command, commandWindows string, force bool) error {
	settings := make(map[string]any)
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, &settings); err != nil {
			if !force {
				return fmt.Errorf("setup codex: existing %s has invalid JSON (use --force to replace): %w", path, err)
			}
			settings = make(map[string]any)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("setup codex: read %s: %w", path, err)
	}

	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		if _, exists := settings["hooks"]; exists && !force {
			return fmt.Errorf("setup codex: existing %s has a non-object hooks value (use --force to replace)", path)
		}
		hooks = make(map[string]any)
	}
	handler := map[string]any{
		"type":           "command",
		"command":        command,
		"commandWindows": commandWindows,
		"timeout":        330,
		"statusMessage":  "Checking Rampart policy",
	}
	matcher := map[string]any{
		"matcher": "*",
		"hooks":   []any{handler},
	}
	for _, event := range []string{"PreToolUse", "PostToolUse"} {
		if existing, exists := hooks[event]; exists {
			if _, valid := existing.([]any); !valid && !force {
				return fmt.Errorf("setup codex: existing %s %s value is not an array (use --force to replace)", path, event)
			}
		}
		hooks[event] = replaceRampartMatcher(hooks[event], matcher)
	}
	settings["hooks"] = hooks
	if _, ok := settings["description"]; !ok {
		settings["description"] = "Codex lifecycle hooks, including Rampart policy enforcement."
	}
	return writeCodexHooks(path, settings)
}

func codexHooksConfiguredForHome(home string) bool {
	data, err := os.ReadFile(filepath.Join(codexHomeDir(home), "hooks.json"))
	if err != nil {
		return false
	}
	var settings map[string]any
	if json.Unmarshal(data, &settings) != nil {
		return false
	}
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		return false
	}
	for _, event := range []string{"PreToolUse", "PostToolUse"} {
		entries, ok := hooks[event].([]any)
		if !ok {
			return false
		}
		found := false
		for _, entry := range entries {
			matcher, ok := entry.(map[string]any)
			if ok && isRampartCodexMatcher(matcher) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func codexHomeDir(home string) string {
	if configured := strings.TrimSpace(os.Getenv("CODEX_HOME")); configured != "" {
		expanded := os.ExpandEnv(configured)
		if strings.HasPrefix(expanded, "~"+string(os.PathSeparator)) {
			expanded = filepath.Join(home, strings.TrimPrefix(expanded, "~"+string(os.PathSeparator)))
		}
		return filepath.Clean(expanded)
	}
	return filepath.Join(home, ".codex")
}

func replaceRampartMatcher(existing any, rampartMatcher map[string]any) []any {
	var kept []any
	if entries, ok := existing.([]any); ok {
		for _, entry := range entries {
			if matcher, ok := entry.(map[string]any); ok && isRampartCodexMatcher(matcher) {
				continue
			}
			kept = append(kept, entry)
		}
	}
	return append(kept, rampartMatcher)
}

func removeCodexHooks(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("setup codex: read %s: %w", path, err)
	}
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		return false, fmt.Errorf("setup codex: parse %s: %w", path, err)
	}
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		return false, nil
	}

	removed := false
	for _, event := range []string{"PreToolUse", "PostToolUse"} {
		entries, ok := hooks[event].([]any)
		if !ok {
			continue
		}
		var kept []any
		for _, entry := range entries {
			if matcher, ok := entry.(map[string]any); ok && isRampartCodexMatcher(matcher) {
				removed = true
				continue
			}
			kept = append(kept, entry)
		}
		if len(kept) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = kept
		}
	}
	if !removed {
		return false, nil
	}
	settings["hooks"] = hooks
	return true, writeCodexHooks(path, settings)
}

func isRampartCodexMatcher(matcher map[string]any) bool {
	handlers, ok := matcher["hooks"].([]any)
	if !ok {
		return false
	}
	for _, rawHandler := range handlers {
		handler, ok := rawHandler.(map[string]any)
		if !ok {
			continue
		}
		for _, field := range []string{"command", "commandWindows"} {
			command, _ := handler[field].(string)
			// "hook --format codex" is Rampart's CLI contract. The executable
			// may be an absolute release path (or a Go test binary), so do not
			// key ownership detection on the basename.
			if strings.Contains(command, "hook --format codex") {
				return true
			}
		}
	}
	return false
}

func writeCodexHooks(path string, settings map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("setup codex: create hooks directory: %w", err)
	}
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("setup codex: marshal hooks: %w", err)
	}
	data = append(data, '\n')

	temp, err := os.CreateTemp(filepath.Dir(path), ".rampart-codex-hooks-*.json")
	if err != nil {
		return fmt.Errorf("setup codex: create temporary hooks file: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("setup codex: secure temporary hooks file: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return fmt.Errorf("setup codex: write temporary hooks file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("setup codex: close temporary hooks file: %w", err)
	}
	if err := replaceCodexHooksFile(tempPath, path); err != nil {
		return fmt.Errorf("setup codex: replace hooks file: %w", err)
	}
	return nil
}

func removeManagedCodexWrapper(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("setup codex: read legacy wrapper: %w", err)
	}
	if !containsRampartPreload(string(data)) {
		return false, nil
	}
	if err := os.Remove(path); err != nil {
		return false, fmt.Errorf("setup codex: remove legacy wrapper: %w", err)
	}
	return true, nil
}

func shellQuoteCodexHookArg(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

func windowsQuoteCodexHookArg(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
}

func containsRampartPreload(content string) bool {
	return strings.Contains(content, "rampart preload") ||
		strings.Contains(content, "Rampart wrapper")
}
