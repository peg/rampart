// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// decodeUserJSON preserves arbitrary numeric fields owned by the host. The
// default map[string]any decoder converts numbers to float64, which can round
// unrelated integer settings when Rampart later rewrites the document.
func decodeUserJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func regularConfigFileExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return false, fmt.Errorf("refusing linked or non-regular configuration path %s", path)
	}
	return true, nil
}

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

			hookCommand, hookCommandWindows := currentCodexHookCommands()

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
	exists, err := regularConfigFileExists(path)
	if err != nil {
		return fmt.Errorf("setup codex: inspect %s: %w", path, err)
	}
	if exists {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("setup codex: read %s: %w", path, err)
		}
		if err := decodeUserJSON(data, &settings); err != nil {
			if !force {
				return fmt.Errorf("setup codex: existing %s has invalid JSON (use --force to replace): %w", path, err)
			}
			settings = make(map[string]any)
		}
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
	path := filepath.Join(codexHomeDir(home), "hooks.json")
	exists, err := regularConfigFileExists(path)
	if err != nil || !exists {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var settings map[string]any
	if decodeUserJSON(data, &settings) != nil {
		return false
	}
	command, commandWindows := currentCodexHookCommands()
	return codexHooksUseCommands(settings, command, commandWindows)
}

func currentCodexHookCommands() (string, string) {
	hookBin := resolveRampartHookBinary()
	return shellQuoteCodexHookArg(hookBin) + " hook --format codex",
		windowsQuoteCodexHookArg(hookBin) + " hook --format codex"
}

func codexHooksUseCommands(settings map[string]any, command, commandWindows string) bool {
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		return false
	}
	for _, event := range []string{"PreToolUse", "PostToolUse"} {
		entries, ok := hooks[event].([]any)
		if !ok {
			return false
		}
		owned := 0
		for _, entry := range entries {
			matcher, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			handlers, _ := matcher["hooks"].([]any)
			for _, rawHandler := range handlers {
				handler, ok := rawHandler.(map[string]any)
				if !ok || !isRampartCodexHandler(handler) {
					continue
				}
				owned++
				if matcher["matcher"] != "*" || handler["type"] != "command" ||
					handler["command"] != command || handler["commandWindows"] != commandWindows {
					return false
				}
			}
		}
		if owned != 1 {
			return false
		}
	}
	return true
}

func codexHomeDir(home string) string {
	if configured := strings.TrimSpace(os.Getenv("CODEX_HOME")); configured != "" {
		expanded := os.ExpandEnv(configured)
		if expanded == "~" {
			return filepath.Clean(home)
		}
		if len(expanded) >= 2 && expanded[0] == '~' && (expanded[1] == '/' || expanded[1] == '\\') {
			// Environment files and cross-platform launchers commonly use `/`
			// even on Windows. Accept both separator forms for a leading tilde.
			relative := strings.ReplaceAll(expanded[2:], "\\", "/")
			expanded = filepath.Join(home, filepath.FromSlash(relative))
		}
		return filepath.Clean(expanded)
	}
	return filepath.Join(home, ".codex")
}

func replaceRampartMatcher(existing any, rampartMatcher map[string]any) []any {
	kept, _ := removeRampartCodexHandlers(existing)
	return append(kept, rampartMatcher)
}

func removeCodexHooks(path string) (bool, error) {
	exists, err := regularConfigFileExists(path)
	if err != nil {
		return false, fmt.Errorf("setup codex: inspect %s: %w", path, err)
	}
	if !exists {
		return false, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("setup codex: read %s: %w", path, err)
	}
	var settings map[string]any
	if err := decodeUserJSON(data, &settings); err != nil {
		return false, fmt.Errorf("setup codex: parse %s: %w", path, err)
	}
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		return false, nil
	}

	removed := false
	for _, event := range []string{"PreToolUse", "PostToolUse"} {
		kept, eventRemoved := removeRampartCodexHandlers(hooks[event])
		removed = removed || eventRemoved
		if !eventRemoved {
			continue
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
		if ok && isRampartCodexHandler(handler) {
			return true
		}
	}
	return false
}

func isRampartCodexHandler(handler map[string]any) bool {
	for _, field := range []string{"command", "commandWindows"} {
		command, _ := handler[field].(string)
		// "hook --format codex" is Rampart's CLI contract. The executable
		// may be an absolute release path (or a Go test binary), so do not
		// key ownership detection on the basename.
		if hasRampartHookFormat(command, "codex") {
			return true
		}
	}
	return false
}

// removeRampartCodexHandlers removes only Rampart-owned commands. Codex hook
// matchers may contain multiple handlers, so setup and uninstall must preserve
// unrelated handlers and all matcher metadata.
func removeRampartCodexHandlers(existing any) ([]any, bool) {
	entries, ok := existing.([]any)
	if !ok {
		return nil, false
	}
	kept := make([]any, 0, len(entries))
	removed := false
	for _, entry := range entries {
		matcher, ok := entry.(map[string]any)
		if !ok {
			kept = append(kept, entry)
			continue
		}
		handlers, ok := matcher["hooks"].([]any)
		if !ok {
			kept = append(kept, entry)
			continue
		}
		remaining := make([]any, 0, len(handlers))
		for _, rawHandler := range handlers {
			handler, ok := rawHandler.(map[string]any)
			if ok && isRampartCodexHandler(handler) {
				removed = true
				continue
			}
			remaining = append(remaining, rawHandler)
		}
		if len(remaining) == len(handlers) {
			kept = append(kept, entry)
			continue
		}
		if len(remaining) > 0 {
			copyMatcher := make(map[string]any, len(matcher))
			for key, value := range matcher {
				copyMatcher[key] = value
			}
			copyMatcher["hooks"] = remaining
			kept = append(kept, copyMatcher)
		}
	}
	return kept, removed
}

func writeCodexHooks(path string, settings map[string]any) error {
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("setup codex: marshal hooks: %w", err)
	}
	data = append(data, '\n')
	if err := atomicWritePrivateFile(path, data); err != nil {
		return fmt.Errorf("setup codex: write hooks file: %w", err)
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
