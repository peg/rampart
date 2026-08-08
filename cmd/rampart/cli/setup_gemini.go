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

func newSetupGeminiCmd() *cobra.Command {
	var force bool
	var remove bool

	cmd := &cobra.Command{
		Use:   "gemini",
		Short: "Install experimental Rampart hooks for Gemini CLI",
		Long: `Installs experimental user-level BeforeTool and AfterTool hooks in
~/.gemini/settings.json. Existing Gemini settings and non-Rampart hooks are
preserved.

This targets enterprise, Google Cloud, and paid API-key Gemini CLI access. It
does not configure Antigravity and is not part of zero-configuration protect.

Run 'rampart setup gemini --remove' to uninstall.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("setup gemini: resolve home: %w", err)
			}
			settingsPath := filepath.Join(home, ".gemini", "settings.json")
			if remove {
				removed, err := removeGeminiHooks(settingsPath)
				if err != nil {
					return err
				}
				if !removed {
					fmt.Fprintln(cmd.OutOrStdout(), "No Rampart Gemini CLI integration found. Nothing to remove.")
					return nil
				}
				fmt.Fprintf(cmd.OutOrStdout(), "✓ Rampart hooks removed from %s\n", settingsPath)
				return nil
			}

			hookCommand := currentGeminiHookCommand()
			if err := installGeminiHooks(settingsPath, hookCommand, force); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "✓ Rampart lifecycle hooks installed in %s\n", settingsPath)
			fmt.Fprintln(cmd.OutOrStdout(), "  Covers Gemini CLI tool calls exposed through BeforeTool and AfterTool.")
			fmt.Fprintln(cmd.OutOrStdout(), "  Allowed calls still pass through Gemini's own permission checks.")
			fmt.Fprintln(cmd.OutOrStdout(), "  Uninstall: rampart setup gemini --remove")
			printFirstRunTest(cmd.OutOrStdout())
			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Replace invalid Gemini hook configuration instead of refusing")
	cmd.Flags().BoolVar(&remove, "remove", false, "Remove Rampart hooks from Gemini CLI settings")
	return cmd
}

func installGeminiHooks(path, command string, force bool) error {
	settings := make(map[string]any)
	exists, err := regularConfigFileExists(path)
	if err != nil {
		return fmt.Errorf("setup gemini: inspect %s: %w", path, err)
	}
	if exists {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("setup gemini: read %s: %w", path, err)
		}
		if err := decodeUserJSON(data, &settings); err != nil {
			if !force {
				return fmt.Errorf("setup gemini: existing %s has invalid JSON (use --force to replace): %w", path, err)
			}
			settings = make(map[string]any)
		}
	}

	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		if _, exists := settings["hooks"]; exists && !force {
			return fmt.Errorf("setup gemini: existing %s has a non-object hooks value (use --force to replace)", path)
		}
		hooks = make(map[string]any)
	}
	handler := map[string]any{
		"type":    "command",
		"command": command,
		"name":    "Rampart policy enforcement",
		"timeout": 330000,
	}
	matcher := map[string]any{
		"matcher": ".*",
		"hooks":   []any{handler},
	}
	for _, event := range []string{"BeforeTool", "AfterTool"} {
		if existing, exists := hooks[event]; exists {
			if _, valid := existing.([]any); !valid && !force {
				return fmt.Errorf("setup gemini: existing %s %s value is not an array (use --force to replace)", path, event)
			}
		}
		hooks[event] = replaceGeminiRampartMatcher(hooks[event], matcher)
	}
	settings["hooks"] = hooks
	return writeGeminiSettings(path, settings)
}

func geminiHooksConfiguredForHome(home string) bool {
	path := filepath.Join(home, ".gemini", "settings.json")
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
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		return false
	}
	for _, event := range []string{"BeforeTool", "AfterTool"} {
		entries, ok := hooks[event].([]any)
		if !ok {
			return false
		}
		found := false
		for _, entry := range entries {
			matcher, ok := entry.(map[string]any)
			if ok && geminiMatcherUsesCommand(matcher, currentGeminiHookCommand()) {
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

func currentGeminiHookCommand() string {
	hookBin := resolveRampartHookBinary()
	if runtime.GOOS == "windows" {
		return windowsQuoteCodexHookArg(hookBin) + " hook --format gemini"
	}
	return shellQuoteCodexHookArg(hookBin) + " hook --format gemini"
}

func geminiMatcherUsesCommand(matcher map[string]any, expected string) bool {
	handlers, ok := matcher["hooks"].([]any)
	if !ok {
		return false
	}
	for _, rawHandler := range handlers {
		handler, ok := rawHandler.(map[string]any)
		if !ok {
			continue
		}
		command, _ := handler["command"].(string)
		if command == expected {
			return true
		}
	}
	return false
}

func replaceGeminiRampartMatcher(existing any, rampartMatcher map[string]any) []any {
	var kept []any
	if entries, ok := existing.([]any); ok {
		for _, entry := range entries {
			if matcher, ok := entry.(map[string]any); ok && isRampartGeminiMatcher(matcher) {
				continue
			}
			kept = append(kept, entry)
		}
	}
	return append(kept, rampartMatcher)
}

func removeGeminiHooks(path string) (bool, error) {
	exists, err := regularConfigFileExists(path)
	if err != nil {
		return false, fmt.Errorf("setup gemini: inspect %s: %w", path, err)
	}
	if !exists {
		return false, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("setup gemini: read %s: %w", path, err)
	}
	var settings map[string]any
	if err := decodeUserJSON(data, &settings); err != nil {
		return false, fmt.Errorf("setup gemini: parse %s: %w", path, err)
	}
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		return false, nil
	}

	removed := false
	for _, event := range []string{"BeforeTool", "AfterTool"} {
		entries, ok := hooks[event].([]any)
		if !ok {
			continue
		}
		var kept []any
		for _, entry := range entries {
			if matcher, ok := entry.(map[string]any); ok && isRampartGeminiMatcher(matcher) {
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
	return true, writeGeminiSettings(path, settings)
}

func isRampartGeminiMatcher(matcher map[string]any) bool {
	handlers, ok := matcher["hooks"].([]any)
	if !ok {
		return false
	}
	for _, rawHandler := range handlers {
		handler, ok := rawHandler.(map[string]any)
		if !ok {
			continue
		}
		command, _ := handler["command"].(string)
		if hasRampartHookFormat(command, "gemini") {
			return true
		}
	}
	return false
}

func writeGeminiSettings(path string, settings map[string]any) error {
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("setup gemini: marshal settings: %w", err)
	}
	data = append(data, '\n')
	if err := atomicWritePrivateFile(path, data); err != nil {
		return fmt.Errorf("setup gemini: write settings: %w", err)
	}
	return nil
}
