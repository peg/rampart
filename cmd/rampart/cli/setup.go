// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func newSetupCmd(opts *rootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Set up Rampart integrations with AI agents",
	}

	cmd.AddCommand(newSetupClaudeCodeCmd(opts))
	cmd.AddCommand(newSetupClineCmd(opts))

	return cmd
}

// claudeSettings represents the Claude Code settings.json structure.
// We use a flexible map to preserve existing settings.
type claudeSettings map[string]any

func newSetupClaudeCodeCmd(opts *rootOptions) *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "claude-code",
		Short: "Install Rampart hook into Claude Code settings",
		Long: `Adds a PreToolUse hook to ~/.claude/settings.json that routes all
Bash commands through Rampart's policy engine before execution.

Safe to run multiple times — will not duplicate hooks or overwrite
other settings.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("setup: resolve home: %w", err)
			}

			settingsPath := filepath.Join(home, ".claude", "settings.json")

			// Load existing settings or start fresh
			settings := make(claudeSettings)
			if data, err := os.ReadFile(settingsPath); err == nil {
				if err := json.Unmarshal(data, &settings); err != nil {
					if !force {
						return fmt.Errorf("setup: existing %s has invalid JSON (use --force to overwrite): %w", settingsPath, err)
					}
					settings = make(claudeSettings)
				}
			}

			// Check if Rampart hook already exists
			if hasRampartHook(settings) && !force {
				fmt.Fprintln(cmd.OutOrStdout(), "Rampart hook already configured in Claude Code settings.")
				return nil
			}

			// Build the hook config
			rampartHook := map[string]any{
				"type":    "command",
				"command": "rampart hook",
			}

			bashMatcher := map[string]any{
				"matcher": "Bash",
				"hooks":   []any{rampartHook},
			}
			readMatcher := map[string]any{
				"matcher": "Read",
				"hooks":   []any{rampartHook},
			}
			writeMatcher := map[string]any{
				"matcher": "Write|Edit",
				"hooks":   []any{rampartHook},
			}

			// Get or create hooks section
			hooks, ok := settings["hooks"].(map[string]any)
			if !ok {
				hooks = make(map[string]any)
			}

			// Get or create PreToolUse array
			var preToolUse []any
			if existing, ok := hooks["PreToolUse"].([]any); ok {
				// Filter out any existing rampart hooks
				for _, h := range existing {
					if m, ok := h.(map[string]any); ok {
						if hasRampartInMatcher(m) {
							continue
						}
					}
					preToolUse = append(preToolUse, h)
				}
			}
			preToolUse = append(preToolUse, bashMatcher, readMatcher, writeMatcher)

			hooks["PreToolUse"] = preToolUse
			settings["hooks"] = hooks

			// Ensure directory exists
			if err := os.MkdirAll(filepath.Dir(settingsPath), 0o755); err != nil {
				return fmt.Errorf("setup: create .claude dir: %w", err)
			}

			// Write settings
			data, err := json.MarshalIndent(settings, "", "  ")
			if err != nil {
				return fmt.Errorf("setup: marshal settings: %w", err)
			}
			data = append(data, '\n')

			if err := os.WriteFile(settingsPath, data, 0o644); err != nil {
				return fmt.Errorf("setup: write settings: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "✓ Rampart hook installed in %s\n", settingsPath)
			fmt.Fprintln(cmd.OutOrStdout(), "  Claude Code will now route Bash commands through Rampart.")
			fmt.Fprintln(cmd.OutOrStdout(), "  Run 'claude' normally — no wrapper needed.")
			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing Rampart hook config")
	return cmd
}

func newSetupClineCmd(opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "cline",
		Short: "Install Rampart hook into Cline settings (coming soon)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "Cline integration coming soon.")
			fmt.Fprintln(cmd.OutOrStdout(), "For now, use: rampart wrap -- cline")
			return nil
		},
	}
}

func hasRampartHook(settings claudeSettings) bool {
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		return false
	}
	preToolUse, ok := hooks["PreToolUse"].([]any)
	if !ok {
		return false
	}
	for _, h := range preToolUse {
		if m, ok := h.(map[string]any); ok {
			if hasRampartInMatcher(m) {
				return true
			}
		}
	}
	return false
}

func hasRampartInMatcher(matcher map[string]any) bool {
	hooks, ok := matcher["hooks"].([]any)
	if !ok {
		return false
	}
	for _, h := range hooks {
		if m, ok := h.(map[string]any); ok {
			if cmd, ok := m["command"].(string); ok {
				if cmd == "rampart hook" {
					return true
				}
			}
		}
	}
	return false
}
