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
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func newSetupClineCmd(opts *rootOptions) *cobra.Command {
	var workspace bool
	var force bool

	cmd := &cobra.Command{
		Use:   "cline",
		Short: "Install Rampart hook into Cline settings",
		Long: `Installs PreToolUse and PostToolUse hooks for Cline (VS Code AI coding agent).

Hooks are installed to:
  - Global: ~/Documents/Cline/Hooks/ (default)  
  - Workspace: .clinerules/hooks/ (with --workspace flag)

The PreToolUse hook evaluates all tool calls through Rampart's policy engine
before execution. The PostToolUse hook logs completed actions for audit.

Compatible with Cline's hook system - no configuration changes needed.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("setup cline: resolve home: %w", err)
			}

			// Determine hook installation directory
			var hookDir string
			var installScope string
			if workspace {
				hookDir = ".clinerules/hooks"
				installScope = "workspace-level"
			} else {
				hookDir = filepath.Join(home, "Documents", "Cline", "Hooks")
				installScope = "global"
			}

			preToolUseDir := filepath.Join(hookDir, "PreToolUse")
			postToolUseDir := filepath.Join(hookDir, "PostToolUse")

			// Create hook directories
			if err := os.MkdirAll(preToolUseDir, 0o755); err != nil {
				return fmt.Errorf("setup cline: create PreToolUse dir: %w", err)
			}
			if err := os.MkdirAll(postToolUseDir, 0o755); err != nil {
				return fmt.Errorf("setup cline: create PostToolUse dir: %w", err)
			}

			// Find rampart binary path
			rampartBin, err := findRampartBinary()
			if err != nil {
				return fmt.Errorf("setup cline: locate rampart binary: %w", err)
			}

			// Create PreToolUse hook script
			preHookPath := filepath.Join(preToolUseDir, "rampart-policy")
			preHookContent := createPreToolUseScript(rampartBin)
			
			if err := installHookScript(preHookPath, preHookContent, force); err != nil {
				return fmt.Errorf("setup cline: install PreToolUse hook: %w", err)
			}

			// Create PostToolUse hook script
			postHookPath := filepath.Join(postToolUseDir, "rampart-audit")
			postHookContent := createPostToolUseScript(rampartBin)
			
			if err := installHookScript(postHookPath, postHookContent, force); err != nil {
				return fmt.Errorf("setup cline: install PostToolUse hook: %w", err)
			}

			// Print success message
			fmt.Fprintf(cmd.OutOrStdout(), "✓ Cline hooks installed (%s)\n", installScope)
			fmt.Fprintf(cmd.OutOrStdout(), "  PreToolUse:  %s\n", preHookPath)
			fmt.Fprintf(cmd.OutOrStdout(), "  PostToolUse: %s\n", postHookPath)
			fmt.Fprintln(cmd.OutOrStdout(), "")
			fmt.Fprintln(cmd.OutOrStdout(), "Cline will now route tool calls through Rampart's policy engine.")
			fmt.Fprintln(cmd.OutOrStdout(), "No additional configuration needed - hooks activate automatically.")

			return nil
		},
	}

	cmd.Flags().BoolVar(&workspace, "workspace", false, "Install hooks at workspace level (.clinerules/hooks/) instead of global")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing hook scripts")
	return cmd
}

// Variables for testing (osExecutable only; execLookPath is declared in setup.go)
var osExecutable = os.Executable

// findRampartBinary locates the rampart executable, preferring the current binary
func findRampartBinary() (string, error) {
	// First try to get the current executable path
	if exe, err := osExecutable(); err == nil {
		return exe, nil
	}
	
	// Fall back to PATH lookup
	if path, err := execLookPath("rampart"); err == nil {
		return path, nil
	}
	
	return "", fmt.Errorf("rampart binary not found in PATH")
}

// createPreToolUseScript generates the PreToolUse hook script content
func createPreToolUseScript(rampartBin string) string {
	return fmt.Sprintf(`#!/usr/bin/env bash
# Rampart PreToolUse hook for Cline
# Evaluates tool calls through policy engine before execution

set -euo pipefail

# Read Cline hook input from stdin and pass to rampart
exec "%s" hook --format cline --config ~/.rampart/policies/standard.yaml
`, rampartBin)
}

// createPostToolUseScript generates the PostToolUse hook script content  
func createPostToolUseScript(rampartBin string) string {
	return fmt.Sprintf(`#!/usr/bin/env bash
# Rampart PostToolUse hook for Cline
# Logs completed tool calls for audit trail

set -euo pipefail

# Read Cline hook input from stdin and log to audit
exec "%s" hook --format cline --mode audit --config ~/.rampart/policies/standard.yaml 2>/dev/null || true
`, rampartBin)
}

// installHookScript writes a hook script to disk with executable permissions
func installHookScript(path, content string, force bool) error {
	// Check if file already exists
	if _, err := os.Stat(path); err == nil && !force {
		return fmt.Errorf("hook script already exists at %s (use --force to overwrite)", path)
	}
	
	// Write script with executable permissions
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		return fmt.Errorf("write hook script: %w", err)
	}
	
	return nil
}