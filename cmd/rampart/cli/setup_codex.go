// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package cli

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

func newSetupCodexCmd(_ *rootOptions) *cobra.Command {
	var remove bool
	var force bool

	cmd := &cobra.Command{
		Use:   "codex",
		Short: "Install Rampart wrapper for Codex CLI",
		Long: `Creates a wrapper script that intercepts all Codex tool calls via
rampart preload (LD_PRELOAD syscall interception). The wrapper is installed
at ~/.local/bin/codex and the real codex binary is called through it.

Run 'rampart setup codex --remove' to uninstall.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if runtime.GOOS == "windows" {
				return fmt.Errorf("setup codex: LD_PRELOAD not supported on Windows — use 'rampart wrap -- codex' instead")
			}

			out := cmd.OutOrStdout()

			// Find the real codex binary.
			realCodex, err := exec.LookPath("codex")
			if err != nil {
				return fmt.Errorf("setup codex: codex not found in PATH — install it first")
			}

			// Resolve symlinks so the wrapper doesn't point to itself.
			realCodex, err = filepath.EvalSymlinks(realCodex)
			if err != nil {
				return fmt.Errorf("setup codex: resolve codex path: %w", err)
			}

			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("setup codex: resolve home: %w", err)
			}

			wrapperDir := filepath.Join(home, ".local", "bin")
			wrapperPath := filepath.Join(wrapperDir, "codex")

			if remove {
				return removeCodexWrapper(out, wrapperPath)
			}

			// Safety: don't overwrite if it's already pointing somewhere else.
			if _, err := os.Stat(wrapperPath); err == nil && !force {
				data, readErr := os.ReadFile(wrapperPath)
				if readErr == nil && !containsRampartPreload(string(data)) {
					return fmt.Errorf("setup codex: %s already exists and is not a Rampart wrapper\n  use --force to overwrite or --remove to uninstall", wrapperPath)
				}
			}

			if err := os.MkdirAll(wrapperDir, 0o755); err != nil {
				return fmt.Errorf("setup codex: create %s: %w", wrapperDir, err)
			}

			// Find rampart binary path for the wrapper.
			rampartPath, err := exec.LookPath("rampart")
			if err != nil {
				rampartPath = "rampart" // fallback to PATH lookup at runtime
			}

			wrapper := fmt.Sprintf(`#!/bin/sh
# Rampart wrapper for Codex — managed by 'rampart setup codex'
# Intercepts all tool calls via LD_PRELOAD syscall enforcement.
# Real codex: %s
# Remove: rampart setup codex --remove
exec %s preload -- %s "$@"
`, realCodex, rampartPath, realCodex)

			// Atomic write.
			tmp, err := os.CreateTemp(wrapperDir, ".rampart-codex-wrapper-*.sh")
			if err != nil {
				return fmt.Errorf("setup codex: create temp file: %w", err)
			}
			tmpPath := tmp.Name()
			if _, err := tmp.WriteString(wrapper); err != nil {
				tmp.Close()
				os.Remove(tmpPath)
				return fmt.Errorf("setup codex: write wrapper: %w", err)
			}
			if err := tmp.Chmod(0o755); err != nil {
				tmp.Close()
				os.Remove(tmpPath)
				return fmt.Errorf("setup codex: chmod wrapper: %w", err)
			}
			tmp.Close()
			if err := os.Rename(tmpPath, wrapperPath); err != nil {
				os.Remove(tmpPath)
				return fmt.Errorf("setup codex: install wrapper: %w", err)
			}

			fmt.Fprintf(out, "✓ Wrapper installed at %s\n", wrapperPath)
			fmt.Fprintf(out, "  Wraps: %s\n", realCodex)
			fmt.Fprintf(out, "  Via:   %s preload\n\n", rampartPath)

			// Check if wrapperDir is on PATH and warn if not.
			if !isOnPath(wrapperDir) {
				fmt.Fprintf(out, "⚠ %s is not on your PATH.\n", wrapperDir)
				fmt.Fprintln(out, "  Add this to your shell config (~/.bashrc, ~/.zshrc):")
				fmt.Fprintf(out, "    export PATH=\"%s:$PATH\"\n\n", wrapperDir)
			}

			fmt.Fprintln(out, "✓ Run 'codex' normally — all tool calls are now enforced by Rampart.")
			fmt.Fprintln(out, "  Uninstall: rampart setup codex --remove")
			return nil
		},
	}

	cmd.Flags().BoolVar(&remove, "remove", false, "Remove the Codex wrapper")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing wrapper")
	return cmd
}

func removeCodexWrapper(out io.Writer, wrapperPath string) error {
	data, err := os.ReadFile(wrapperPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(out, "Nothing to remove — %s does not exist.\n", wrapperPath)
			return nil
		}
		return fmt.Errorf("setup codex: read wrapper: %w", err)
	}
	if !containsRampartPreload(string(data)) {
		return fmt.Errorf("setup codex: %s does not appear to be a Rampart wrapper — refusing to remove", wrapperPath)
	}
	// Extract real binary path from the wrapper comment before deleting.
	realBin := extractRealBinFromWrapper(string(data))
	if err := os.Remove(wrapperPath); err != nil {
		return fmt.Errorf("setup codex: remove wrapper: %w", err)
	}
	fmt.Fprintf(out, "✓ Wrapper removed from %s\n", wrapperPath)
	if realBin != "" {
		fmt.Fprintf(out, "  codex now points to: %s\n", realBin)
	}
	return nil
}

// extractRealBinFromWrapper parses "# Real codex: /path" from the wrapper script.
func extractRealBinFromWrapper(content string) string {
	const prefix = "# Real codex: "
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

func containsRampartPreload(content string) bool {
	return strings.Contains(content, "rampart preload") ||
		strings.Contains(content, "Rampart wrapper")
}

func isOnPath(dir string) bool {
	pathEnv := os.Getenv("PATH")
	for _, p := range filepath.SplitList(pathEnv) {
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		if abs == dir {
			return true
		}
	}
	return false
}
