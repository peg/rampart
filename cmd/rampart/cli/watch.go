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

// Package cli contains rampart command-line subcommands.
package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/peg/rampart/internal/watch"
	"github.com/spf13/cobra"
)

func newWatchCmd(_ *rootOptions) *cobra.Command {
	var auditFile string
	var policyName string
	var mode string
	var agent string
	var decision string
	var tool string

	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Live TUI dashboard for audit decisions",
		RunE: func(cmd *cobra.Command, _ []string) error {
			resolvedDir, err := expandHome(auditFile)
			if err != nil {
				return err
			}
			resolvedDir = filepath.Clean(resolvedDir)

			if err := os.MkdirAll(resolvedDir, 0o700); err != nil {
				return fmt.Errorf("watch: create audit dir: %w", err)
			}

			latestFile, err := latestAuditFile(resolvedDir)
			if err != nil {
				return fmt.Errorf("watch: find audit file: %w", err)
			}

			return watch.Run(cmd.Context(), watch.Config{
				AuditFile:  latestFile,
				PolicyName: policyName,
				Mode:       mode,
				Agent:      agent,
				Decision:   decision,
				Tool:       tool,
				Out:        cmd.OutOrStdout(),
			})
		},
	}

	cmd.Flags().StringVar(&auditFile, "audit-dir", "~/.rampart/audit", "Directory containing audit JSONL files")
	cmd.Flags().StringVar(&policyName, "policy", "standard.yaml", "Policy file name to display in status")
	cmd.Flags().StringVar(&mode, "mode", "enforce", "Display mode label")
	cmd.Flags().StringVar(&agent, "agent", "all", "Filter to a single agent in view")
	cmd.Flags().StringVar(&decision, "decision", "", "Filter by decision (allow, deny, log, webhook)")
	cmd.Flags().StringVar(&tool, "tool", "", "Filter by tool name (e.g., exec, read, write)")

	return cmd
}

// latestAuditFile returns the most recently modified *.jsonl file in dir.
// Falls back to a predicted daily filename if no files exist yet.
func latestAuditFile(dir string) (string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil {
		return "", err
	}
	if len(matches) == 0 {
		today := time.Now().UTC().Format("2006-01-02")
		return filepath.Join(dir, "audit-hook-"+today+".jsonl"), nil
	}
	// Pick the most recently modified file.
	var latest string
	var latestMod time.Time
	for _, m := range matches {
		info, err := os.Stat(m)
		if err != nil {
			continue
		}
		if info.ModTime().After(latestMod) {
			latestMod = info.ModTime()
			latest = m
		}
	}
	if latest == "" {
		sort.Strings(matches)
		latest = matches[len(matches)-1]
	}
	return latest, nil
}

func expandHome(path string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", fmt.Errorf("watch: audit file path is empty")
	}
	if !strings.HasPrefix(trimmed, "~/") && trimmed != "~" {
		return trimmed, nil
	}

	home, err := homeDir()
	if err != nil {
		return "", err
	}
	if trimmed == "~" {
		return home, nil
	}
	return filepath.Join(home, strings.TrimPrefix(trimmed, "~/")), nil
}

func homeDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("watch: resolve home directory: %w", err)
	}
	if strings.TrimSpace(home) == "" {
		return "", fmt.Errorf("watch: home directory is empty")
	}
	return home, nil
}
