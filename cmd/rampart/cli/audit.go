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
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/peg/rampart/internal/audit"
	"github.com/spf13/cobra"
)

const tailPollInterval = 200 * time.Millisecond

func newAuditCmd(_ *rootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit trail inspection commands",
	}

	cmd.AddCommand(newAuditTailCmd())
	cmd.AddCommand(newAuditVerifyCmd())
	cmd.AddCommand(newAuditStatsCmd())
	cmd.AddCommand(newAuditSearchCmd())
	cmd.AddCommand(newAuditReplayCmd())

	return cmd
}

func newAuditTailCmd() *cobra.Command {
	var auditDir string
	var lines int
	var follow bool
	var noColor bool

	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Show recent audit events",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if lines <= 0 {
				return fmt.Errorf("audit: --lines must be > 0")
			}

			file, err := findLatestAuditFile(auditDir)
			if err != nil {
				return err
			}

			events, err := readAuditEvents(file)
			if err != nil {
				return err
			}

			start := max(0, len(events)-lines)
			for _, event := range events[start:] {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), renderAuditEventLine(event, noColor)); err != nil {
					return fmt.Errorf("audit: write tail output: %w", err)
				}
			}

			if !follow {
				return nil
			}

			return followAuditFile(cmd, auditDir, file, noColor)
		},
	}

	cmd.Flags().StringVar(&auditDir, "audit-dir", "~/.rampart/audit", "Directory containing audit JSONL files")
	cmd.Flags().IntVar(&lines, "lines", 20, "Number of events to print")
	cmd.Flags().BoolVar(&follow, "follow", false, "Follow new events")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Disable color output")

	return cmd
}

func followAuditFile(cmd *cobra.Command, auditDir, startFile string, noColor bool) error {
	currentFile := startFile
	offset, err := fileSize(currentFile)
	if err != nil {
		return err
	}

	ticker := time.NewTicker(tailPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-cmd.Context().Done():
			return nil
		case <-ticker.C:
			latest, latestErr := findLatestAuditFile(auditDir)
			if latestErr == nil && latest != currentFile {
				currentFile = latest
				offset = 0
			}

			events, newOffset, readErr := readAuditEventsFromOffset(currentFile, offset)
			if readErr != nil {
				if os.IsNotExist(readErr) {
					continue
				}
				return readErr
			}

			for _, event := range events {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), renderAuditEventLine(event, noColor)); err != nil {
					return fmt.Errorf("audit: write tail follow output: %w", err)
				}
			}
			offset = newOffset
		}
	}
}

func newAuditVerifyCmd() *cobra.Command {
	var auditDir string

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify audit hash-chain integrity",
		RunE: func(cmd *cobra.Command, _ []string) error {
			files, err := listAuditFiles(auditDir)
			if err != nil {
				return err
			}
			if len(files) == 0 {
				return fmt.Errorf("audit: no .jsonl files found in %s", auditDir)
			}

			count, hashesByID, err := verifyAuditChain(files)
			if err != nil {
				return err
			}

			if err := verifyAnchors(auditDir, hashesByID); err != nil {
				return err
			}

			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "✓ Chain verified: %d events across %d files, no tampering detected\n", count, len(files)); err != nil {
				return fmt.Errorf("audit: write verify output: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&auditDir, "audit-dir", "~/.rampart/audit", "Directory containing audit JSONL files")
	return cmd
}

func verifyAuditChain(files []string) (int, map[string]string, error) {
	prevHash := ""
	eventCount := 0
	hashesByID := map[string]string{}

	for _, file := range files {
		scanErr := scanAuditEvents(file, func(event audit.Event) error {
			eventCount++
			if eventCount == 1 && event.PrevHash != "" {
				return fmt.Errorf("audit: CHAIN BROKEN at event %s in file %s: first event has non-empty prev_hash", event.ID, filepath.Base(file))
			}
			if eventCount > 1 && event.PrevHash != prevHash {
				return fmt.Errorf("audit: CHAIN BROKEN at event %s in file %s: prev_hash mismatch", event.ID, filepath.Base(file))
			}

			ok, err := event.VerifyHash()
			if err != nil {
				return fmt.Errorf("audit: verify hash for event %s in file %s: %w", event.ID, filepath.Base(file), err)
			}
			if !ok {
				return fmt.Errorf("audit: CHAIN BROKEN at event %s in file %s: hash verification failed", event.ID, filepath.Base(file))
			}

			prevHash = event.Hash
			hashesByID[event.ID] = event.Hash
			return nil
		})
		if scanErr != nil {
			return 0, nil, scanErr
		}
	}

	return eventCount, hashesByID, nil
}

func newAuditStatsCmd() *cobra.Command {
	var auditDir string
	var since string
	var noColor bool

	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Show audit summary statistics",
		RunE: func(cmd *cobra.Command, _ []string) error {
			events, err := readAllAuditEvents(auditDir)
			if err != nil {
				return err
			}

			filtered, windowLabel, err := filterEventsBySince(events, since)
			if err != nil {
				return err
			}

			stats := computeAuditStats(filtered)
			output := formatAuditStats(stats, windowLabel, noColor)
			if _, err := fmt.Fprint(cmd.OutOrStdout(), output); err != nil {
				return fmt.Errorf("audit: write stats output: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&auditDir, "audit-dir", "~/.rampart/audit", "Directory containing audit JSONL files")
	cmd.Flags().StringVar(&since, "since", "", "Only include events within this duration (e.g. 24h, 7d, 1h30m)")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Disable color output")
	return cmd
}

func newAuditSearchCmd() *cobra.Command {
	var auditDir string
	var tool string
	var agent string
	var decision string
	var noColor bool

	cmd := &cobra.Command{
		Use:   "search <query>",
		Short: "Search audit events",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			query := strings.ToLower(args[0])
			events, err := readAllAuditEvents(auditDir)
			if err != nil {
				return err
			}

			count := 0
			for _, event := range events {
				if !matchesAuditFilters(event, tool, agent, decision) {
					continue
				}
				if !eventMatchesQuery(event, query) {
					continue
				}
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), renderAuditEventLine(event, noColor)); err != nil {
					return fmt.Errorf("audit: write search output: %w", err)
				}
				count++
			}

			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Found %d matching events\n", count); err != nil {
				return fmt.Errorf("audit: write search count: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&auditDir, "audit-dir", "~/.rampart/audit", "Directory containing audit JSONL files")
	cmd.Flags().StringVar(&tool, "tool", "", "Filter by tool")
	cmd.Flags().StringVar(&agent, "agent", "", "Filter by agent")
	cmd.Flags().StringVar(&decision, "decision", "", "Filter by decision (allow|deny|log)")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Disable color output")
	return cmd
}

func newAuditReplayCmd() *cobra.Command {
	var auditDir string
	var speed float64
	var noColor bool

	cmd := &cobra.Command{
		Use:   "replay",
		Short: "Replay audit events with timing",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if speed < 0 {
				return fmt.Errorf("audit: --speed must be >= 0")
			}

			events, err := readAllAuditEvents(auditDir)
			if err != nil {
				return err
			}

			total := len(events)
			for i, event := range events {
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "[%d/%d] %s\n", i+1, total, renderAuditEventLine(event, noColor)); err != nil {
					return fmt.Errorf("audit: write replay output: %w", err)
				}

				if i == total-1 || speed == 0 {
					continue
				}

				delta := events[i+1].Timestamp.Sub(event.Timestamp)
				if delta <= 0 {
					continue
				}

				sleepFor := time.Duration(math.Round(float64(delta) / speed))
				if sleepFor > 0 {
					time.Sleep(sleepFor)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&auditDir, "audit-dir", "~/.rampart/audit", "Directory containing audit JSONL files")
	cmd.Flags().Float64Var(&speed, "speed", 1, "Replay speed multiplier (0 = no delay)")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Disable color output")
	return cmd
}

func listAuditFiles(auditDir string) ([]string, error) {
	entries, err := os.ReadDir(auditDir)
	if err != nil {
		return nil, fmt.Errorf("audit: read audit dir: %w", err)
	}

	files := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		files = append(files, filepath.Join(auditDir, entry.Name()))
	}
	sort.Strings(files)
	return files, nil
}

func findLatestAuditFile(auditDir string) (string, error) {
	files, err := listAuditFiles(auditDir)
	if err != nil {
		return "", err
	}
	if len(files) == 0 {
		return "", fmt.Errorf("audit: no .jsonl files found in %s", auditDir)
	}
	return files[len(files)-1], nil
}
