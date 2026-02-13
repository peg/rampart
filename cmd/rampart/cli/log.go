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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/peg/rampart/internal/audit"
	"github.com/spf13/cobra"
)

func newLogCmd(_ *rootOptions) *cobra.Command {
	var (
		count    int
		denyOnly bool
		today    bool
		jsonOut  bool
		auditDir string
		noColorF bool
	)

	cmd := &cobra.Command{
		Use:   "log",
		Short: "Pretty-print recent audit events",
		Long: `Display recent audit events from the Rampart audit trail.

Unlike "rampart watch", this prints events and exits — no TUI required.

Examples:
  rampart log              # Last 20 events
  rampart log -n 50        # Last 50 events
  rampart log --deny       # Only deny events
  rampart log --today      # Today's events only
  rampart log --json       # Raw JSON output (for piping)`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			resolvedDir, err := expandHome(auditDir)
			if err != nil {
				return err
			}
			resolvedDir = filepath.Clean(resolvedDir)

			disableColor := noColorF || noColor()

			events, err := loadLogEvents(resolvedDir, today)
			if err != nil {
				return err
			}

			// Filter deny-only
			if denyOnly {
				filtered := make([]audit.Event, 0, len(events))
				for _, e := range events {
					if strings.EqualFold(e.Decision.Action, "deny") {
						filtered = append(filtered, e)
					}
				}
				events = filtered
			}

			// Tail to last N
			if count > 0 && len(events) > count {
				events = events[len(events)-count:]
			}

			if len(events) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No events found.")
				return nil
			}

			out := cmd.OutOrStdout()
			if jsonOut {
				return writeJSONEvents(out, events)
			}
			return writePrettyEvents(out, events, disableColor)
		},
	}

	cmd.Flags().IntVarP(&count, "number", "n", 20, "Number of events to display")
	cmd.Flags().BoolVar(&denyOnly, "deny", false, "Show only deny events")
	cmd.Flags().BoolVar(&today, "today", false, "Show only today's events")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output raw JSON lines")
	cmd.Flags().StringVar(&auditDir, "audit-dir", "~/.rampart/audit", "Directory containing audit JSONL files")
	cmd.Flags().BoolVar(&noColorF, "no-color", false, "Disable colored output")

	return cmd
}

// loadLogEvents reads events from audit files. If today is true, only
// reads files matching today's date pattern.
func loadLogEvents(auditDir string, todayOnly bool) ([]audit.Event, error) {
	if todayOnly {
		todayStr := time.Now().UTC().Format("2006-01-02")
		matches, err := filepath.Glob(filepath.Join(auditDir, "*"+todayStr+"*.jsonl"))
		if err != nil {
			return nil, fmt.Errorf("log: glob today's files: %w", err)
		}
		if len(matches) == 0 {
			return nil, nil
		}
		var events []audit.Event
		for _, f := range matches {
			fe, err := readAuditEvents(f)
			if err != nil {
				return nil, err
			}
			events = append(events, fe...)
		}
		return events, nil
	}

	// Default: read latest file only
	latest, err := findLatestAuditFile(auditDir)
	if err != nil {
		if os.IsNotExist(err) || strings.Contains(err.Error(), "no .jsonl files") {
			return nil, nil
		}
		return nil, err
	}
	return readAuditEvents(latest)
}

func writeJSONEvents(w io.Writer, events []audit.Event) error {
	enc := json.NewEncoder(w)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			return fmt.Errorf("log: encode event: %w", err)
		}
	}
	return nil
}

func writePrettyEvents(w io.Writer, events []audit.Event, disableColor bool) error {
	for _, e := range events {
		line := formatLogLine(e, disableColor)
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

// formatLogLine produces a single pretty-printed line for a log event.
func formatLogLine(e audit.Event, disableColor bool) string {
	ts := e.Timestamp.Format("15:04:05")
	tool := e.Tool
	detail := extractPrimaryRequestValue(e.Request)
	decision := strings.ToLower(e.Decision.Action)

	policy := "(no match)"
	if len(e.Decision.MatchedPolicies) > 0 {
		policy = e.Decision.MatchedPolicies[0]
	}

	// Truncate detail
	if len(detail) > 45 {
		detail = detail[:42] + "..."
	}

	var icon, decLabel string
	switch decision {
	case "allow":
		icon = "✅"
		decLabel = "allow"
	case "deny":
		icon = "🛡️"
		decLabel = "deny"
	case "log":
		icon = "📝"
		decLabel = "log"
	default:
		icon = "•"
		decLabel = decision
	}

	line := fmt.Sprintf("%s  %s %-5s  %-6s %-45s %s", ts, icon, decLabel, tool, detail, policy)

	if disableColor {
		return line
	}

	switch decision {
	case "allow":
		return "\033[32m" + line + "\033[0m"
	case "deny":
		return "\033[1;31m" + line + "\033[0m"
	case "log":
		return "\033[33m" + line + "\033[0m"
	}
	return line
}
