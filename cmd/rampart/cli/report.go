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
	"strings"
	"time"

	"github.com/peg/rampart/internal/report"
	"github.com/spf13/cobra"
)

type reportOptions struct {
	auditDir string
	output   string
	last     string
}

// newReportCmd creates the `rampart report` command.
func newReportCmd(opts *rootOptions) *cobra.Command {
	reportOpts := &reportOptions{}

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate HTML audit report",
		Long: `Generate a self-contained HTML audit report from JSONL audit files.

The report includes event summaries, timelines, top denied commands, policy 
triggers, and a searchable event log. The HTML is completely self-contained
with inline CSS and JavaScript.

Examples:
  rampart report                                    # Last 24 hours
  rampart report --last 7d                         # Last 7 days  
  rampart report --output weekly.html --last 7d    # Custom output
  rampart report --audit-dir /var/log/rampart      # Custom audit dir`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReport(reportOpts)
		},
	}

	// Set default audit directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	defaultAuditDir := filepath.Join(homeDir, ".rampart", "audit")

	cmd.Flags().StringVar(&reportOpts.auditDir, "audit-dir", defaultAuditDir, "Directory containing audit JSONL files")
	cmd.Flags().StringVar(&reportOpts.output, "output", "report.html", "Output HTML file path")
	cmd.Flags().StringVar(&reportOpts.last, "last", "24h", "Time window (e.g., 24h, 7d, 30d)")

	return cmd
}

// runReport executes the report generation.
func runReport(opts *reportOptions) error {
	// Parse duration
	duration, err := parseDuration(opts.last)
	if err != nil {
		return fmt.Errorf("invalid duration '%s': %w", opts.last, err)
	}

	// Read audit events from directory
	fmt.Printf("Reading audit events from %s...\n", opts.auditDir)
	events, err := report.ReadEventsFromDir(opts.auditDir)
	if err != nil {
		return fmt.Errorf("read audit events: %w", err)
	}

	if len(events) == 0 {
		return fmt.Errorf("no audit events found in %s", opts.auditDir)
	}

	fmt.Printf("Found %d total events\n", len(events))

	// Filter by time window
	filteredEvents := report.FilterEventsByTime(events, duration)
	fmt.Printf("Filtered to %d events within %s\n", len(filteredEvents), opts.last)

	if len(filteredEvents) == 0 {
		return fmt.Errorf("no events found within the last %s", opts.last)
	}

	// Determine time range
	endTime := time.Now()
	startTime := endTime.Add(-duration)

	// Create output file
	outputFile, err := os.Create(opts.output)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer outputFile.Close()

	// Generate HTML report
	fmt.Printf("Generating HTML report...\n")
	if err := report.GenerateHTMLReport(filteredEvents, startTime, endTime, outputFile); err != nil {
		return fmt.Errorf("generate HTML report: %w", err)
	}

	// Get absolute path for display
	absPath, _ := filepath.Abs(opts.output)
	fmt.Printf("✅ Report generated: %s\n", absPath)

	return nil
}

// parseDuration parses durations with support for days (d) suffix.
func parseDuration(s string) (time.Duration, error) {
	// Handle custom "d" suffix for days
	if strings.HasSuffix(s, "d") {
		daysStr := strings.TrimSuffix(s, "d")
		duration, err := time.ParseDuration(daysStr + "h")
		if err != nil {
			return 0, err
		}
		return duration * 24, nil
	}

	// Use standard Go duration parsing for other formats
	return time.ParseDuration(s)
}