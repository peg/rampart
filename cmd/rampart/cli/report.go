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
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/peg/rampart/internal/build"
	"github.com/peg/rampart/internal/report"
	"github.com/spf13/cobra"
)

type reportOptions struct {
	auditDir string
	output   string
	last     string
}

type complianceReportOptions struct {
	auditDir string
	since    string
	until    string
	format   string
	output   string
}

// newReportCmd creates the `rampart report` command.
func newReportCmd(opts *rootOptions) *cobra.Command {
	reportOpts := &reportOptions{}

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate reports from audit logs",
		Long: `Generate reports from Rampart audit logs.

By default this command generates a self-contained HTML report.
Use 'rampart report compliance' to generate a security posture report.

Examples:
  rampart report                                    # HTML report for last 24h
  rampart report --last 7d                         # HTML report for last 7 days
  rampart report --output weekly.html --last 7d    # Custom HTML output path
  rampart report compliance                        # Security posture text report
  rampart report compliance --format json          # Security posture JSON report`,
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

	cmd.AddCommand(newReportComplianceCmd(opts, defaultAuditDir))
	cmd.AddCommand(newReportExportCmd(defaultAuditDir))
	return cmd
}

func newReportExportCmd(defaultAuditDir string) *cobra.Command {
	var auditDir, output, last string

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export audit summary for sharing",
		Long: `Export an audit summary as JSON for sharing with the Rampart team.

The export includes rule hit counts, sample commands, and tool usage
breakdown. Review the output before sharing — it contains your actual
commands and file paths.

Examples:
  rampart report export                        # Last 7 days, auto-named file
  rampart report export --last 30d             # Last 30 days
  rampart report export --output my-export.json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			exportReport, outPath, err := report.GenerateExport(report.ExportOptions{
				AuditDir: auditDir,
				Last:     last,
				Output:   output,
			})
			if err != nil {
				return err
			}

			report.PrintExportSummary(exportReport)

			absPath, _ := filepath.Abs(outPath)
			fmt.Printf("📁 Saved to: %s\n", absPath)
			fmt.Println("→ Review the file, then share via GitHub issue or paste.")
			return nil
		},
	}

	cmd.Flags().StringVar(&auditDir, "audit-dir", defaultAuditDir, "Directory containing audit JSONL files")
	cmd.Flags().StringVar(&output, "output", "", "Output file path (default: rampart-export-YYYY-MM-DD.json)")
	cmd.Flags().StringVar(&last, "last", "7d", "Time window (e.g., 24h, 7d, 30d)")
	return cmd
}

func newReportComplianceCmd(rootOpts *rootOptions, defaultAuditDir string) *cobra.Command {
	complianceOpts := &complianceReportOptions{}

	cmd := &cobra.Command{
		Use:   "compliance",
		Short: "Generate security posture report",
		Long: `Generate a security posture report from audit logs.

This report evaluates how well your Rampart deployment enforces key
agent security controls. It can be shared with security teams as
supporting evidence for compliance efforts.

Controls evaluated:
  RC-1 Tool Call Authorization  — All tool calls evaluated against policy
  RC-2 Audit Logging            — Tamper-evident audit chain maintained
  RC-3 Human-in-the-Loop        — Sensitive ops require human approval
  RC-4 Data Exfiltration Prev.  — Credential/sensitive path access blocked

Note: a fresh installation with no audit history will show FAIL.
Run Rampart with an agent to generate audit logs, then re-run this report.

Examples:
  rampart report compliance
  rampart report compliance --since 2026-02-01 --until 2026-02-28
  rampart report compliance --format json --output posture-report.json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runComplianceReport(cmd, rootOpts, complianceOpts)
		},
	}

	cmd.Flags().StringVar(&complianceOpts.auditDir, "audit-dir", defaultAuditDir, "Directory containing audit JSONL files")
	cmd.Flags().StringVar(&complianceOpts.since, "since", "", "Reporting period start date (YYYY-MM-DD, default: 30 days ago)")
	cmd.Flags().StringVar(&complianceOpts.until, "until", "", "Reporting period end date (YYYY-MM-DD, default: now)")
	cmd.Flags().StringVar(&complianceOpts.format, "format", "text", "Output format: text or json")
	cmd.Flags().StringVar(&complianceOpts.output, "output", "", "Write report to file instead of stdout")

	return cmd
}

func runComplianceReport(cmd *cobra.Command, rootOpts *rootOptions, opts *complianceReportOptions) error {
	format := strings.ToLower(strings.TrimSpace(opts.format))
	if format != "text" && format != "json" {
		return fmt.Errorf("report: invalid --format %q (expected text or json)", opts.format)
	}

	now := time.Now().UTC()
	since, err := parseReportDateStart(opts.since)
	if err != nil {
		return err
	}
	if since.IsZero() {
		since = now.AddDate(0, 0, -30)
	}

	until, err := parseReportDateEnd(opts.until)
	if err != nil {
		return err
	}
	if until.IsZero() {
		until = now
	}
	if since.After(until) {
		return fmt.Errorf("report: --since must be before --until")
	}

	policyPath := resolveCompliancePolicyPath(cmd, rootOpts.configPath)

	reportData, err := report.GeneratePostureReport(report.ComplianceOptions{
		AuditDir:       opts.auditDir,
		PolicyPath:     policyPath,
		Since:          since,
		Until:          until,
		GeneratedAt:    now,
		RampartVersion: build.Version,
	})
	if err != nil {
		return err
	}

	var payload []byte
	if format == "json" {
		payload, err = json.MarshalIndent(reportData, "", "  ")
		if err != nil {
			return fmt.Errorf("report: marshal json: %w", err)
		}
		payload = append(payload, '\n')
	} else {
		payload = []byte(report.FormatPostureTextReport(reportData))
	}

	if strings.TrimSpace(opts.output) != "" {
		if err := os.WriteFile(opts.output, payload, 0o644); err != nil {
			return fmt.Errorf("report: write output file: %w", err)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Wrote compliance report to %s\n", opts.output)
		return nil
	}

	if _, err := cmd.OutOrStdout().Write(payload); err != nil {
		return fmt.Errorf("report: write output: %w", err)
	}
	return nil
}

func resolveCompliancePolicyPath(cmd *cobra.Command, configPath string) string {
	resolved, err := resolveExplainPolicyPath(cmd, configPath)
	if err == nil {
		return resolved
	}
	if strings.TrimSpace(configPath) != "" {
		return configPath
	}
	return "rampart.yaml"
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

func parseReportDateStart(raw string) (time.Time, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse("2006-01-02", trimmed)
	if err != nil {
		return time.Time{}, fmt.Errorf("report: invalid --since date %q (expected YYYY-MM-DD)", raw)
	}
	return parsed.UTC(), nil
}

func parseReportDateEnd(raw string) (time.Time, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse("2006-01-02", trimmed)
	if err != nil {
		return time.Time{}, fmt.Errorf("report: invalid --until date %q (expected YYYY-MM-DD)", raw)
	}
	parsed = parsed.UTC()
	return parsed.Add(24*time.Hour - time.Nanosecond), nil
}
