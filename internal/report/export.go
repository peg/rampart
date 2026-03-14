// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package report

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/build"
)

// ExportOptions configures the export report.
type ExportOptions struct {
	AuditDir string
	Last     string // duration like "7d", "24h", "30d"
	Output   string // output file path (empty = auto-generated)
}

// ExportReport is the JSON structure written to the export file.
type ExportReport struct {
	Version   string    `json:"version"`
	Generated time.Time `json:"generated"`
	Period    struct {
		Since time.Time `json:"since"`
		Until time.Time `json:"until"`
		Days  int       `json:"days"`
	} `json:"period"`
	Platform struct {
		OS   string `json:"os"`
		Arch string `json:"arch"`
	} `json:"platform"`
	PolicyProfile string         `json:"policy_profile,omitempty"`
	PolicyCount   int            `json:"policy_count"`
	Totals        ExportTotals   `json:"totals"`
	DeniedRules   []ExportRule   `json:"denied_rules"`
	AllowedRules  []ExportRule   `json:"allowed_rules,omitempty"`
	ApprovalRules []ExportRule   `json:"approval_rules,omitempty"`
	ToolBreakdown map[string]int `json:"tool_breakdown"`
	AgentCount    int            `json:"agent_count"`
}

// ExportTotals summarizes action counts.
type ExportTotals struct {
	Allow      int `json:"allow"`
	Deny       int `json:"deny"`
	Ask        int `json:"ask"`
	AutoAllow  int `json:"auto_allowed"`
	Total      int `json:"total"`
}

// ExportRule is a rule with its hit count and sample commands.
type ExportRule struct {
	Name     string   `json:"name"`
	Count    int      `json:"count"`
	Samples  []string `json:"samples"` // up to 5 example commands
}

// GenerateExport reads audit logs and produces an export report.
func GenerateExport(opts ExportOptions) (*ExportReport, string, error) {
	auditDir, err := expandHomePath(opts.AuditDir)
	if err != nil {
		return nil, "", fmt.Errorf("resolve audit dir: %w", err)
	}
	if strings.TrimSpace(auditDir) == "" {
		auditDir = "."
	}

	dur, err := parseExportDuration(opts.Last)
	if err != nil {
		return nil, "", fmt.Errorf("parse --last: %w", err)
	}

	until := time.Now().UTC()
	since := until.Add(-dur)

	auditFiles, err := listAuditJSONLFiles(auditDir)
	if err != nil {
		return nil, "", fmt.Errorf("list audit files: %w", err)
	}

	// Read all events in the time window.
	var events []audit.Event
	for _, f := range auditFiles {
		fileEvents, _, readErr := audit.ReadEventsFromOffset(f, 0)
		if readErr != nil {
			continue
		}
		for _, e := range fileEvents {
			if !e.Timestamp.Before(since) && !e.Timestamp.After(until) {
				events = append(events, e)
			}
		}
	}

	report := &ExportReport{
		Version:   build.Version,
		Generated: until,
	}
	report.Period.Since = since
	report.Period.Until = until
	report.Period.Days = int(dur.Hours() / 24)
	if report.Period.Days == 0 {
		report.Period.Days = 1
	}
	report.Platform.OS = runtime.GOOS
	report.Platform.Arch = runtime.GOARCH

	// Aggregate.
	denied := map[string]*ruleAgg{}
	allowed := map[string]*ruleAgg{}
	approval := map[string]*ruleAgg{}
	tools := map[string]int{}
	agents := map[string]bool{}

	for _, e := range events {
		action := strings.ToLower(e.Decision.Action)
		cmd := extractCommand(e)
		tools[e.Tool]++

		if e.Agent != "" {
			agents[e.Agent] = true
		}

		switch action {
		case "deny":
			report.Totals.Deny++
			for _, p := range e.Decision.MatchedPolicies {
				agg, ok := denied[p]
				if !ok {
					agg = &ruleAgg{}
					denied[p] = agg
				}
				agg.count++
				if len(agg.samples) < 5 {
					agg.samples = append(agg.samples, cmd)
				}
			}
		case "allow":
			report.Totals.Allow++
			for _, p := range e.Decision.MatchedPolicies {
				agg, ok := allowed[p]
				if !ok {
					agg = &ruleAgg{}
					allowed[p] = agg
				}
				agg.count++
				if len(agg.samples) < 3 {
					agg.samples = append(agg.samples, cmd)
				}
			}
		case "ask", "require_approval":
			report.Totals.Ask++
			for _, p := range e.Decision.MatchedPolicies {
				agg, ok := approval[p]
				if !ok {
					agg = &ruleAgg{}
					approval[p] = agg
				}
				agg.count++
				if len(agg.samples) < 5 {
					agg.samples = append(agg.samples, cmd)
				}
			}
		case "auto_allow":
			report.Totals.AutoAllow++
		default:
			report.Totals.Allow++
		}
	}

	report.Totals.Total = len(events)
	report.ToolBreakdown = tools
	report.AgentCount = len(agents)

	report.DeniedRules = aggToSorted(denied)
	report.AllowedRules = aggToSorted(allowed)
	report.ApprovalRules = aggToSorted(approval)

	// Determine output path.
	outPath := opts.Output
	if outPath == "" {
		outPath = fmt.Sprintf("rampart-export-%s.json", until.Format("2006-01-02"))
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("marshal export: %w", err)
	}

	if err := os.WriteFile(outPath, data, 0o600); err != nil {
		return nil, "", fmt.Errorf("write export file: %w", err)
	}

	return report, outPath, nil
}

// PrintExportSummary prints a human-readable summary to stdout.
func PrintExportSummary(report *ExportReport) {
	fmt.Println()
	fmt.Printf("📋 Export Summary (%dd window)\n", report.Period.Days)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	if len(report.DeniedRules) > 0 {
		fmt.Printf("%d denied events across %d rules:\n", report.Totals.Deny, len(report.DeniedRules))
		for _, r := range report.DeniedRules {
			fmt.Printf("  %-35s %3d\n", r.Name, r.Count)
		}
		fmt.Println()
	}

	if len(report.ApprovalRules) > 0 {
		fmt.Printf("%d approval-gated:\n", report.Totals.Ask)
		for _, r := range report.ApprovalRules {
			fmt.Printf("  %-35s %3d\n", r.Name, r.Count)
		}
		fmt.Println()
	}

	fmt.Printf("%d allowed  |  %d auto-allowed  |  %d total events\n",
		report.Totals.Allow, report.Totals.AutoAllow, report.Totals.Total)
	fmt.Println()

	fmt.Println("⚠️  This export contains your actual commands and file paths.")
	fmt.Println("   Review the file before sharing.")
	fmt.Println()
}

type ruleAgg struct {
	count   int
	samples []string
}

func extractCommand(e audit.Event) string {
	if cmd, ok := e.Request["command"]; ok {
		if s, ok := cmd.(string); ok {
			return s
		}
	}
	if path, ok := e.Request["path"]; ok {
		if s, ok := path.(string); ok {
			return s
		}
	}
	// Fallback: first string value in request.
	for _, v := range e.Request {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return "(unknown)"
}

// parseExportDuration parses durations with support for days (d) suffix.
func parseExportDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		daysStr := strings.TrimSuffix(s, "d")
		h, err := time.ParseDuration(daysStr + "h")
		if err != nil {
			return 0, err
		}
		return h * 24, nil
	}
	return time.ParseDuration(s)
}

func aggToSorted(m map[string]*ruleAgg) []ExportRule {
	rules := make([]ExportRule, 0, len(m))
	for name, agg := range m {
		rules = append(rules, ExportRule{
			Name:    name,
			Count:   agg.count,
			Samples: agg.samples,
		})
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Count > rules[j].Count
	})
	return rules
}


