// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/peg/rampart/internal/audit"
)

func TestGenerateExport_Empty(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "export.json")

	_, _, err := GenerateExport(ExportOptions{
		AuditDir: dir,
		Last:     "7d",
		Output:   outPath,
	})
	// Empty audit dir — should succeed with zero events, not error.
	if err != nil {
		t.Fatalf("unexpected error on empty audit dir: %v", err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("output file not created: %v", err)
	}
}

func TestGenerateExport_WithEvents(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "export.json")

	// Write a minimal JSONL audit file.
	now := time.Now().UTC()
	events := []audit.Event{
		{
			ID:        "01HTEST0000000000000000001",
			Timestamp: now,
			Agent:     "agent-1",
			Tool:      "exec",
			Request:   map[string]any{"command": "rm -rf /"},
			Decision: audit.EventDecision{
				Action:          "deny",
				MatchedPolicies: []string{"block-destructive"},
				Message:         "Destructive command blocked",
			},
		},
		{
			ID:        "01HTEST0000000000000000002",
			Timestamp: now,
			Agent:     "agent-1",
			Tool:      "exec",
			Request:   map[string]any{"command": "npm test"},
			Decision: audit.EventDecision{
				Action:          "allow",
				MatchedPolicies: []string{"allow-dev-tools"},
			},
		},
		{
			ID:        "01HTEST0000000000000000003",
			Timestamp: now,
			Agent:     "agent-2",
			Tool:      "read",
			Request:   map[string]any{"path": "~/.ssh/id_rsa"},
			Decision: audit.EventDecision{
				Action:          "ask",
				MatchedPolicies: []string{"require-ssh-key-approval"},
			},
		},
	}

	// Write events as JSONL.
	auditFile := filepath.Join(dir, now.Format("2006-01-02")+".jsonl")
	f, err := os.Create(auditFile)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(f)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()

	report, path, err := GenerateExport(ExportOptions{
		AuditDir: dir,
		Last:     "7d",
		Output:   outPath,
	})
	if err != nil {
		t.Fatalf("GenerateExport: %v", err)
	}
	if path != outPath {
		t.Errorf("path = %q, want %q", path, outPath)
	}

	// Verify totals.
	if report.Totals.Deny != 1 {
		t.Errorf("Deny = %d, want 1", report.Totals.Deny)
	}
	if report.Totals.Allow != 1 {
		t.Errorf("Allow = %d, want 1", report.Totals.Allow)
	}
	if report.Totals.Ask != 1 {
		t.Errorf("Ask = %d, want 1", report.Totals.Ask)
	}
	if report.Totals.Total != 3 {
		t.Errorf("Total = %d, want 3", report.Totals.Total)
	}
	if report.AgentCount != 2 {
		t.Errorf("AgentCount = %d, want 2", report.AgentCount)
	}

	// Verify denied rules captured.
	if len(report.DeniedRules) != 1 {
		t.Errorf("DeniedRules count = %d, want 1", len(report.DeniedRules))
	} else {
		if report.DeniedRules[0].Name != "block-destructive" {
			t.Errorf("DeniedRules[0].Name = %q, want block-destructive", report.DeniedRules[0].Name)
		}
		if len(report.DeniedRules[0].Samples) == 0 {
			t.Error("DeniedRules[0].Samples is empty")
		}
	}

	// Verify tool breakdown.
	if report.ToolBreakdown["exec"] != 2 {
		t.Errorf("ToolBreakdown[exec] = %d, want 2", report.ToolBreakdown["exec"])
	}
	if report.ToolBreakdown["read"] != 1 {
		t.Errorf("ToolBreakdown[read] = %d, want 1", report.ToolBreakdown["read"])
	}

	// Verify file is valid JSON.
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	var parsed ExportReport
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// File should be 0600 (Unix only — Windows doesn't enforce Unix perms).
	if runtime.GOOS != "windows" {
		info, err := os.Stat(outPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("file mode = %o, want 0600", info.Mode().Perm())
		}
	}
}

func TestGenerateExport_InvalidDuration(t *testing.T) {
	_, _, err := GenerateExport(ExportOptions{
		AuditDir: t.TempDir(),
		Last:     "notaduration",
	})
	if err == nil {
		t.Error("expected error for invalid duration, got nil")
	}
}

func TestPrintExportSummary_NoError(t *testing.T) {
	// Smoke test — just verify it doesn't panic on empty report.
	report := &ExportReport{}
	report.Period.Days = 7
	PrintExportSummary(report) // should not panic
}
