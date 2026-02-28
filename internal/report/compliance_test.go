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

package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peg/rampart/internal/audit"
)

func TestGenerateAIUC1Report_Compliant(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC)

	events := makeEvents(t, now,
		"allow",
		"ask",
		"deny",
	)
	writeAuditFile(t, dir, "audit-20260228.jsonl", events)

	policyPath := filepath.Join(dir, "policy.yaml")
	policy := `version: "1"
policies:
  - name: sensitive-deny
    rules:
      - action: deny
        when:
          path_matches: ["**/etc/shadow", "**/.ssh/**", "**/.env", "**/credentials/**"]
`
	if err := os.WriteFile(policyPath, []byte(policy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	rep, err := GenerateAIUC1Report(ComplianceOptions{
		AuditDir:       dir,
		PolicyPath:     policyPath,
		Since:          now.Add(-24 * time.Hour),
		Until:          now,
		GeneratedAt:    now,
		RampartVersion: "v1.2.3",
	})
	if err != nil {
		t.Fatalf("GenerateAIUC1Report returned error: %v", err)
	}

	if rep.Standard != "AIUC-1" {
		t.Fatalf("standard = %q, want AIUC-1", rep.Standard)
	}
	if rep.Summary.ComplianceStatus != ComplianceStatusCompliant {
		t.Fatalf("status = %s, want %s", rep.Summary.ComplianceStatus, ComplianceStatusCompliant)
	}
	if rep.Summary.DecisionCounts.Total != 3 || rep.Summary.DecisionCounts.Ask != 1 {
		t.Fatalf("unexpected decision counts: %+v", rep.Summary.DecisionCounts)
	}
	if rep.Controls["AIUC-1.1"].Status != ControlStatusPass {
		t.Fatalf("AIUC-1.1 status = %s, want PASS", rep.Controls["AIUC-1.1"].Status)
	}
	if rep.Controls["AIUC-1.2"].Status != ControlStatusPass {
		t.Fatalf("AIUC-1.2 status = %s, want PASS", rep.Controls["AIUC-1.2"].Status)
	}
	if rep.Controls["AIUC-1.3"].Status != ControlStatusPass {
		t.Fatalf("AIUC-1.3 status = %s, want PASS", rep.Controls["AIUC-1.3"].Status)
	}
	if rep.Controls["AIUC-1.4"].Status != ControlStatusPass {
		t.Fatalf("AIUC-1.4 status = %s, want PASS", rep.Controls["AIUC-1.4"].Status)
	}
}

func TestGenerateAIUC1Report_NoAuditLogsNonCompliant(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC)

	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("version: \"1\"\n"), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	rep, err := GenerateAIUC1Report(ComplianceOptions{
		AuditDir:    filepath.Join(dir, "missing"),
		PolicyPath:  policyPath,
		Since:       now.Add(-24 * time.Hour),
		Until:       now,
		GeneratedAt: now,
	})
	if err != nil {
		t.Fatalf("GenerateAIUC1Report returned error: %v", err)
	}

	if rep.Controls["AIUC-1.1"].Status != ControlStatusFail {
		t.Fatalf("AIUC-1.1 status = %s, want FAIL", rep.Controls["AIUC-1.1"].Status)
	}
	if rep.Controls["AIUC-1.2"].Status != ControlStatusFail {
		t.Fatalf("AIUC-1.2 status = %s, want FAIL", rep.Controls["AIUC-1.2"].Status)
	}
	if rep.Summary.ComplianceStatus != ComplianceStatusNonCompliant {
		t.Fatalf("status = %s, want %s", rep.Summary.ComplianceStatus, ComplianceStatusNonCompliant)
	}
}

func TestGenerateAIUC1Report_ZeroEventsWarnsClearly(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC)

	emptyLog := filepath.Join(dir, "audit-20260228.jsonl")
	if err := os.WriteFile(emptyLog, nil, 0o644); err != nil {
		t.Fatalf("write empty log: %v", err)
	}

	policyPath := filepath.Join(dir, "policy.yaml")
	policy := `version: "1"
policies:
  - name: sensitive-deny
    rules:
      - action: deny
        when:
          path_matches: ["**/etc/shadow", "**/.ssh/**", "**/.env", "**/credentials/**"]
`
	if err := os.WriteFile(policyPath, []byte(policy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	rep, err := GenerateAIUC1Report(ComplianceOptions{
		AuditDir:    dir,
		PolicyPath:  policyPath,
		Since:       now.Add(-24 * time.Hour),
		Until:       now,
		GeneratedAt: now,
	})
	if err != nil {
		t.Fatalf("GenerateAIUC1Report returned error: %v", err)
	}

	if rep.Summary.DecisionCounts.Total != 0 {
		t.Fatalf("total decisions = %d, want 0", rep.Summary.DecisionCounts.Total)
	}
	if rep.Controls["AIUC-1.1"].Status != ControlStatusWarn {
		t.Fatalf("AIUC-1.1 status = %s, want WARN", rep.Controls["AIUC-1.1"].Status)
	}
	if rep.Controls["AIUC-1.2"].Status != ControlStatusPass {
		t.Fatalf("AIUC-1.2 status = %s, want PASS", rep.Controls["AIUC-1.2"].Status)
	}
	if rep.Controls["AIUC-1.3"].Status != ControlStatusWarn {
		t.Fatalf("AIUC-1.3 status = %s, want WARN", rep.Controls["AIUC-1.3"].Status)
	}
	if rep.Summary.ComplianceStatus != ComplianceStatusPartial {
		t.Fatalf("status = %s, want %s", rep.Summary.ComplianceStatus, ComplianceStatusPartial)
	}
	if !strings.Contains(strings.Join(rep.Controls["AIUC-1.1"].Evidence, " | "), "no events") {
		t.Fatalf("expected AIUC-1.1 evidence to explain no events: %v", rep.Controls["AIUC-1.1"].Evidence)
	}
}

func TestGenerateAIUC1Report_PartialForMissingAskAndPolicyCoverage(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC)

	events := makeEvents(t, now, "allow", "deny")
	writeAuditFile(t, dir, "audit-20260228.jsonl", events)

	policyPath := filepath.Join(dir, "policy.yaml")
	policy := `version: "1"
policies:
  - name: not-sensitive
    rules:
      - action: deny
        when:
          cmd_matches: ["rm -rf /"]
`
	if err := os.WriteFile(policyPath, []byte(policy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	rep, err := GenerateAIUC1Report(ComplianceOptions{
		AuditDir:    dir,
		PolicyPath:  policyPath,
		Since:       now.Add(-24 * time.Hour),
		Until:       now,
		GeneratedAt: now,
	})
	if err != nil {
		t.Fatalf("GenerateAIUC1Report returned error: %v", err)
	}

	if rep.Summary.ComplianceStatus != ComplianceStatusPartial {
		t.Fatalf("status = %s, want %s", rep.Summary.ComplianceStatus, ComplianceStatusPartial)
	}
	if rep.Controls["AIUC-1.3"].Status != ControlStatusWarn {
		t.Fatalf("AIUC-1.3 status = %s, want WARN", rep.Controls["AIUC-1.3"].Status)
	}
	if rep.Controls["AIUC-1.4"].Status != ControlStatusWarn {
		t.Fatalf("AIUC-1.4 status = %s, want WARN", rep.Controls["AIUC-1.4"].Status)
	}
}

func TestGenerateAIUC1Report_FailsOnTamperedChain(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC)

	events := makeEvents(t, now, "allow", "deny")
	events[1].PrevHash = "sha256:tampered"
	writeAuditFile(t, dir, "audit-20260228.jsonl", events)

	policyPath := filepath.Join(dir, "policy.yaml")
	policy := `version: "1"
policies:
  - name: sensitive-deny
    rules:
      - action: deny
        when:
          path_matches: ["**/etc/shadow", "**/.ssh/**", "**/.env", "**/credentials/**"]
`
	if err := os.WriteFile(policyPath, []byte(policy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	rep, err := GenerateAIUC1Report(ComplianceOptions{
		AuditDir:    dir,
		PolicyPath:  policyPath,
		Since:       now.Add(-24 * time.Hour),
		Until:       now,
		GeneratedAt: now,
	})
	if err != nil {
		t.Fatalf("GenerateAIUC1Report returned error: %v", err)
	}

	if rep.Controls["AIUC-1.2"].Status != ControlStatusFail {
		t.Fatalf("AIUC-1.2 status = %s, want FAIL", rep.Controls["AIUC-1.2"].Status)
	}
	if rep.Summary.ComplianceStatus != ComplianceStatusNonCompliant {
		t.Fatalf("status = %s, want %s", rep.Summary.ComplianceStatus, ComplianceStatusNonCompliant)
	}
}

func makeEvents(t *testing.T, now time.Time, actions ...string) []audit.Event {
	t.Helper()
	events := make([]audit.Event, 0, len(actions))
	prevHash := ""

	for i, action := range actions {
		e := audit.Event{
			ID:        fmt.Sprintf("evt-%04d", i+1),
			Timestamp: now.Add(time.Duration(-len(actions)+i) * time.Minute),
			Agent:     "codex",
			Session:   "session-1",
			Tool:      "exec",
			Request:   map[string]any{"command": "echo test"},
			Decision: audit.EventDecision{
				Action: action,
			},
			PrevHash: prevHash,
		}
		if err := e.ComputeHash(); err != nil {
			t.Fatalf("compute hash: %v", err)
		}
		prevHash = e.Hash
		events = append(events, e)
	}

	return events
}

func writeAuditFile(t *testing.T, dir, name string, events []audit.Event) {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create audit file: %v", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, event := range events {
		if err := enc.Encode(event); err != nil {
			t.Fatalf("encode event: %v", err)
		}
	}
}
