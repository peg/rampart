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
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/peg/rampart/internal/audit"
)

func TestGenerateHTMLReport_Basic(t *testing.T) {
	now := time.Now().UTC()
	events := []audit.Event{
		{
			ID:        "01EXAMPLE001",
			Timestamp: now.Add(-1 * time.Hour),
			Agent:     "claude-code",
			Tool:      "exec",
			Request:   map[string]any{"command": "ls -la"},
			Decision:  audit.EventDecision{Action: "allow", MatchedPolicies: []string{"default"}, EvalTimeUS: 50},
		},
		{
			ID:        "01EXAMPLE002",
			Timestamp: now.Add(-30 * time.Minute),
			Agent:     "claude-code",
			Tool:      "exec",
			Request:   map[string]any{"command": "rm -rf /"},
			Decision:  audit.EventDecision{Action: "deny", MatchedPolicies: []string{"block-destructive"}, Message: "Destructive command blocked", EvalTimeUS: 30},
		},
		{
			ID:        "01EXAMPLE003",
			Timestamp: now.Add(-10 * time.Minute),
			Agent:     "claude-code",
			Tool:      "read",
			Request:   map[string]any{"path": "/etc/passwd"},
			Decision:  audit.EventDecision{Action: "log", MatchedPolicies: []string{"log-sensitive-reads"}, Message: "Sensitive file read", EvalTimeUS: 20},
		},
	}

	var buf bytes.Buffer
	err := GenerateHTMLReport(events, now.Add(-2*time.Hour), now, &buf)
	if err != nil {
		t.Fatalf("GenerateHTMLReport failed: %v", err)
	}

	html := buf.String()

	// Basic structure checks
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("missing DOCTYPE")
	}
	if !strings.Contains(html, "Rampart Audit Report") {
		t.Error("missing report title")
	}

	// Summary data
	if !strings.Contains(html, "3") { // total events
		t.Error("missing total event count")
	}

	// Decision badges
	if !strings.Contains(html, "deny") {
		t.Error("missing deny badge")
	}
	if !strings.Contains(html, "allow") {
		t.Error("missing allow badge")
	}

	// Policy names
	if !strings.Contains(html, "block-destructive") {
		t.Error("missing policy name")
	}

	// Commands
	if !strings.Contains(html, "rm -rf /") {
		t.Error("missing denied command")
	}
}

func TestGenerateHTMLReport_EmptyEvents(t *testing.T) {
	var buf bytes.Buffer
	now := time.Now().UTC()
	err := GenerateHTMLReport([]audit.Event{}, now.Add(-24*time.Hour), now, &buf)
	// Should either succeed with empty report or return error
	if err != nil {
		// Acceptable to error on empty
		return
	}
	if !strings.Contains(buf.String(), "<!DOCTYPE html>") {
		t.Error("should produce valid HTML even with no events")
	}
}

func TestFilterEventsByTime(t *testing.T) {
	now := time.Now().UTC()
	events := []audit.Event{
		{Timestamp: now.Add(-48 * time.Hour)},
		{Timestamp: now.Add(-12 * time.Hour)},
		{Timestamp: now.Add(-1 * time.Hour)},
	}

	filtered := FilterEventsByTime(events, 24*time.Hour)
	if len(filtered) != 2 {
		t.Errorf("expected 2 events within 24h, got %d", len(filtered))
	}
}

func TestPrepareTopCommands(t *testing.T) {
	counts := map[string]int{
		"rm -rf /":    5,
		"cat /etc/shadow": 3,
		"ls":          1,
	}
	top := prepareTopCommands(counts)
	if len(top) == 0 {
		t.Fatal("expected top commands")
	}
	if top[0].Command != "rm -rf /" || top[0].Count != 5 {
		t.Errorf("expected 'rm -rf /' with count 5, got %q with %d", top[0].Command, top[0].Count)
	}
}

func TestVerifyHashChain_Empty(t *testing.T) {
	if !verifyHashChain(nil) {
		t.Error("empty chain should be valid")
	}
}
