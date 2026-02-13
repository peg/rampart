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
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peg/rampart/internal/audit"
)

func testEvents() []audit.Event {
	now := time.Date(2026, 2, 13, 14, 30, 0, 0, time.UTC)
	return []audit.Event{
		{
			ID:        "01",
			Timestamp: now,
			Agent:     "test",
			Tool:      "exec",
			Request:   map[string]any{"command": "git status"},
			Decision:  audit.EventDecision{Action: "allow"},
		},
		{
			ID:        "02",
			Timestamp: now.Add(time.Second),
			Agent:     "test",
			Tool:      "exec",
			Request:   map[string]any{"command": "rm -rf /tmp/*"},
			Decision: audit.EventDecision{
				Action:          "deny",
				MatchedPolicies: []string{"block-destructive"},
			},
		},
		{
			ID:        "03",
			Timestamp: now.Add(2 * time.Second),
			Agent:     "test",
			Tool:      "read",
			Request:   map[string]any{"path": "src/main.go"},
			Decision:  audit.EventDecision{Action: "allow"},
		},
	}
}

func TestFormatLogLine_NoColor(t *testing.T) {
	events := testEvents()

	line := formatLogLine(events[0], true)
	if !strings.Contains(line, "14:30:00") {
		t.Errorf("expected timestamp, got: %s", line)
	}
	if !strings.Contains(line, "allow") {
		t.Errorf("expected 'allow', got: %s", line)
	}
	if !strings.Contains(line, "git status") {
		t.Errorf("expected command, got: %s", line)
	}
	if !strings.Contains(line, "(no match)") {
		t.Errorf("expected '(no match)', got: %s", line)
	}

	line2 := formatLogLine(events[1], true)
	if !strings.Contains(line2, "deny") {
		t.Errorf("expected 'deny', got: %s", line2)
	}
	if !strings.Contains(line2, "block-destructive") {
		t.Errorf("expected policy name, got: %s", line2)
	}
}

func TestFormatLogLine_WithColor(t *testing.T) {
	events := testEvents()

	line := formatLogLine(events[0], false)
	if !strings.Contains(line, "\033[32m") {
		t.Errorf("expected green color for allow, got: %s", line)
	}

	line2 := formatLogLine(events[1], false)
	if !strings.Contains(line2, "\033[1;31m") {
		t.Errorf("expected red color for deny, got: %s", line2)
	}
}

func TestFormatLogLine_Truncation(t *testing.T) {
	e := audit.Event{
		Timestamp: time.Now(),
		Tool:      "exec",
		Request:   map[string]any{"command": strings.Repeat("x", 100)},
		Decision:  audit.EventDecision{Action: "allow"},
	}
	line := formatLogLine(e, true)
	if !strings.Contains(line, "...") {
		t.Error("expected truncation with '...'")
	}
}

func TestWritePrettyEvents(t *testing.T) {
	var buf bytes.Buffer
	events := testEvents()
	if err := writePrettyEvents(&buf, events, true); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 lines, got %d", len(lines))
	}
}

func TestWriteJSONEvents(t *testing.T) {
	var buf bytes.Buffer
	events := testEvents()
	if err := writeJSONEvents(&buf, events); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 JSON lines, got %d", len(lines))
	}
	for _, line := range lines {
		var e audit.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Errorf("invalid JSON line: %s", err)
		}
	}
}

func TestLoadLogEvents_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	events, err := loadLogEvents(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events, got %d", len(events))
	}
}

func TestLoadLogEvents_WithFile(t *testing.T) {
	dir := t.TempDir()
	events := testEvents()

	var lines []string
	for _, e := range events {
		b, _ := json.Marshal(e)
		lines = append(lines, string(b))
	}
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "2026-02-13.jsonl"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := loadLogEvents(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 3 {
		t.Errorf("expected 3 events, got %d", len(loaded))
	}
}
