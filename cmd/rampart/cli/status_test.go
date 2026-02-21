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
	"strings"
	"testing"

	"github.com/peg/rampart/internal/audit"
)

func TestRunStatus(t *testing.T) {
	var buf bytes.Buffer
	err := runStatus(&buf)
	if err != nil {
		t.Fatalf("runStatus returned error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "🛡️ Rampart Status") {
		t.Error("missing status header")
	}
}

func TestExtractEventCommand(t *testing.T) {
	ev := &audit.Event{
		Tool:    "exec",
		Request: map[string]any{"command": "ls -la"},
	}
	got := extractEventCommand(ev)
	if got != "ls -la" {
		t.Errorf("extractEventCommand = %q, want %q", got, "ls -la")
	}
}

func TestExtractEventCommandTruncation(t *testing.T) {
	long := strings.Repeat("x", 100)
	ev := &audit.Event{
		Tool:    "exec",
		Request: map[string]any{"command": long},
	}
	got := extractEventCommand(ev)
	if len(got) > 61 {
		t.Errorf("expected truncation, got len=%d", len(got))
	}
}

func TestExtractEventCommandFallback(t *testing.T) {
	ev := &audit.Event{
		Tool:    "read",
		Request: map[string]any{"path": "/etc/passwd"},
	}
	got := extractEventCommand(ev)
	if got != "read" {
		t.Errorf("expected tool name fallback, got %q", got)
	}
}

func TestIsUnknownOrEmpty(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"", true},
		{"unknown", true},
		{"UNKNOWN", true},
		{"(unknown)", true},
		{"exec ls", false},
	}
	for _, tt := range tests {
		if got := isUnknownOrEmpty(tt.input); got != tt.want {
			t.Errorf("isUnknownOrEmpty(%q)=%v want %v", tt.input, got, tt.want)
		}
	}
}
