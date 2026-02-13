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
	"time"
)


func TestRunDoctor(t *testing.T) {
	var buf bytes.Buffer
	err := runDoctor(&buf)
	if err != nil {
		t.Fatalf("runDoctor returned error: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "🩺 Rampart Doctor") {
		t.Error("missing header")
	}
	if !strings.Contains(out, "✓ Version:") {
		t.Error("missing version check")
	}
	if !strings.Contains(out, "System:") {
		t.Error("missing system info")
	}
}

func TestRelHome(t *testing.T) {
	got := relHome("/home/user/.rampart/audit", "/home/user")
	if got != ".rampart/audit" {
		t.Errorf("relHome = %q, want .rampart/audit", got)
	}
}

func TestFormatAgo(t *testing.T) {
	tests := []struct {
		input    string
		contains string
	}{
		{"30s", "30s ago"},
		{"5m", "5m ago"},
		{"3h", "3h ago"},
	}
	for _, tt := range tests {
		d, _ := time.ParseDuration(tt.input)
		got := formatAgo(d)
		if got != tt.contains {
			t.Errorf("formatAgo(%s) = %q, want %q", tt.input, got, tt.contains)
		}
	}
}

func TestCountClaudeHookMatchers(t *testing.T) {
	settings := map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{
				map[string]any{
					"matcher": "Bash",
					"hooks": []any{
						map[string]any{"type": "command", "command": "rampart hook"},
					},
				},
			},
		},
	}
	count := countClaudeHookMatchers(settings)
	if count == 0 {
		t.Error("expected non-zero count for rampart hooks")
	}
}
