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

// Package watch provides the live terminal dashboard for audit events.
package watch

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/peg/rampart/internal/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestSummary(t *testing.T) {
	evt := audit.Event{Request: map[string]any{"command": "git push"}}
	assert.Equal(t, "git push", requestSummary(evt))

	evt = audit.Event{Request: map[string]any{"path": "/tmp/a.txt"}}
	assert.Equal(t, "/tmp/a.txt", requestSummary(evt))
}

func TestFormatEventLineTruncates(t *testing.T) {
	evt := audit.Event{
		Timestamp: time.Date(2026, 2, 10, 21, 3, 42, 0, time.UTC),
		Tool:      "exec",
		Request:   map[string]any{"command": "rm -rf /tmp/very/long/path/that/keeps/going"},
		Decision: audit.EventDecision{
			Action:          "deny",
			MatchedPolicies: []string{"protect-sys"},
		},
	}
	line := formatEventLine(evt, 40)
	assert.LessOrEqual(t, len([]rune(line)), 40)
	assert.True(t, strings.Contains(line, "🔴"))
}

func TestModelUpdateCountsAndScroll(t *testing.T) {
	m := NewModel(Config{AuditFile: "/tmp/does-not-matter", PolicyName: "standard.yaml", Agent: "all"})
	m.events = []audit.Event{}
	m.scroll = 0

	evt := audit.Event{
		Timestamp: time.Now(),
		Tool:      "exec",
		Request:   map[string]any{"command": "git push"},
		Decision:  audit.EventDecision{Action: "allow"},
	}

	updatedModel, _ := m.Update(tailerMsg{event: evt})
	updated, ok := updatedModel.(*Model)
	require.True(t, ok)
	assert.Equal(t, 1, updated.stats.Total)
	assert.Equal(t, 1, updated.stats.Allow)
	assert.Len(t, updated.events, 1)

	updatedModel, _ = updated.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	updated, ok = updatedModel.(*Model)
	require.True(t, ok)
	assert.GreaterOrEqual(t, updated.scroll, 0)
}

func TestVisibleEventsRespectsScroll(t *testing.T) {
	m := NewModel(Config{AuditFile: "/tmp/audit.jsonl"})
	for i := 0; i < 6; i++ {
		m.events = append(m.events, audit.Event{Tool: "exec", Request: map[string]any{"command": "cmd"}})
	}
	m.scroll = 2
	visible := m.visibleEvents(2)
	require.Len(t, visible, 2)
}
