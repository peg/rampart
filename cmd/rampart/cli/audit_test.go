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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peg/rampart/internal/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestAuditFile writes a JSONL file with properly hash-chained events.
func createTestAuditFile(t *testing.T, dir string, events []audit.Event) string {
	t.Helper()

	prevHash := ""
	for i := range events {
		if events[i].ID == "" {
			events[i].ID = audit.NewEventID()
		}
		if events[i].Timestamp.IsZero() {
			events[i].Timestamp = time.Now().UTC().Add(time.Duration(i) * time.Second)
		}
		events[i].PrevHash = prevHash
		require.NoError(t, events[i].ComputeHash())
		prevHash = events[i].Hash
	}

	filename := "audit-2026-02-09T22-00-00.jsonl"
	path := filepath.Join(dir, filename)

	var lines []string
	for _, e := range events {
		data, err := json.Marshal(e)
		require.NoError(t, err)
		lines = append(lines, string(data))
	}

	require.NoError(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644))
	return path
}

func makeEvent(tool, command, agent, decision, message string) audit.Event {
	params := map[string]any{}
	if command != "" {
		params["command"] = command
	}
	return audit.Event{
		Tool:    tool,
		Agent:   agent,
		Session: "test-session",
		Request: params,
		Decision: audit.EventDecision{
			Action:          decision,
			MatchedPolicies: []string{"test-policy"},
			Message:         message,
		},
	}
}

func TestAuditTail_PrintsEvents(t *testing.T) {
	dir := t.TempDir()
	events := []audit.Event{
		makeEvent("exec", "git push", "main", "allow", "allowed"),
		makeEvent("exec", "rm -rf /", "main", "deny", "blocked"),
		makeEvent("read", "/etc/passwd", "main", "allow", "allowed"),
		makeEvent("exec", "sudo reboot", "ops", "log", "flagged"),
		makeEvent("exec", "npm test", "main", "allow", "allowed"),
	}
	createTestAuditFile(t, dir, events)

	stdout, _, err := runCLI(t, "audit", "tail", "--audit-dir", dir, "--no-color")
	require.NoError(t, err)

	assert.Contains(t, stdout, "git push")
	assert.Contains(t, stdout, "rm -rf /")
	assert.Contains(t, stdout, "/etc/passwd")
	assert.Contains(t, stdout, "sudo reboot")
	assert.Contains(t, stdout, "npm test")
}

func TestAuditVerify_ValidChain(t *testing.T) {
	dir := t.TempDir()
	events := make([]audit.Event, 10)
	for i := range events {
		events[i] = makeEvent("exec", "cmd-"+string(rune('a'+i)), "main", "allow", "ok")
	}
	createTestAuditFile(t, dir, events)

	stdout, _, err := runCLI(t, "audit", "verify", "--audit-dir", dir)
	require.NoError(t, err)
	assert.Contains(t, stdout, "no tampering detected")
	assert.Contains(t, stdout, "10 events")
}

func TestAuditVerify_BrokenChain(t *testing.T) {
	dir := t.TempDir()
	events := make([]audit.Event, 5)
	for i := range events {
		events[i] = makeEvent("exec", "cmd", "main", "allow", "ok")
	}

	// Build proper chain first
	prevHash := ""
	for i := range events {
		events[i].ID = audit.NewEventID()
		events[i].Timestamp = time.Now().UTC().Add(time.Duration(i) * time.Second)
		events[i].PrevHash = prevHash
		require.NoError(t, events[i].ComputeHash())
		prevHash = events[i].Hash
	}

	// Corrupt event #3's hash
	events[2].Hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	filename := "audit-2026-02-09T22-00-00.jsonl"
	path := filepath.Join(dir, filename)
	var lines []string
	for _, e := range events {
		data, err := json.Marshal(e)
		require.NoError(t, err)
		lines = append(lines, string(data))
	}
	require.NoError(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644))

	_, _, err := runCLI(t, "audit", "verify", "--audit-dir", dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CHAIN BROKEN")
}

func TestAuditStats_Counts(t *testing.T) {
	dir := t.TempDir()
	events := []audit.Event{
		makeEvent("exec", "git push", "main", "allow", "ok"),
		makeEvent("exec", "git pull", "main", "allow", "ok"),
		makeEvent("exec", "rm -rf /", "main", "deny", "blocked"),
		makeEvent("read", "/etc/passwd", "ops", "log", "flagged"),
		makeEvent("exec", "npm test", "main", "allow", "ok"),
	}
	createTestAuditFile(t, dir, events)

	stdout, _, err := runCLI(t, "audit", "stats", "--audit-dir", dir, "--no-color")
	require.NoError(t, err)

	assert.Contains(t, stdout, "Total events:  5")
	assert.Contains(t, stdout, "allow")
	assert.Contains(t, stdout, "deny")
	assert.Contains(t, stdout, "watch")
}

func TestAuditStats_SinceFilter(t *testing.T) {
	dir := t.TempDir()

	now := time.Now().UTC()
	events := []audit.Event{
		makeEvent("exec", "old-cmd", "main", "allow", "ok"),
		makeEvent("exec", "recent-cmd", "main", "deny", "blocked"),
	}
	// First event: 48h ago
	events[0].Timestamp = now.Add(-48 * time.Hour)
	// Second event: 1h ago
	events[1].Timestamp = now.Add(-1 * time.Hour)

	// Build chain manually with explicit timestamps
	prevHash := ""
	for i := range events {
		events[i].ID = audit.NewEventID()
		events[i].PrevHash = prevHash
		require.NoError(t, events[i].ComputeHash())
		prevHash = events[i].Hash
	}

	filename := "audit-2026-02-09T22-00-00.jsonl"
	path := filepath.Join(dir, filename)
	var lines []string
	for _, e := range events {
		data, err := json.Marshal(e)
		require.NoError(t, err)
		lines = append(lines, string(data))
	}
	require.NoError(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644))

	stdout, _, err := runCLI(t, "audit", "stats", "--audit-dir", dir, "--since", "24h", "--no-color")
	require.NoError(t, err)

	assert.Contains(t, stdout, "Total events:  1")
}

func TestAuditSearch_FindsMatch(t *testing.T) {
	dir := t.TempDir()
	events := []audit.Event{
		makeEvent("exec", "kubectl get pods", "main", "allow", "ok"),
		makeEvent("exec", "git push", "main", "allow", "ok"),
		makeEvent("exec", "kubectl delete ns", "ops", "deny", "blocked"),
	}
	createTestAuditFile(t, dir, events)

	stdout, _, err := runCLI(t, "audit", "search", "kubectl", "--audit-dir", dir, "--no-color")
	require.NoError(t, err)

	assert.Contains(t, stdout, "kubectl get pods")
	assert.Contains(t, stdout, "kubectl delete ns")
	assert.Contains(t, stdout, "Found 2 matching events")
}

func TestAuditSearch_NoMatch(t *testing.T) {
	dir := t.TempDir()
	events := []audit.Event{
		makeEvent("exec", "git push", "main", "allow", "ok"),
	}
	createTestAuditFile(t, dir, events)

	stdout, _, err := runCLI(t, "audit", "search", "nonexistent", "--audit-dir", dir, "--no-color")
	require.NoError(t, err)
	assert.Contains(t, stdout, "Found 0 matching events")
}

func TestAuditReplay_PrintsAll(t *testing.T) {
	dir := t.TempDir()
	events := []audit.Event{
		makeEvent("exec", "cmd-1", "main", "allow", "ok"),
		makeEvent("exec", "cmd-2", "main", "deny", "blocked"),
		makeEvent("exec", "cmd-3", "main", "log", "flagged"),
	}
	createTestAuditFile(t, dir, events)

	stdout, _, err := runCLI(t, "audit", "replay", "--audit-dir", dir, "--speed", "0", "--no-color")
	require.NoError(t, err)

	assert.Contains(t, stdout, "[1/3]")
	assert.Contains(t, stdout, "[2/3]")
	assert.Contains(t, stdout, "[3/3]")
	assert.Contains(t, stdout, "cmd-1")
	assert.Contains(t, stdout, "cmd-2")
	assert.Contains(t, stdout, "cmd-3")
}
