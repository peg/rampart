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

func TestAuditVerify_MixedServiceChainAndStandaloneHooks(t *testing.T) {
	dir := t.TempDir()
	serviceEvents := []audit.Event{
		makeEvent("exec", "service-a", "main", "allow", "ok"),
		makeEvent("exec", "service-b", "main", "deny", "blocked"),
	}
	createTestAuditFile(t, dir, serviceEvents)

	hookPath := filepath.Join(dir, "audit-hook-2026-07-28.jsonl")
	writeStandaloneAuditEvent(t, hookPath,
		makeEvent("exec", "hook-a", "codex", "allow", "ok"))
	writeStandaloneAuditEvent(t, hookPath,
		makeEvent("write", "hook-b", "claude-code", "deny", "blocked"))

	stdout, _, err := runCLI(t, "audit", "verify", "--audit-dir", dir)
	require.NoError(t, err)
	assert.Contains(t, stdout, "2 chained events")
	assert.Contains(t, stdout, "2 native-hook events")
}

func TestAuditVerify_StandaloneHookDetectsModification(t *testing.T) {
	dir := t.TempDir()
	hookPath := filepath.Join(dir, "audit-hook-2026-07-28.jsonl")
	event := makeEvent("exec", "hook-a", "codex", "allow", "ok")
	writeStandaloneAuditEvent(t, hookPath, event)

	data, err := os.ReadFile(hookPath)
	require.NoError(t, err)
	data = []byte(strings.Replace(string(data), `"action":"allow"`, `"action":"deny"`, 1))
	require.NoError(t, os.WriteFile(hookPath, data, 0o600))

	_, _, err = runCLI(t, "audit", "verify", "--audit-dir", dir)
	require.ErrorContains(t, err, "RECORD MODIFIED")
}

func TestAuditVerifySince_FiltersHookFilenameDate(t *testing.T) {
	dir := t.TempDir()
	writeStandaloneAuditEvent(t,
		filepath.Join(dir, "audit-hook-2026-02-08.jsonl"),
		makeEvent("exec", "old", "codex", "allow", "ok"))
	writeStandaloneAuditEvent(t,
		filepath.Join(dir, "audit-hook-2026-02-09.jsonl"),
		makeEvent("exec", "new", "codex", "allow", "ok"))

	stdout, _, err := runCLI(t, "audit", "verify", "--audit-dir", dir, "--since", "2026-02-09")
	require.NoError(t, err)
	assert.Contains(t, stdout, "1 native-hook events across 1 files")
}

func writeStandaloneAuditEvent(t *testing.T, path string, event audit.Event) {
	t.Helper()
	event.PrevHash = ""
	line, err := audit.MarshalRecord(event)
	require.NoError(t, err)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	require.NoError(t, err)
	_, err = file.Write(append(line, '\n'))
	require.NoError(t, err)
	require.NoError(t, file.Close())
}

func TestAuditVerifySince_AllowsPartialChainAndSkippedAnchor(t *testing.T) {
	dir := t.TempDir()

	first := makeEvent("exec", "old", "main", "allow", "ok")
	first.ID = audit.NewEventID()
	first.Timestamp = time.Date(2026, 2, 8, 12, 0, 0, 0, time.UTC)
	require.NoError(t, first.ComputeHash())

	second := makeEvent("exec", "new", "main", "allow", "ok")
	second.ID = audit.NewEventID()
	second.Timestamp = time.Date(2026, 2, 9, 12, 0, 0, 0, time.UTC)
	second.PrevHash = first.Hash
	require.NoError(t, second.ComputeHash())

	writeSingleAuditEvent := func(name string, event audit.Event) {
		t.Helper()
		data, err := json.Marshal(event)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), append(data, '\n'), 0o644))
	}
	writeSingleAuditEvent("2026-02-08.jsonl", first)
	writeSingleAuditEvent("2026-02-09.jsonl", second)

	anchor := audit.ChainAnchor{
		EventID:    first.ID,
		Hash:       first.Hash,
		EventCount: 1,
		Timestamp:  first.Timestamp,
		File:       "2026-02-08.jsonl",
	}
	anchorData, err := json.Marshal(anchor)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "audit-anchor.json"), anchorData, 0o644))

	stdout, _, err := runCLI(t, "audit", "verify", "--audit-dir", dir, "--since", "2026-02-09")
	require.NoError(t, err)
	assert.Contains(t, stdout, "1 events")
	assert.Contains(t, stdout, "no tampering detected")
}

func TestAuditVerifySince_FailsMissingAnchorInsideWindow(t *testing.T) {
	dir := t.TempDir()

	event := makeEvent("exec", "new", "main", "allow", "ok")
	event.ID = audit.NewEventID()
	event.Timestamp = time.Date(2026, 2, 9, 12, 0, 0, 0, time.UTC)
	require.NoError(t, event.ComputeHash())

	data, err := json.Marshal(event)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "2026-02-09.jsonl"), append(data, '\n'), 0o644))

	anchor := audit.ChainAnchor{
		EventID:    audit.NewEventID(),
		Hash:       event.Hash,
		EventCount: 1,
		Timestamp:  event.Timestamp,
		File:       "2026-02-09.jsonl",
	}
	anchorData, err := json.Marshal(anchor)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "audit-anchor.json"), anchorData, 0o644))

	_, _, err = runCLI(t, "audit", "verify", "--audit-dir", dir, "--since", "2026-02-09")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "anchor event not found")
}

func TestListAuditFiles_SortsRotatedFilesNaturally(t *testing.T) {
	dir := t.TempDir()
	names := []string{"2026-02-13.jsonl", "2026-02-13.p1.jsonl", "2026-02-13.p2.jsonl", "2026-02-13.p10.jsonl"}
	for _, name := range names {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), nil, 0o644))
	}

	files, err := listAuditFiles(dir)
	require.NoError(t, err)
	require.Len(t, files, len(names))

	for i, file := range files {
		assert.Equal(t, names[i], filepath.Base(file))
	}
}

func TestFindLatestAuditFile_PrefersUnifiedChainAfterUpgrade(t *testing.T) {
	dir := t.TempDir()
	managed := filepath.Join(dir, time.Now().UTC().Format("2006-01-02")+".jsonl")
	legacy := filepath.Join(dir, "audit-hook-2099-12-31.jsonl")
	require.NoError(t, os.WriteFile(managed, nil, 0o600))
	require.NoError(t, os.WriteFile(legacy, nil, 0o600))

	latest, err := findLatestAuditFile(dir)
	require.NoError(t, err)
	assert.Equal(t, managed, latest)
}

func TestFindLatestAuditFile_LegacyOnlyFallback(t *testing.T) {
	dir := t.TempDir()
	older := filepath.Join(dir, "audit-hook-2026-07-27.jsonl")
	newer := filepath.Join(dir, "audit-hook-2026-07-28.jsonl")
	require.NoError(t, os.WriteFile(older, nil, 0o600))
	require.NoError(t, os.WriteFile(newer, nil, 0o600))

	latest, err := findLatestAuditFile(dir)
	require.NoError(t, err)
	assert.Equal(t, newer, latest)
}

func TestLatestAuditEvent_PrefersUnifiedChainAfterUpgrade(t *testing.T) {
	dir := t.TempDir()
	managedEvent := makeEvent("exec", "managed-current", "main", "allow", "ok")
	managedEvent.ID = audit.NewEventID()
	managedEvent.Timestamp = time.Now().UTC()
	require.NoError(t, managedEvent.ComputeHash())
	managedLine, err := json.Marshal(managedEvent)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, managedEvent.Timestamp.Format("2006-01-02")+".jsonl"),
		append(managedLine, '\n'),
		0o600,
	))

	legacyEvent := makeEvent("exec", "legacy-stale", "main", "allow", "ok")
	legacyEvent.Timestamp = managedEvent.Timestamp.Add(time.Hour)
	writeStandaloneAuditEvent(t, filepath.Join(dir, "audit-hook-2099-12-31.jsonl"), legacyEvent)

	latest, err := latestAuditEvent(dir)
	require.NoError(t, err)
	assert.Equal(t, "managed-current", latest.Request["command"])
}

func TestAuditVerify_AcceptsLegacyReopenAfterRotationLayout(t *testing.T) {
	dir := t.TempDir()
	date := time.Now().UTC().Format("2006-01-02")
	baseName := date + ".jsonl"
	rotatedName := date + ".p1.jsonl"

	first := makeEvent("exec", "first", "main", "allow", "ok")
	first.ID = audit.NewEventID()
	first.Timestamp = time.Now().UTC()
	require.NoError(t, first.ComputeHash())
	second := makeEvent("read", "second", "main", "allow", "ok")
	second.ID = audit.NewEventID()
	second.Timestamp = first.Timestamp.Add(time.Second)
	second.PrevHash = first.Hash
	require.NoError(t, second.ComputeHash())
	third := makeEvent("write", "third", "main", "allow", "ok")
	third.ID = audit.NewEventID()
	third.Timestamp = second.Timestamp.Add(time.Second)
	third.PrevHash = second.Hash
	require.NoError(t, third.ComputeHash())

	firstLine, err := json.Marshal(first)
	require.NoError(t, err)
	secondLine, err := json.Marshal(second)
	require.NoError(t, err)
	thirdLine, err := json.Marshal(third)
	require.NoError(t, err)
	headerLine, err := json.Marshal(map[string]string{
		"chain_continue": first.Hash,
		"prev_file":      baseName,
	})
	require.NoError(t, err)

	// Older restarts could append the third event back to the daily base file,
	// leaving physical order A,C in the base and B in the rotated file.
	require.NoError(t, os.WriteFile(filepath.Join(dir, baseName),
		[]byte(string(firstLine)+"\n"+string(thirdLine)+"\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, rotatedName),
		[]byte(string(headerLine)+"\n"+string(secondLine)+"\n"), 0o600))

	stdout, _, err := runCLI(t, "audit", "verify", "--audit-dir", dir)
	require.NoError(t, err)
	assert.Contains(t, stdout, "3 events")
	assert.Contains(t, stdout, "no tampering detected")
}

func TestAuditVerify_RejectsTamperedContinuationHeader(t *testing.T) {
	dir := t.TempDir()
	date := time.Now().UTC().Format("2006-01-02")
	baseName := date + ".jsonl"
	rotatedName := date + ".p1.jsonl"

	first := makeEvent("exec", "first", "main", "allow", "ok")
	first.ID = audit.NewEventID()
	first.Timestamp = time.Now().UTC()
	require.NoError(t, first.ComputeHash())
	second := makeEvent("read", "second", "main", "allow", "ok")
	second.ID = audit.NewEventID()
	second.Timestamp = first.Timestamp.Add(time.Second)
	second.PrevHash = first.Hash
	require.NoError(t, second.ComputeHash())

	firstLine, err := json.Marshal(first)
	require.NoError(t, err)
	secondLine, err := json.Marshal(second)
	require.NoError(t, err)
	headerLine, err := json.Marshal(map[string]string{
		"chain_continue": "sha256:tampered",
		"prev_file":      baseName,
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, baseName), append(firstLine, '\n'), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, rotatedName),
		[]byte(string(headerLine)+"\n"+string(secondLine)+"\n"), 0o600))

	_, _, err = runCLI(t, "audit", "verify", "--audit-dir", dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CHAIN BROKEN")
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
