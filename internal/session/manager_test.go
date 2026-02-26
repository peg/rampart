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

package session

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// newTestManager returns a Manager and a temp directory for use in tests.
func newTestManager(t *testing.T, sessionID string) (*Manager, string) {
	t.Helper()
	dir := t.TempDir()
	m := NewManager(dir, sessionID, slog.Default())
	return m, dir
}

// readState is a helper that reads and parses the state file for a session.
func readState(t *testing.T, dir, sessionID string) *State {
	t.Helper()
	path := filepath.Join(dir, sessionID+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("readState: %v", err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("readState unmarshal: %v", err)
	}
	return &s
}

// ---------------------------------------------------------------------------
// NewManager
// ---------------------------------------------------------------------------

func TestNewManager_NilLogger(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, "sess1", nil)
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
	if m.logger == nil {
		t.Fatal("expected non-nil logger (default slog)")
	}
}

func TestNewManager_DefaultDir(t *testing.T) {
	// Manager with empty dir should resolve to ~/.rampart/session-state on first I/O.
	// We can verify the field is empty and that resolveDir fills it.
	m := NewManager("", "sess1", slog.Default())
	if m.dir != "" {
		t.Fatalf("expected empty dir field, got %q", m.dir)
	}
}

// ---------------------------------------------------------------------------
// RecordAsk
// ---------------------------------------------------------------------------

func TestRecordAsk_CreatesFile(t *testing.T) {
	m, dir := newTestManager(t, "sess-record-1")

	err := m.RecordAsk("toolu_01", "exec", "sudo apt install git",
		"sudo apt install *", "require-sudo", "sudo requires approval")
	if err != nil {
		t.Fatalf("RecordAsk: %v", err)
	}

	s := readState(t, dir, "sess-record-1")

	if s.SessionID != "sess-record-1" {
		t.Errorf("SessionID = %q, want %q", s.SessionID, "sess-record-1")
	}
	if s.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
	if s.LastActive.IsZero() {
		t.Error("LastActive should not be zero")
	}

	ask, ok := s.PendingAsks["toolu_01"]
	if !ok {
		t.Fatal("PendingAsks[toolu_01] not found")
	}
	if ask.Tool != "exec" {
		t.Errorf("Tool = %q, want exec", ask.Tool)
	}
	if ask.Command != "sudo apt install git" {
		t.Errorf("Command = %q", ask.Command)
	}
	if ask.GeneralizedPattern != "sudo apt install *" {
		t.Errorf("GeneralizedPattern = %q", ask.GeneralizedPattern)
	}
	if ask.PolicyName != "require-sudo" {
		t.Errorf("PolicyName = %q", ask.PolicyName)
	}
	if ask.DecisionMessage != "sudo requires approval" {
		t.Errorf("DecisionMessage = %q", ask.DecisionMessage)
	}
	if ask.AskedAt.IsZero() {
		t.Error("AskedAt should not be zero")
	}
}

func TestRecordAsk_MultipleAsks(t *testing.T) {
	m, dir := newTestManager(t, "sess-record-2")

	for i := range 3 {
		id := fmt.Sprintf("toolu_%02d", i)
		cmd := fmt.Sprintf("sudo apt install pkg%d", i)
		if err := m.RecordAsk(id, "exec", cmd, "sudo apt install *", "", ""); err != nil {
			t.Fatalf("RecordAsk %d: %v", i, err)
		}
	}

	s := readState(t, dir, "sess-record-2")
	if len(s.PendingAsks) != 3 {
		t.Errorf("len(PendingAsks) = %d, want 3", len(s.PendingAsks))
	}
}

func TestRecordAsk_NoSessionID(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, "", slog.Default())
	err := m.RecordAsk("toolu_01", "exec", "ls", "ls", "", "")
	if err == nil {
		t.Fatal("expected error for empty sessionID")
	}
}

func TestRecordAsk_OmitsEmptyCommand(t *testing.T) {
	// Command with omitempty — empty string should not appear in JSON.
	m, dir := newTestManager(t, "sess-record-3")
	if err := m.RecordAsk("toolu_01", "read", "", "/home/**", "", ""); err != nil {
		t.Fatalf("RecordAsk: %v", err)
	}

	path := filepath.Join(dir, "sess-record-3.json")
	data, _ := os.ReadFile(path)
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	asks, _ := raw["pending_asks"].(map[string]any)
	ask, _ := asks["toolu_01"].(map[string]any)
	if _, hasCommand := ask["command"]; hasCommand {
		t.Error("expected 'command' field to be omitted when empty")
	}
}

// ---------------------------------------------------------------------------
// ObserveApproval
// ---------------------------------------------------------------------------

func TestObserveApproval_MovesToApprovals(t *testing.T) {
	m, dir := newTestManager(t, "sess-approve-1")

	if err := m.RecordAsk("toolu_01", "exec", "sudo apt install git",
		"sudo apt install *", "policy-x", "msg"); err != nil {
		t.Fatalf("RecordAsk: %v", err)
	}

	record, err := m.ObserveApproval("toolu_01")
	if err != nil {
		t.Fatalf("ObserveApproval: %v", err)
	}

	if record.ApprovalCount != 1 {
		t.Errorf("ApprovalCount = %d, want 1", record.ApprovalCount)
	}
	if record.Pattern != "sudo apt install *" {
		t.Errorf("Pattern = %q", record.Pattern)
	}
	if record.Tool != "exec" {
		t.Errorf("Tool = %q", record.Tool)
	}
	if record.FirstApproved.IsZero() {
		t.Error("FirstApproved should not be zero")
	}
	if record.LastApproved.IsZero() {
		t.Error("LastApproved should not be zero")
	}

	s := readState(t, dir, "sess-approve-1")

	// Must not be in pending_asks anymore.
	if _, ok := s.PendingAsks["toolu_01"]; ok {
		t.Error("toolu_01 should have been removed from pending_asks")
	}

	// Must be in session_approvals.
	key := "exec:sudo apt install *"
	rec, ok := s.SessionApprovals[key]
	if !ok {
		t.Fatalf("session_approvals[%q] not found", key)
	}
	if rec.ApprovalCount != 1 {
		t.Errorf("ApprovalCount = %d, want 1", rec.ApprovalCount)
	}
}

func TestObserveApproval_IncrementsCount(t *testing.T) {
	m, _ := newTestManager(t, "sess-approve-2")

	// Record and approve the same pattern three times with different tool_use_ids.
	for i := range 3 {
		id := fmt.Sprintf("toolu_%02d", i)
		if err := m.RecordAsk(id, "exec", "sudo apt install curl",
			"sudo apt install *", "", ""); err != nil {
			t.Fatalf("RecordAsk %d: %v", i, err)
		}
		record, err := m.ObserveApproval(id)
		if err != nil {
			t.Fatalf("ObserveApproval %d: %v", i, err)
		}
		wantCount := i + 1
		if record.ApprovalCount != wantCount {
			t.Errorf("iter %d: ApprovalCount = %d, want %d", i, record.ApprovalCount, wantCount)
		}
	}
}

func TestObserveApproval_FirstVsLastApproved(t *testing.T) {
	m, dir := newTestManager(t, "sess-approve-3")

	// First approval.
	if err := m.RecordAsk("toolu_01", "exec", "npm install", "npm install *", "", ""); err != nil {
		t.Fatalf("RecordAsk 1: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, err := m.ObserveApproval("toolu_01"); err != nil {
		t.Fatalf("ObserveApproval 1: %v", err)
	}

	s1 := readState(t, dir, "sess-approve-3")
	key := "exec:npm install *"
	first := s1.SessionApprovals[key].FirstApproved

	// Second approval — FirstApproved should stay the same, LastApproved advances.
	time.Sleep(2 * time.Millisecond)
	if err := m.RecordAsk("toolu_02", "exec", "npm install lodash", "npm install *", "", ""); err != nil {
		t.Fatalf("RecordAsk 2: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, err := m.ObserveApproval("toolu_02"); err != nil {
		t.Fatalf("ObserveApproval 2: %v", err)
	}

	s2 := readState(t, dir, "sess-approve-3")
	rec := s2.SessionApprovals[key]

	if !rec.FirstApproved.Equal(first) {
		t.Errorf("FirstApproved changed: was %v, now %v", first, rec.FirstApproved)
	}
	if !rec.LastApproved.After(first) {
		t.Errorf("LastApproved should be after FirstApproved: last=%v first=%v",
			rec.LastApproved, first)
	}
	if rec.ApprovalCount != 2 {
		t.Errorf("ApprovalCount = %d, want 2", rec.ApprovalCount)
	}
}

func TestObserveApproval_MissingToolUseID(t *testing.T) {
	m, _ := newTestManager(t, "sess-approve-4")
	// No RecordAsk called — should return error.
	_, err := m.ObserveApproval("toolu_nope")
	if err == nil {
		t.Fatal("expected error for unknown tool_use_id")
	}
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

func TestCleanup_RemovesOldFiles(t *testing.T) {
	dir := t.TempDir()

	// Write a "stale" session file with last_active in the past.
	staleState := State{
		SessionID:        "stale-sess",
		CreatedAt:        time.Now().UTC().Add(-48 * time.Hour),
		LastActive:       time.Now().UTC().Add(-48 * time.Hour),
		PendingAsks:      map[string]PendingAsk{},
		SessionApprovals: map[string]ApprovalRecord{},
	}
	writeStateFile(t, dir, "stale-sess", staleState)

	// Write a "fresh" session file.
	freshState := State{
		SessionID:        "fresh-sess",
		CreatedAt:        time.Now().UTC(),
		LastActive:       time.Now().UTC(),
		PendingAsks:      map[string]PendingAsk{},
		SessionApprovals: map[string]ApprovalRecord{},
	}
	writeStateFile(t, dir, "fresh-sess", freshState)

	m := NewManager(dir, "", slog.Default())
	if err := m.Cleanup(24 * time.Hour); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	// Stale file should be gone.
	if _, err := os.Stat(filepath.Join(dir, "stale-sess.json")); !os.IsNotExist(err) {
		t.Error("stale-sess.json should have been removed")
	}

	// Fresh file should remain.
	if _, err := os.Stat(filepath.Join(dir, "fresh-sess.json")); err != nil {
		t.Errorf("fresh-sess.json should still exist: %v", err)
	}
}

func TestCleanup_RemovesUnparseableFiles(t *testing.T) {
	dir := t.TempDir()

	// Write a corrupt JSON file.
	badPath := filepath.Join(dir, "bad-sess.json")
	if err := os.WriteFile(badPath, []byte("{broken json"), 0o600); err != nil {
		t.Fatalf("write bad file: %v", err)
	}

	m := NewManager(dir, "", slog.Default())
	if err := m.Cleanup(24 * time.Hour); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	if _, err := os.Stat(badPath); !os.IsNotExist(err) {
		t.Error("corrupt file should have been removed")
	}
}

func TestCleanup_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, "", slog.Default())
	if err := m.Cleanup(24 * time.Hour); err != nil {
		t.Fatalf("Cleanup on empty dir: %v", err)
	}
}

func TestCleanup_NonExistentDir(t *testing.T) {
	m := NewManager("/tmp/rampart-test-nonexistent-cleanup-dir-xyz", "", slog.Default())
	// Should not return error — directory just doesn't exist yet.
	if err := m.Cleanup(24 * time.Hour); err != nil {
		t.Fatalf("Cleanup on nonexistent dir: %v", err)
	}
}

func TestCleanup_IgnoresNonJSONFiles(t *testing.T) {
	dir := t.TempDir()

	// Non-JSON file should be left alone.
	txtPath := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(txtPath, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write txt: %v", err)
	}

	m := NewManager(dir, "", slog.Default())
	if err := m.Cleanup(1 * time.Second); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	if _, err := os.Stat(txtPath); err != nil {
		t.Errorf("notes.txt should not have been touched: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Concurrent access
// ---------------------------------------------------------------------------

func TestConcurrentRecordAsk(t *testing.T) {
	// Spawn multiple goroutines all writing to the same session file.
	// After all complete, verify that at least N asks are recorded (some
	// may be overwritten in the last-write-wins model, but the file must
	// always be valid JSON and the count must be > 0).
	m, dir := newTestManager(t, "sess-concurrent")

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("toolu_%03d", i)
			_ = m.RecordAsk(id, "exec", fmt.Sprintf("cmd-%d", i),
				"cmd-*", "policy", "msg")
		}(i)
	}
	wg.Wait()

	// File must be valid JSON.
	path := filepath.Join(dir, "sess-concurrent.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("state file is not valid JSON after concurrent writes: %v", err)
	}
	if len(s.PendingAsks) == 0 {
		t.Error("expected at least one pending ask after concurrent writes")
	}
}

func TestConcurrentObserveApproval(t *testing.T) {
	// Record N asks, then concurrently observe all approvals.
	// Each ObserveApproval must either succeed (finding the pending ask)
	// or fail gracefully (if another goroutine already moved it).
	// The file must always parse as valid JSON.
	const n = 10
	m, dir := newTestManager(t, "sess-concurrent-approve")

	for i := range n {
		id := fmt.Sprintf("toolu_%03d", i)
		if err := m.RecordAsk(id, "exec", fmt.Sprintf("cmd-%d", i),
			fmt.Sprintf("cmd-%d-*", i), "policy", "msg"); err != nil {
			t.Fatalf("RecordAsk %d: %v", i, err)
		}
	}

	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("toolu_%03d", i)
			_, _ = m.ObserveApproval(id) // error is acceptable (idempotent race)
		}(i)
	}
	wg.Wait()

	// File must still be valid JSON.
	path := filepath.Join(dir, "sess-concurrent-approve.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("state file is not valid JSON after concurrent approvals: %v", err)
	}
}

// ---------------------------------------------------------------------------
// State JSON round-trip
// ---------------------------------------------------------------------------

func TestStateJSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := State{
		SessionID:  "rt-sess",
		CreatedAt:  now,
		LastActive: now,
		PendingAsks: map[string]PendingAsk{
			"toolu_01": {
				Tool:               "exec",
				Command:            "git push",
				GeneralizedPattern: "git push *",
				AskedAt:            now,
				PolicyName:         "git-policy",
				DecisionMessage:    "git push requires approval",
			},
		},
		SessionApprovals: map[string]ApprovalRecord{
			"exec:npm install *": {
				Pattern:       "npm install *",
				Tool:          "exec",
				FirstApproved: now,
				LastApproved:  now,
				ApprovalCount: 2,
			},
		},
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded State
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.SessionID != orig.SessionID {
		t.Errorf("SessionID mismatch")
	}
	if !decoded.CreatedAt.Equal(orig.CreatedAt) {
		t.Errorf("CreatedAt mismatch")
	}
	if len(decoded.PendingAsks) != 1 {
		t.Errorf("PendingAsks len = %d", len(decoded.PendingAsks))
	}
	if len(decoded.SessionApprovals) != 1 {
		t.Errorf("SessionApprovals len = %d", len(decoded.SessionApprovals))
	}
	rec := decoded.SessionApprovals["exec:npm install *"]
	if rec.ApprovalCount != 2 {
		t.Errorf("ApprovalCount = %d", rec.ApprovalCount)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// writeStateFile marshals s to JSON and writes it to dir/sessionID.json.
func writeStateFile(t *testing.T, dir, sessionID string, s State) {
	t.Helper()
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal state for %s: %v", sessionID, err)
	}
	path := filepath.Join(dir, sessionID+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write state file for %s: %v", sessionID, err)
	}
}
