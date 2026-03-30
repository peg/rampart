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

package approval

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/peg/rampart/internal/engine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testCall() engine.ToolCall {
	return engine.ToolCall{
		ID:        "test-1",
		Agent:     "main",
		Tool:      "exec",
		Params:    map[string]any{"command": "sudo reboot"},
		Timestamp: time.Now(),
	}
}

func testDecision() engine.Decision {
	return engine.Decision{
		Action:          engine.ActionRequireApproval,
		MatchedPolicies: []string{"privileged-ops"},
		Message:         "Privileged command requires approval",
	}
}

func TestCreateAndResolveApproval(t *testing.T) {
	store := NewStore()
	req, _ := store.Create(testCall(), testDecision())

	assert.Equal(t, StatusPending, req.Status)
	assert.NotEmpty(t, req.ID)
	assert.False(t, req.ExpiresAt.IsZero())

	// Approve it.
	err := store.Resolve(req.ID, true, "cli", false)
	require.NoError(t, err)

	assert.Equal(t, StatusApproved, req.Status)
	assert.Equal(t, "cli", req.ResolvedBy)

	// Channel should be closed.
	select {
	case <-req.Done():
	default:
		t.Fatal("done channel should be closed after resolve")
	}
}

func TestDenyApproval(t *testing.T) {
	store := NewStore()
	req, _ := store.Create(testCall(), testDecision())

	err := store.Resolve(req.ID, false, "api", false)
	require.NoError(t, err)

	assert.Equal(t, StatusDenied, req.Status)
}

func TestResolveUnknownID(t *testing.T) {
	store := NewStore()
	err := store.Resolve("nonexistent", true, "cli", false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown id")
}

func TestDoubleResolve(t *testing.T) {
	store := NewStore()
	req, _ := store.Create(testCall(), testDecision())

	require.NoError(t, store.Resolve(req.ID, true, "cli", false))
	err := store.Resolve(req.ID, false, "cli", false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already")
}

func TestExpiry(t *testing.T) {
	expired := make(chan *Request, 1)
	store := NewStore(
		WithTimeout(100*time.Millisecond),
		WithExpireCallback(func(r *Request) {
			expired <- r
		}),
	)

	req, _ := store.Create(testCall(), testDecision())

	select {
	case got := <-expired:
		assert.Equal(t, req.ID, got.ID)
		assert.Equal(t, StatusExpired, got.Status)
		assert.Equal(t, "timeout", got.ResolvedBy)
	case <-time.After(2 * time.Second):
		t.Fatal("expected expiry callback")
	}
}

func TestListPending(t *testing.T) {
	store := NewStore()
	call1 := testCall()
	call1.Params = map[string]any{"command": "cmd-1"}
	call2 := testCall()
	call2.Params = map[string]any{"command": "cmd-2"}
	_, _ = store.Create(call1, testDecision())
	_, _ = store.Create(call2, testDecision())

	pending := store.List()
	assert.Len(t, pending, 2)
}

func TestCleanup(t *testing.T) {
	store := NewStore()
	req, _ := store.Create(testCall(), testDecision())
	require.NoError(t, store.Resolve(req.ID, true, "cli", false))

	// Should not clean up yet (too recent).
	removed := store.Cleanup(1 * time.Hour)
	assert.Equal(t, 0, removed)

	// Force the resolved time to be old.
	req.ResolvedAt = time.Now().Add(-2 * time.Hour)
	removed = store.Cleanup(1 * time.Hour)
	assert.Equal(t, 1, removed)
}

func TestDeduplicateWithinWindow(t *testing.T) {
	store := NewStore()
	call := testCall()
	decision := testDecision()

	req1, err := store.Create(call, decision)
	require.NoError(t, err)

	// Same call within window should return the same approval.
	req2, err := store.Create(call, decision)
	require.NoError(t, err)

	assert.Equal(t, req1.ID, req2.ID, "duplicate call within window should return same approval")

	// Different call should get a new approval.
	call2 := testCall()
	call2.Params = map[string]any{"command": "echo different"}
	req3, err := store.Create(call2, decision)
	require.NoError(t, err)

	assert.NotEqual(t, req1.ID, req3.ID, "different call should get different approval")
}

func TestWaitForResolution(t *testing.T) {
	store := NewStore()
	req, _ := store.Create(testCall(), testDecision())

	// Resolve in background after a delay.
	go func() {
		time.Sleep(50 * time.Millisecond)
		store.Resolve(req.ID, true, "cli", false)
	}()

	select {
	case <-req.Done():
		assert.Equal(t, StatusApproved, req.Status)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for resolution")
	}
}

func TestApprovalStorePersistence(t *testing.T) {
	// Use a temp file for persistence.
	f, err := os.CreateTemp(t.TempDir(), "approvals-*.jsonl")
	require.NoError(t, err)
	f.Close()
	persistFile := f.Name()

	// 1. Create a store with a pending approval.
	store1 := NewStore(WithPersistenceFile(persistFile))
	req, err := store1.Create(testCall(), testDecision())
	require.NoError(t, err)
	assert.Equal(t, StatusPending, req.Status)
	store1.Close()

	// 2. Create a NEW store pointing to the same file.
	store2 := NewStore(WithPersistenceFile(persistFile))
	defer store2.Close()

	// 3. Verify the approval is restored and still pending.
	restored, ok := store2.Get(req.ID)
	require.True(t, ok, "approval should be restored from disk")
	assert.Equal(t, StatusPending, restored.Status)
	assert.Equal(t, req.ID, restored.ID)
	assert.Equal(t, req.Call.Tool, restored.Call.Tool)
	assert.Equal(t, req.Call.Agent, restored.Call.Agent)

	// Also verify it shows up in List().
	pending := store2.List()
	assert.Len(t, pending, 1)
	assert.Equal(t, req.ID, pending[0].ID)
}

func TestApprovalStorePersistenceExpiredNotRestored(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "approvals-expired-*.jsonl")
	require.NoError(t, err)
	f.Close()
	persistFile := f.Name()

	// Create a store with a very short timeout so approval expires immediately.
	store1 := NewStore(
		WithPersistenceFile(persistFile),
		WithTimeout(1*time.Millisecond),
	)
	req, err := store1.Create(testCall(), testDecision())
	require.NoError(t, err)
	assert.NotEmpty(t, req.ID)
	// Wait for expiry.
	time.Sleep(50 * time.Millisecond)
	store1.Close()

	// Create a new store: expired approval should NOT be restored.
	store2 := NewStore(WithPersistenceFile(persistFile))
	defer store2.Close()

	_, ok := store2.Get(req.ID)
	assert.False(t, ok, "expired approval should not be restored from disk")
	assert.Empty(t, store2.List(), "no pending approvals should be restored")
}

func TestApprovalStorePersistenceResolvedNotRestored(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "approvals-resolved-*.jsonl")
	require.NoError(t, err)
	f.Close()
	persistFile := f.Name()

	store1 := NewStore(WithPersistenceFile(persistFile))
	req, err := store1.Create(testCall(), testDecision())
	require.NoError(t, err)

	// Resolve the approval.
	err = store1.Resolve(req.ID, true, "cli", false)
	require.NoError(t, err)
	store1.Close()

	// Create a new store: resolved approval should NOT be restored.
	store2 := NewStore(WithPersistenceFile(persistFile))
	defer store2.Close()

	_, ok := store2.Get(req.ID)
	assert.False(t, ok, "resolved approval should not be restored from disk")
	assert.Empty(t, store2.List())
}

func TestApprovalStorePersistenceMissingFile(t *testing.T) {
	// Point to a nonexistent file — should not panic or error.
	persistFile := filepath.Join(t.TempDir(), "does-not-exist.jsonl")
	store := NewStore(WithPersistenceFile(persistFile))
	defer store.Close()

	// Should work fine with an empty store.
	assert.Empty(t, store.List())

	// Create should work and create the file.
	req, err := store.Create(testCall(), testDecision())
	require.NoError(t, err)
	assert.Equal(t, StatusPending, req.Status)

	_, err = os.Stat(persistFile)
	assert.NoError(t, err, "persistence file should be created on first write")
}
