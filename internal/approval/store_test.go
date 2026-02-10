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
	req := store.Create(testCall(), testDecision())

	assert.Equal(t, StatusPending, req.Status)
	assert.NotEmpty(t, req.ID)
	assert.False(t, req.ExpiresAt.IsZero())

	// Approve it.
	err := store.Resolve(req.ID, true, "cli")
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
	req := store.Create(testCall(), testDecision())

	err := store.Resolve(req.ID, false, "api")
	require.NoError(t, err)

	assert.Equal(t, StatusDenied, req.Status)
}

func TestResolveUnknownID(t *testing.T) {
	store := NewStore()
	err := store.Resolve("nonexistent", true, "cli")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown id")
}

func TestDoubleResolve(t *testing.T) {
	store := NewStore()
	req := store.Create(testCall(), testDecision())

	require.NoError(t, store.Resolve(req.ID, true, "cli"))
	err := store.Resolve(req.ID, false, "cli")
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

	req := store.Create(testCall(), testDecision())

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
	store.Create(testCall(), testDecision())
	store.Create(testCall(), testDecision())

	pending := store.List()
	assert.Len(t, pending, 2)
}

func TestCleanup(t *testing.T) {
	store := NewStore()
	req := store.Create(testCall(), testDecision())
	require.NoError(t, store.Resolve(req.ID, true, "cli"))

	// Should not clean up yet (too recent).
	removed := store.Cleanup(1 * time.Hour)
	assert.Equal(t, 0, removed)

	// Force the resolved time to be old.
	req.ResolvedAt = time.Now().Add(-2 * time.Hour)
	removed = store.Cleanup(1 * time.Hour)
	assert.Equal(t, 1, removed)
}

func TestWaitForResolution(t *testing.T) {
	store := NewStore()
	req := store.Create(testCall(), testDecision())

	// Resolve in background after a delay.
	go func() {
		time.Sleep(50 * time.Millisecond)
		store.Resolve(req.ID, true, "cli")
	}()

	select {
	case <-req.Done():
		assert.Equal(t, StatusApproved, req.Status)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for resolution")
	}
}
