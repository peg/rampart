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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/peg/rampart/internal/engine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStoreCloseIsConcurrentSafe(t *testing.T) {
	store := NewStore()
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store.Close()
		}()
	}
	wg.Wait()
}

func TestStoreCloseWaitsForOwnedWorkers(t *testing.T) {
	store := NewStore()
	started := make(chan struct{})
	release := make(chan struct{})
	store.startWorker(func() {
		close(started)
		<-release
	})
	<-started

	closed := make(chan struct{})
	go func() {
		store.Close()
		close(closed)
	}()

	select {
	case <-closed:
		t.Fatal("Close returned while a Store-owned worker was still running")
	case <-time.After(25 * time.Millisecond):
	}

	close(release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not return after the Store-owned worker stopped")
	}
}

func TestStoreRejectsCreateAfterClose(t *testing.T) {
	store := NewStore()
	store.Close()

	_, err := store.Create(testCall(), testDecision())
	require.ErrorIs(t, err, ErrStoreClosed)
}

func testCall() engine.ToolCall {
	return engine.ToolCall{
		ID:         "test-1",
		Agent:      "main",
		Session:    "session-1",
		RunID:      "run-1",
		ToolCallID: "tool-call-1",
		Tool:       "exec",
		Params:     map[string]any{"command": "sudo reboot"},
		Timestamp:  time.Now(),
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

func TestResolveBeforePublishOrdersJournalAndAuditBeforeAuthorization(t *testing.T) {
	persistFile := filepath.Join(t.TempDir(), "approvals.jsonl")
	store := NewStore(WithPersistenceFile(persistFile))
	t.Cleanup(store.Close)

	call := testCall()
	req, err := store.Create(call, testDecision())
	require.NoError(t, err)

	callbackCalled := false
	err = store.ResolveBeforePublish(req.ID, true, "operator", func(candidate *Request) error {
		callbackCalled = true
		assert.Equal(t, StatusApproved, candidate.Status)
		assert.Equal(t, "operator", candidate.ResolvedBy)

		journal, readErr := os.ReadFile(persistFile)
		require.NoError(t, readErr)
		assert.Contains(t, string(journal), `"status":"approved"`, "resolution must be journaled before required audit work")

		select {
		case <-req.Done():
			t.Fatal("waiter woke before required audit work completed")
		default:
		}
		_, published := store.approvedOnce[replayKey(call)]
		assert.False(t, published, "one-shot authorization became visible before required audit work")
		return nil
	})
	require.NoError(t, err)
	assert.True(t, callbackCalled)

	select {
	case <-req.Done():
	default:
		t.Fatal("waiter was not woken after journal and audit work succeeded")
	}
	grant, consumed, err := store.ConsumeApproved(call)
	require.NoError(t, err)
	require.True(t, consumed)
	assert.Equal(t, req.ID, grant.ID)
}

func TestResolveBeforePublishFailureLeavesRequestPendingAndRetryable(t *testing.T) {
	persistFile := filepath.Join(t.TempDir(), "approvals.jsonl")
	store := NewStore(WithPersistenceFile(persistFile))
	t.Cleanup(store.Close)

	call := testCall()
	req, err := store.Create(call, testDecision())
	require.NoError(t, err)

	err = store.ResolveBeforePublish(req.ID, true, "operator", func(*Request) error {
		return errors.New("audit unavailable")
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audit unavailable")
	assert.Equal(t, StatusPending, req.Status)
	select {
	case <-req.Done():
		t.Fatal("failed resolution woke its waiter")
	default:
	}
	grant, consumed, consumeErr := store.ConsumeApproved(call)
	require.NoError(t, consumeErr)
	assert.False(t, consumed, "failed resolution published one-shot authorization")
	assert.Nil(t, grant)

	// The compensating pending journal entry must win on restart too.
	restarted := NewStore(WithPersistenceFile(persistFile))
	t.Cleanup(restarted.Close)
	restored, ok := restarted.Get(req.ID)
	require.True(t, ok)
	assert.Equal(t, StatusPending, restored.Status)

	require.NoError(t, store.ResolveBeforePublish(req.ID, true, "operator", func(*Request) error { return nil }))
	assert.Equal(t, StatusApproved, req.Status)
}

func TestResolveBeforePublishJournalFailurePreventsAuditAndAuthorization(t *testing.T) {
	persistFile := filepath.Join(t.TempDir(), "approvals.jsonl")
	store := NewStore(WithPersistenceFile(persistFile))
	t.Cleanup(store.Close)

	call := testCall()
	req, err := store.Create(call, testDecision())
	require.NoError(t, err)
	require.NoError(t, os.Remove(persistFile))
	require.NoError(t, os.Mkdir(persistFile, 0o700))

	callbackCalled := false
	err = store.ResolveBeforePublish(req.ID, true, "operator", func(*Request) error {
		callbackCalled = true
		return nil
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "persistence journal")
	assert.False(t, callbackCalled, "audit work ran before required journal persistence")
	assert.Equal(t, StatusPending, req.Status)
	select {
	case <-req.Done():
		t.Fatal("journal failure woke the approval waiter")
	default:
	}
	_, published := store.approvedOnce[replayKey(call)]
	assert.False(t, published, "journal failure published one-shot authorization")
}

func TestConcurrentResolveBeforePublishIsSingleWinner(t *testing.T) {
	store := NewStore()
	t.Cleanup(store.Close)
	req, err := store.Create(testCall(), testDecision())
	require.NoError(t, err)

	entered := make(chan struct{})
	release := make(chan struct{})
	var callbackOnce sync.Once
	callbackCalls := 0
	callback := func(*Request) error {
		callbackCalls++
		callbackOnce.Do(func() { close(entered) })
		<-release
		return nil
	}

	results := make(chan error, 2)
	go func() { results <- store.ResolveBeforePublish(req.ID, true, "operator-a", callback) }()
	<-entered
	go func() { results <- store.ResolveBeforePublish(req.ID, true, "operator-b", callback) }()
	close(release)

	first := <-results
	second := <-results
	assert.Equal(t, 1, callbackCalls)
	assert.True(t, (first == nil) != (second == nil), "exactly one concurrent resolution must commit")
	if first != nil {
		assert.Contains(t, first.Error(), "already")
	}
	if second != nil {
		assert.Contains(t, second.Error(), "already")
	}
}

func TestMarkPersistedRequiresApprovedRequest(t *testing.T) {
	store := NewStore()
	t.Cleanup(store.Close)

	pending, err := store.Create(testCall(), testDecision())
	require.NoError(t, err)
	require.Error(t, store.MarkPersisted(pending.ID))
	require.NoError(t, store.Resolve(pending.ID, true, "operator"))
	require.NoError(t, store.MarkPersisted(pending.ID))
	resolved, ok := store.Get(pending.ID)
	require.True(t, ok)
	assert.True(t, resolved.Persisted)
}

func TestDenyApproval(t *testing.T) {
	store := NewStore()
	req, _ := store.Create(testCall(), testDecision())

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
	req, _ := store.Create(testCall(), testDecision())

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
	require.NoError(t, store.Resolve(req.ID, true, "cli"))

	// Should not clean up yet (too recent).
	removed := store.Cleanup(1 * time.Hour)
	assert.Equal(t, 0, removed)

	// Force the resolved time to be old.
	req.ResolvedAt = time.Now().Add(-2 * time.Hour)
	removed = store.Cleanup(1 * time.Hour)
	assert.Equal(t, 1, removed)
}

func TestAutoApproveRunIsScopedToAgentSessionAndRun(t *testing.T) {
	store := NewStore()
	defer store.Close()

	original := testCall()
	require.True(t, store.AutoApproveRun(original, time.Minute))
	assert.True(t, store.IsAutoApproved(original))

	for _, tt := range []struct {
		name   string
		mutate func(*engine.ToolCall)
	}{
		{"different agent", func(call *engine.ToolCall) { call.Agent = "other" }},
		{"different session", func(call *engine.ToolCall) { call.Session = "other" }},
		{"different run", func(call *engine.ToolCall) { call.RunID = "other" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			changed := original
			tt.mutate(&changed)
			assert.False(t, store.IsAutoApproved(changed))
		})
	}
}

func TestAutoApproveRunRejectsIncompleteIdentity(t *testing.T) {
	for _, field := range []string{"agent", "session", "run"} {
		t.Run(field, func(t *testing.T) {
			store := NewStore()
			defer store.Close()
			call := testCall()
			switch field {
			case "agent":
				call.Agent = ""
			case "session":
				call.Session = ""
			case "run":
				call.RunID = ""
			}
			assert.False(t, store.AutoApproveRun(call, time.Minute))
			assert.False(t, store.IsAutoApproved(call))
		})
	}
}

func TestCreateOrAutoApprovedDoesNotEnqueueAuthorizedCall(t *testing.T) {
	store := NewStore()
	t.Cleanup(store.Close)
	call := testCall()
	require.True(t, store.AutoApproveRun(call, time.Minute))

	req, autoApproved, err := store.CreateOrAutoApproved(call, testDecision(), "")
	require.NoError(t, err)
	assert.True(t, autoApproved)
	assert.Nil(t, req)
	assert.Empty(t, store.List())
}

func TestAutoApprovePublicationAndCreateAreAtomic(t *testing.T) {
	type createResult struct {
		req          *Request
		autoApproved bool
		err          error
	}
	type installResult struct {
		pending   []*Request
		installed bool
	}

	// Exercise both possible lock winners repeatedly. The valid outcomes are:
	// creation wins and publication returns that pending request, or publication
	// wins and creation observes auto-approved. Installed+pending is forbidden.
	for range 256 {
		store := NewStore()
		call := testCall()
		start := make(chan struct{})
		created := make(chan createResult, 1)
		installed := make(chan installResult, 1)

		go func() {
			<-start
			req, autoApproved, err := store.CreateOrAutoApproved(call, testDecision(), "")
			created <- createResult{req: req, autoApproved: autoApproved, err: err}
		}()
		go func() {
			<-start
			pending, ok := store.AutoApproveRunIfNoPending(call, time.Minute)
			installed <- installResult{pending: pending, installed: ok}
		}()
		close(start)

		create := <-created
		install := <-installed
		require.NoError(t, create.err)
		if install.installed {
			assert.True(t, create.autoApproved)
			assert.Nil(t, create.req)
			assert.Empty(t, install.pending)
			assert.Empty(t, store.List())
		} else {
			assert.False(t, create.autoApproved)
			require.NotNil(t, create.req)
			require.Len(t, install.pending, 1)
			assert.Equal(t, create.req.ID, install.pending[0].ID)
			assert.Len(t, store.List(), 1)
		}
		store.Close()
	}
}

func TestAutoApproveRunIfNoPendingOnlyReturnsExactScope(t *testing.T) {
	store := NewStore()
	t.Cleanup(store.Close)
	target := testCall()
	other := target
	other.Agent = "other"
	other.ToolCallID = "other-call"

	targetReq, err := store.Create(target, testDecision())
	require.NoError(t, err)
	_, err = store.Create(other, testDecision())
	require.NoError(t, err)

	pending, installed := store.AutoApproveRunIfNoPending(target, time.Minute)
	assert.False(t, installed)
	require.Len(t, pending, 1)
	assert.Equal(t, targetReq.ID, pending[0].ID)
	assert.False(t, store.IsAutoApproved(target))
}

func TestDeduplicateStablePendingCall(t *testing.T) {
	store := NewStore()
	call := testCall()
	decision := testDecision()

	req1, err := store.Create(call, decision)
	require.NoError(t, err)

	// Same stable call stays singular for its full pending lifetime.
	req2, err := store.Create(call, decision)
	require.NoError(t, err)
	assert.Equal(t, req1.ID, req2.ID)
	req1.CreatedAt = time.Now().Add(-time.Hour)
	req2, err = store.Create(call, decision)
	require.NoError(t, err)
	assert.Equal(t, req1.ID, req2.ID)

	// Different call should get a new approval.
	call2 := testCall()
	call2.Params = map[string]any{"command": "echo different"}
	req3, err := store.Create(call2, decision)
	require.NoError(t, err)

	assert.NotEqual(t, req1.ID, req3.ID, "different call should get different approval")
}

func TestOwnerScopedPendingDedupSurvivesRestart(t *testing.T) {
	persistFile := filepath.Join(t.TempDir(), "approvals.jsonl")
	ownerA, ownerB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	store := NewStore(WithPersistenceFile(persistFile))
	call := testCall()
	first, autoApproved, err := store.CreateOrAutoApproved(call, testDecision(), ownerA)
	require.NoError(t, err)
	require.False(t, autoApproved)
	store.Close()

	journal, err := os.ReadFile(persistFile)
	require.NoError(t, err)
	assert.Contains(t, string(journal), `"owner_scope"`)
	assert.NotContains(t, string(journal), ownerA, "persist only a domain-separated owner digest")
	var record persistRecord
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(journal), &record))
	assert.Equal(t, scopedPendingStatus, record.Status)
	assert.NotEqual(t, "pending", record.Status, "v1.6.2 must discard scoped pending state on rollback")

	restarted := NewStore(WithPersistenceFile(persistFile))
	defer restarted.Close()
	retry, autoApproved, err := restarted.CreateOrAutoApproved(call, testDecision(), ownerA)
	require.NoError(t, err)
	require.False(t, autoApproved)
	assert.Equal(t, first.ID, retry.ID, "a lost response retry must reuse the restored pending approval")

	other, autoApproved, err := restarted.CreateOrAutoApproved(call, testDecision(), ownerB)
	require.NoError(t, err)
	require.False(t, autoApproved)
	assert.NotEqual(t, first.ID, other.ID, "a sibling token must not inherit pending state")
	assert.Len(t, restarted.List(), 2)
}

func TestDeduplicationIsBoundToExecutionContext(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*engine.ToolCall)
	}{
		{
			name: "different session",
			mutate: func(call *engine.ToolCall) {
				call.Session = "session-2"
			},
		},
		{
			name: "different run",
			mutate: func(call *engine.ToolCall) {
				call.RunID = "run-2"
			},
		},
		{
			name: "different tool call",
			mutate: func(call *engine.ToolCall) {
				call.ToolCallID = "tool-call-2"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewStore()
			defer store.Close()

			first := testCall()
			req1, err := store.Create(first, testDecision())
			require.NoError(t, err)

			second := testCall()
			tt.mutate(&second)
			req2, err := store.Create(second, testDecision())
			require.NoError(t, err)

			assert.NotEqual(t, req1.ID, req2.ID)
		})
	}
}

func TestCallsWithoutStableToolCallIDAreNeverDeduplicated(t *testing.T) {
	store := NewStore()
	defer store.Close()

	call := testCall()
	call.ToolCallID = ""

	req1, err := store.Create(call, testDecision())
	require.NoError(t, err)
	req2, err := store.Create(call, testDecision())
	require.NoError(t, err)

	assert.NotEqual(t, req1.ID, req2.ID)
}

func TestApprovedReplayConsumesExactCallOnce(t *testing.T) {
	store := NewStore()
	defer store.Close()

	call := testCall()
	req, err := store.Create(call, testDecision())
	require.NoError(t, err)
	require.NoError(t, store.Resolve(req.ID, true, "operator"))

	grant, consumed, err := store.ConsumeApproved(call)
	require.NoError(t, err)
	require.True(t, consumed)
	require.NotNil(t, grant)
	assert.Equal(t, req.ID, grant.ID)
	assert.Equal(t, "operator", grant.ResolvedBy)

	grant, consumed, err = store.ConsumeApproved(call)
	require.NoError(t, err)
	assert.False(t, consumed, "an allow-once approval must not authorize a second replay")
	assert.Nil(t, grant)
}

func TestApprovedReplayRequiresExactStableIdentityAndPayload(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*engine.ToolCall)
	}{
		{"missing run id", func(call *engine.ToolCall) { call.RunID = "" }},
		{"missing tool call id", func(call *engine.ToolCall) { call.ToolCallID = "" }},
		{"different agent", func(call *engine.ToolCall) { call.Agent = "other" }},
		{"different agent depth", func(call *engine.ToolCall) { call.AgentDepth++ }},
		{"different session", func(call *engine.ToolCall) { call.Session = "other" }},
		{"different run id", func(call *engine.ToolCall) { call.RunID = "other" }},
		{"different tool call id", func(call *engine.ToolCall) { call.ToolCallID = "other" }},
		{"different tool", func(call *engine.ToolCall) { call.Tool = "write" }},
		{"different working directory", func(call *engine.ToolCall) { call.WorkDir = "/tmp/other" }},
		{"different params", func(call *engine.ToolCall) { call.Params = map[string]any{"command": "sudo poweroff"} }},
		{"different input", func(call *engine.ToolCall) { call.Input = map[string]any{"path": "/tmp/other"} }},
	}

	for _, tt := range mutations {
		t.Run(tt.name, func(t *testing.T) {
			store := NewStore()
			defer store.Close()

			original := testCall()
			original.Input = map[string]any{"path": "/tmp/original"}
			req, err := store.Create(original, testDecision())
			require.NoError(t, err)
			require.NoError(t, store.Resolve(req.ID, true, "operator"))

			changed := original
			tt.mutate(&changed)
			grant, consumed, err := store.ConsumeApproved(changed)
			require.NoError(t, err)
			assert.False(t, consumed)
			assert.Nil(t, grant)

			// A mismatched attempt must not consume the original exact grant.
			grant, consumed, err = store.ConsumeApproved(original)
			require.NoError(t, err)
			assert.True(t, consumed)
			assert.Equal(t, req.ID, grant.ID)
		})
	}
}

func TestDeniedApprovalNeverCreatesReplayGrant(t *testing.T) {
	store := NewStore()
	defer store.Close()

	call := testCall()
	req, err := store.Create(call, testDecision())
	require.NoError(t, err)
	require.NoError(t, store.Resolve(req.ID, false, "operator"))

	grant, consumed, err := store.ConsumeApproved(call)
	require.NoError(t, err)
	assert.False(t, consumed)
	assert.Nil(t, grant)
}

func TestApprovedReplayIsNotCreatedWithoutBothStableIDs(t *testing.T) {
	for _, missing := range []string{"run_id", "tool_call_id"} {
		t.Run(missing, func(t *testing.T) {
			store := NewStore()
			defer store.Close()

			call := testCall()
			if missing == "run_id" {
				call.RunID = ""
			} else {
				call.ToolCallID = ""
			}
			req, err := store.Create(call, testDecision())
			require.NoError(t, err)
			require.NoError(t, store.Resolve(req.ID, true, "operator"))

			grant, consumed, err := store.ConsumeApproved(call)
			require.NoError(t, err)
			assert.False(t, consumed)
			assert.Nil(t, grant)
		})
	}
}

func TestExpiredApprovedReplayCannotBeConsumed(t *testing.T) {
	store := NewStore()
	defer store.Close()

	call := testCall()
	req, err := store.Create(call, testDecision())
	require.NoError(t, err)
	require.NoError(t, store.Resolve(req.ID, true, "operator"))

	key := replayKey(call)
	grant := store.approvedOnce[key]
	grant.ExpiresAt = time.Now().Add(-time.Second)
	store.approvedOnce[key] = grant

	consumedGrant, consumed, err := store.ConsumeApproved(call)
	require.NoError(t, err)
	assert.False(t, consumed)
	assert.Nil(t, consumedGrant)
}

func TestOwnerScopedPersistentReplayIsCrossStoreAndOneShot(t *testing.T) {
	persistFile := filepath.Join(t.TempDir(), "approvals.jsonl")
	ownerA, ownerB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	store1 := NewStore(WithPersistenceFile(persistFile))
	defer store1.Close()

	call := testCall()
	req, autoApproved, err := store1.CreateOrAutoApproved(call, testDecision(), ownerA)
	require.NoError(t, err)
	require.False(t, autoApproved)
	require.NoError(t, store1.Resolve(req.ID, true, "operator"))
	legacyKey := replayKey(call)
	scopedKey := ownerBoundKey(legacyKey, ownerScopeDigest(ownerA))
	_, legacyReady, _ := store1.replayGrantPaths(legacyKey)
	dataPath, scopedReady, _ := store1.replayGrantPaths(scopedKey)
	_, err = os.Stat(legacyReady)
	assert.True(t, os.IsNotExist(err), "v1.6.2 must not find a scoped replay grant at its legacy path")
	require.FileExists(t, scopedReady)
	encoded, err := os.ReadFile(dataPath)
	require.NoError(t, err)
	var persisted replayGrant
	require.NoError(t, json.Unmarshal(encoded, &persisted))
	assert.Equal(t, 2, persisted.Version)
	assert.Equal(t, scopedKey, persisted.Fingerprint)

	// A separate Store models a restarted or concurrently running process.
	store2 := NewStore(WithPersistenceFile(persistFile))
	defer store2.Close()
	assert.Empty(t, store2.List(), "a durably approved request must not be resurrected as pending")
	grant, consumed, err := store2.ConsumeApproved(call)
	require.NoError(t, err)
	assert.False(t, consumed, "legacy unscoped consumption must fail closed")
	assert.Nil(t, grant)
	grant, consumed, err = store2.ConsumeApprovedFor(call, ownerB)
	require.NoError(t, err)
	assert.False(t, consumed, "a sibling owner must not consume the grant")
	assert.Nil(t, grant)

	type result struct {
		grant    *ConsumedApproval
		consumed bool
		err      error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for _, store := range []*Store{store1, store2} {
		go func(candidate *Store) {
			<-start
			grant, consumed, err := candidate.ConsumeApprovedFor(call, ownerA)
			results <- result{grant: grant, consumed: consumed, err: err}
		}(store)
	}
	close(start)

	winners := 0
	for range 2 {
		got := <-results
		require.NoError(t, got.err)
		if got.consumed {
			winners++
			require.NotNil(t, got.grant)
			assert.Equal(t, req.ID, got.grant.ID)
		} else {
			assert.Nil(t, got.grant)
		}
	}
	assert.Equal(t, 1, winners, "the durable allow-once grant must have exactly one cross-process winner")

	grant, consumed, err = store2.ConsumeApprovedFor(call, ownerA)
	require.NoError(t, err)
	assert.False(t, consumed)
	assert.Nil(t, grant)
}

func TestLegacyReplayRemainsAdminOnly(t *testing.T) {
	store := NewStore()
	defer store.Close()
	call := testCall()
	req, err := store.Create(call, testDecision())
	require.NoError(t, err)
	require.NoError(t, store.Resolve(req.ID, true, "operator"))

	grant, consumed, err := store.ConsumeApprovedFor(call, strings.Repeat("a", 64))
	require.NoError(t, err)
	assert.False(t, consumed, "ambiguous legacy state must not authorize an eval token")
	assert.Nil(t, grant)
	grant, consumed, err = store.ConsumeApproved(call)
	require.NoError(t, err)
	require.True(t, consumed, "deliberate unscoped admin/local behavior must remain available")
	assert.Equal(t, req.ID, grant.ID)
}

func TestRunAutoApprovalIsBoundToResolvedOwner(t *testing.T) {
	store := NewStore()
	defer store.Close()
	ownerA, ownerB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	call := testCall()
	request, autoApproved, err := store.CreateOrAutoApproved(call, testDecision(), ownerA)
	require.NoError(t, err)
	require.False(t, autoApproved)
	require.NoError(t, store.Resolve(request.ID, true, "operator"))
	_, installed := store.AutoApproveRunIfNoPendingForRequest(call, request, time.Minute)
	require.True(t, installed)

	next := call
	next.ToolCallID = "next-call"
	next.Params = map[string]any{"command": "different sensitive action"}
	owned, autoApproved, err := store.CreateOrAutoApproved(next, testDecision(), ownerA)
	require.NoError(t, err)
	assert.True(t, autoApproved)
	assert.Nil(t, owned)
	sibling, autoApproved, err := store.CreateOrAutoApproved(next, testDecision(), ownerB)
	require.NoError(t, err)
	assert.False(t, autoApproved)
	assert.NotNil(t, sibling)
}

func TestRunAutoApprovalRequiresPrePublicationStep(t *testing.T) {
	store := NewStore()
	defer store.Close()
	call := testCall()
	request, err := store.Create(call, testDecision())
	require.NoError(t, err)
	require.NoError(t, store.Resolve(request.ID, true, "operator"))

	called := false
	pending, expiresAt, installed, err := store.AutoApproveRunBeforePublishForRequest(
		call,
		request,
		time.Minute,
		func(expiry time.Time) error {
			called = true
			assert.WithinDuration(t, time.Now().Add(time.Minute), expiry, time.Second)
			return fmt.Errorf("audit unavailable")
		},
	)
	require.Error(t, err)
	assert.True(t, called)
	assert.Empty(t, pending)
	assert.True(t, expiresAt.IsZero())
	assert.False(t, installed)
	assert.False(t, store.IsAutoApproved(call))

	pending, expiresAt, installed, err = store.AutoApproveRunBeforePublishForRequest(
		call,
		request,
		time.Minute,
		func(time.Time) error { return nil },
	)
	require.NoError(t, err)
	assert.Empty(t, pending)
	assert.False(t, expiresAt.IsZero())
	assert.True(t, installed)
	assert.True(t, store.IsAutoApproved(call))
}

func TestRunAutoApprovalRejectsGrantExpiredDuringPublication(t *testing.T) {
	store := NewStore()
	defer store.Close()
	call := testCall()
	request, err := store.Create(call, testDecision())
	require.NoError(t, err)
	require.NoError(t, store.Resolve(request.ID, true, "operator"))

	pending, expiresAt, installed, err := store.AutoApproveRunBeforePublishForRequest(
		call,
		request,
		time.Nanosecond,
		func(time.Time) error {
			time.Sleep(time.Millisecond)
			return nil
		},
	)
	require.ErrorContains(t, err, "expired before publication")
	assert.Empty(t, pending)
	assert.True(t, expiresAt.IsZero())
	assert.False(t, installed)
	assert.False(t, store.IsAutoApproved(call))
}

func TestRunScopeSnapshotRejectsPostSnapshotDenial(t *testing.T) {
	store := NewStore()
	t.Cleanup(store.Close)
	call := testCall()
	initial, err := store.Create(call, testDecision())
	require.NoError(t, err)
	snapshot, err := store.BeginRunScopeSnapshot(call, []string{initial.ID}, time.Minute)
	require.NoError(t, err)
	t.Cleanup(func() { store.AbortRunScopeSnapshot(snapshot) })

	commit, err := store.ResolveBeforePublishForRunScopeSnapshot(snapshot, initial.ID, "operator", nil)
	require.NoError(t, err)
	assert.Equal(t, initial.ID, commit.ID)

	racedCall := call
	racedCall.ToolCallID = "post-snapshot-denied"
	racedCall.Params = map[string]any{"command": "deploy denied"}
	raced, autoApproved, err := store.CreateOrAutoApproved(racedCall, testDecision(), "")
	require.NoError(t, err)
	require.False(t, autoApproved)
	require.NotNil(t, raced)
	require.NoError(t, store.Resolve(raced.ID, false, "other-operator"))

	pending, expiresAt, installed, err := store.AutoApproveRunBeforePublishForRunScopeSnapshot(snapshot, nil)
	require.ErrorContains(t, err, "was denied after the run-scope snapshot")
	assert.Empty(t, pending)
	assert.True(t, expiresAt.IsZero())
	assert.False(t, installed)
	assert.False(t, store.IsAutoApproved(call))

	retry := racedCall
	retryRequest, retryAutoApproved, err := store.CreateOrAutoApproved(retry, testDecision(), "")
	require.NoError(t, err)
	assert.False(t, retryAutoApproved, "a denied post-snapshot call gained future authority")
	assert.NotNil(t, retryRequest)
}

func TestRunScopeSnapshotRejectsPostSnapshotExternalApprovalAndExpiry(t *testing.T) {
	for _, test := range []struct {
		name    string
		timeout time.Duration
		settle  func(*testing.T, *Store, *Request)
		want    string
	}{
		{
			name:    "external approval",
			timeout: time.Minute,
			settle: func(t *testing.T, store *Store, request *Request) {
				require.NoError(t, store.Resolve(request.ID, true, "other-operator"))
			},
			want: "approved outside the active run-scope transaction",
		},
		{
			name:    "expiry",
			timeout: 100 * time.Millisecond,
			settle: func(t *testing.T, _ *Store, request *Request) {
				select {
				case <-request.Done():
				case <-time.After(2 * time.Second):
					t.Fatal("post-snapshot approval did not expire")
				}
			},
			want: "expired after the run-scope snapshot",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := NewStore(WithTimeout(test.timeout))
			t.Cleanup(store.Close)
			call := testCall()
			initial, err := store.Create(call, testDecision())
			require.NoError(t, err)
			snapshot, err := store.BeginRunScopeSnapshot(call, []string{initial.ID}, time.Minute)
			require.NoError(t, err)
			t.Cleanup(func() { store.AbortRunScopeSnapshot(snapshot) })
			_, err = store.ResolveBeforePublishForRunScopeSnapshot(snapshot, initial.ID, "operator", nil)
			require.NoError(t, err)

			racedCall := call
			racedCall.ToolCallID = "post-snapshot-" + strings.ReplaceAll(test.name, " ", "-")
			raced, autoApproved, err := store.CreateOrAutoApproved(racedCall, testDecision(), "")
			require.NoError(t, err)
			require.False(t, autoApproved)
			require.NotNil(t, raced)
			test.settle(t, store, raced)

			_, _, installed, err := store.AutoApproveRunBeforePublishForRunScopeSnapshot(snapshot, nil)
			require.ErrorContains(t, err, test.want)
			assert.False(t, installed)
			assert.False(t, store.IsAutoApproved(call))
		})
	}
}

func TestRunScopeSnapshotUsesImmutableCreationScope(t *testing.T) {
	store := NewStore()
	t.Cleanup(store.Close)
	call := testCall()
	request, err := store.Create(call, testDecision())
	require.NoError(t, err)
	request.Call.Agent = "mutated-agent"
	request.Call.Session = "mutated-session"
	request.Call.RunID = "mutated-run"

	snapshot, err := store.BeginRunScopeSnapshot(call, []string{request.ID}, time.Minute)
	require.NoError(t, err)
	t.Cleanup(func() { store.AbortRunScopeSnapshot(snapshot) })
	_, err = store.ResolveBeforePublishForRunScopeSnapshot(snapshot, request.ID, "operator", nil)
	require.NoError(t, err)
	_, _, installed, err := store.AutoApproveRunBeforePublishForRunScopeSnapshot(snapshot, nil)
	require.NoError(t, err)
	assert.True(t, installed)
	assert.True(t, store.IsAutoApproved(call))
}

func TestRunScopeSnapshotReturnsAndCommitsPendingRace(t *testing.T) {
	store := NewStore()
	t.Cleanup(store.Close)
	call := testCall()
	initial, err := store.Create(call, testDecision())
	require.NoError(t, err)
	snapshot, err := store.BeginRunScopeSnapshot(call, []string{initial.ID}, time.Minute)
	require.NoError(t, err)
	t.Cleanup(func() { store.AbortRunScopeSnapshot(snapshot) })
	_, err = store.ResolveBeforePublishForRunScopeSnapshot(snapshot, initial.ID, "operator", nil)
	require.NoError(t, err)

	racedCall := call
	racedCall.ToolCallID = "post-snapshot-pending"
	racedCall.Params = map[string]any{"command": "deploy raced"}
	raced, autoApproved, err := store.CreateOrAutoApproved(racedCall, testDecision(), "")
	require.NoError(t, err)
	require.False(t, autoApproved)
	require.NotNil(t, raced)

	pending, _, installed, err := store.AutoApproveRunBeforePublishForRunScopeSnapshot(snapshot, nil)
	require.NoError(t, err)
	require.False(t, installed)
	require.Len(t, pending, 1)
	assert.Equal(t, raced.ID, pending[0].ID)
	_, err = store.ResolveBeforePublishForRunScopeSnapshot(snapshot, raced.ID, "operator", nil)
	require.NoError(t, err)
	store.mu.Lock()
	racedGrant, replayPublished := store.approvedOnce[ownerBoundKey(replayKey(racedCall), "")]
	store.mu.Unlock()
	require.True(t, replayPublished)
	assert.False(t, racedGrant.ExpiresAt.After(snapshot.expiresAt), "exact replay grant outlived run-scope authorization window")

	pending, expiresAt, installed, err := store.AutoApproveRunBeforePublishForRunScopeSnapshot(snapshot, nil)
	require.NoError(t, err)
	assert.Empty(t, pending)
	assert.False(t, expiresAt.IsZero())
	assert.True(t, installed)
	assert.True(t, store.IsAutoApproved(racedCall))

	_, _, installed, err = store.AutoApproveRunBeforePublishForRunScopeSnapshot(snapshot, nil)
	require.ErrorContains(t, err, "stale, consumed, or belongs to another store")
	assert.False(t, installed)
}

func TestRunScopeSnapshotIgnoresUnrelatedScopeAndRejectsForeignStore(t *testing.T) {
	store := NewStore()
	t.Cleanup(store.Close)
	otherStore := NewStore()
	t.Cleanup(otherStore.Close)
	call := testCall()
	initial, err := store.Create(call, testDecision())
	require.NoError(t, err)
	snapshot, err := store.BeginRunScopeSnapshot(call, []string{initial.ID}, time.Minute)
	require.NoError(t, err)
	t.Cleanup(func() { store.AbortRunScopeSnapshot(snapshot) })

	_, _, installed, err := otherStore.AutoApproveRunBeforePublishForRunScopeSnapshot(snapshot, nil)
	require.ErrorContains(t, err, "another store")
	assert.False(t, installed)

	otherCall := call
	otherCall.RunID = "unrelated-run"
	otherCall.ToolCallID = "unrelated-call"
	other, err := store.Create(otherCall, testDecision())
	require.NoError(t, err)
	require.NoError(t, store.Resolve(other.ID, false, "other-operator"))
	_, err = store.ResolveBeforePublishForRunScopeSnapshot(snapshot, initial.ID, "operator", nil)
	require.NoError(t, err)
	_, _, installed, err = store.AutoApproveRunBeforePublishForRunScopeSnapshot(snapshot, nil)
	require.NoError(t, err)
	assert.True(t, installed)
}

func TestRunScopeSnapshotDeadlineCannotBeExtendedByRacedCalls(t *testing.T) {
	store := NewStore()
	t.Cleanup(store.Close)
	call := testCall()
	initial, err := store.Create(call, testDecision())
	require.NoError(t, err)
	snapshot, err := store.BeginRunScopeSnapshot(call, []string{initial.ID}, 20*time.Millisecond)
	require.NoError(t, err)
	t.Cleanup(func() { store.AbortRunScopeSnapshot(snapshot) })
	_, err = store.ResolveBeforePublishForRunScopeSnapshot(snapshot, initial.ID, "operator", nil)
	require.NoError(t, err)

	var raced *Request
	for index := 0; time.Now().Before(snapshot.expiresAt); index++ {
		racedCall := call
		racedCall.ToolCallID = fmt.Sprintf("deadline-race-%d", index)
		racedCall.Params = map[string]any{"command": racedCall.ToolCallID}
		var autoApproved bool
		raced, autoApproved, err = store.CreateOrAutoApproved(racedCall, testDecision(), "")
		require.NoError(t, err)
		require.False(t, autoApproved)
		time.Sleep(time.Millisecond)
	}
	require.NotNil(t, raced)

	_, err = store.ResolveBeforePublishForRunScopeSnapshot(snapshot, raced.ID, "operator", nil)
	require.ErrorContains(t, err, "authorization window expired")
	_, _, installed, err := store.AutoApproveRunBeforePublishForRunScopeSnapshot(snapshot, nil)
	require.ErrorContains(t, err, "authorization window expired")
	assert.False(t, installed)
	assert.False(t, store.IsAutoApproved(call))
}

func TestRunScopeSnapshotDeadlineCannotPassDuringResolutionAudit(t *testing.T) {
	store := NewStore(WithTimeout(time.Minute))
	t.Cleanup(store.Close)
	call := testCall()
	initial, err := store.Create(call, testDecision())
	require.NoError(t, err)
	snapshot, err := store.BeginRunScopeSnapshot(call, []string{initial.ID}, 100*time.Millisecond)
	require.NoError(t, err)
	t.Cleanup(func() { store.AbortRunScopeSnapshot(snapshot) })
	_, err = store.ResolveBeforePublishForRunScopeSnapshot(snapshot, initial.ID, "operator", nil)
	require.NoError(t, err)

	racedCall := call
	racedCall.ToolCallID = "resolution-audit-deadline-race"
	racedCall.Params = map[string]any{"command": "echo deadline"}
	raced, autoApproved, err := store.CreateOrAutoApproved(racedCall, testDecision(), "")
	require.NoError(t, err)
	require.False(t, autoApproved)

	callbackRan := false
	_, err = store.ResolveBeforePublishForRunScopeSnapshot(snapshot, raced.ID, "operator", func(*Request) error {
		callbackRan = true
		time.Sleep(time.Until(snapshot.expiresAt) + 10*time.Millisecond)
		return nil
	})
	require.True(t, callbackRan)
	require.ErrorContains(t, err, "authorization window expired")

	current, ok := store.Get(raced.ID)
	require.True(t, ok)
	assert.Equal(t, StatusPending, current.Status)
	select {
	case <-raced.Done():
		t.Fatal("raced approval waiter was published after the snapshot deadline")
	default:
	}
	grant, consumed, consumeErr := store.ConsumeApproved(racedCall)
	require.NoError(t, consumeErr)
	assert.False(t, consumed)
	assert.Nil(t, grant)
	assert.False(t, store.IsAutoApproved(call))
}

func TestRunScopeSnapshotAuditPanicCannotPublishGrant(t *testing.T) {
	store := NewStore()
	t.Cleanup(store.Close)
	call := testCall()
	request, err := store.Create(call, testDecision())
	require.NoError(t, err)
	snapshot, err := store.BeginRunScopeSnapshot(call, []string{request.ID}, time.Minute)
	require.NoError(t, err)
	t.Cleanup(func() { store.AbortRunScopeSnapshot(snapshot) })
	_, err = store.ResolveBeforePublishForRunScopeSnapshot(snapshot, request.ID, "operator", nil)
	require.NoError(t, err)

	func() {
		defer func() {
			assert.Equal(t, "audit panic", recover())
		}()
		_, _, _, _ = store.AutoApproveRunBeforePublishForRunScopeSnapshot(snapshot, func(time.Time) error {
			panic("audit panic")
		})
	}()
	assert.False(t, store.IsAutoApproved(call))
}

func TestRunGrantAuditPanicPreservesPreviousState(t *testing.T) {
	store := NewStore()
	t.Cleanup(store.Close)
	call := testCall()
	request, err := store.Create(call, testDecision())
	require.NoError(t, err)
	require.NoError(t, store.Resolve(request.ID, true, "operator"))

	func() {
		defer func() {
			assert.Equal(t, "audit panic", recover())
		}()
		_, _, _, _ = store.AutoApproveRunBeforePublishForRequest(call, request, time.Minute, func(time.Time) error {
			panic("audit panic")
		})
	}()
	assert.False(t, store.IsAutoApproved(call))
}

func TestResolveRejectsWallClockExpiredPendingRequest(t *testing.T) {
	store := NewStore(WithTimeout(5 * time.Millisecond))
	t.Cleanup(store.Close)
	request, err := store.Create(testCall(), testDecision())
	require.NoError(t, err)
	time.Sleep(10 * time.Millisecond)

	err = store.Resolve(request.ID, true, "operator")
	require.Error(t, err)
	current, ok := store.Get(request.ID)
	require.True(t, ok)
	assert.NotEqual(t, StatusApproved, current.Status)
}

func TestBeginRunScopeSnapshotPrunesExpiredAbandonedTokens(t *testing.T) {
	store := NewStore()
	t.Cleanup(store.Close)
	snapshots := make([]*RunScopeSnapshot, 0, maxActiveRunScopeSnapshots)

	for index := 0; index < maxActiveRunScopeSnapshots; index++ {
		call := testCall()
		call.RunID = fmt.Sprintf("abandoned-run-%d", index)
		call.ToolCallID = fmt.Sprintf("abandoned-call-%d", index)
		request, err := store.Create(call, testDecision())
		require.NoError(t, err)
		snapshot, err := store.BeginRunScopeSnapshot(call, []string{request.ID}, time.Minute)
		require.NoError(t, err)
		snapshots = append(snapshots, snapshot)
	}
	require.Len(t, store.activeRunScopes, maxActiveRunScopeSnapshots)
	for _, snapshot := range snapshots {
		snapshot.expiresAt = time.Now().Add(-time.Second)
	}

	call := testCall()
	call.RunID = "replacement-run"
	call.ToolCallID = "replacement-call"
	request, err := store.Create(call, testDecision())
	require.NoError(t, err)
	replacement, err := store.BeginRunScopeSnapshot(call, []string{request.ID}, time.Minute)
	require.NoError(t, err)
	t.Cleanup(func() { store.AbortRunScopeSnapshot(replacement) })
	assert.Len(t, store.activeRunScopes, 1)
	for _, snapshot := range snapshots {
		assert.True(t, snapshot.consumed)
	}
}

func TestPersistentApprovalAuthorizationFilesAreOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows DACL behavior is covered by internal/securefile tests")
	}

	persistFile := filepath.Join(t.TempDir(), "approvals.jsonl")
	store := NewStore(WithPersistenceFile(persistFile))
	defer store.Close()

	call := testCall()
	req, err := store.Create(call, testDecision())
	require.NoError(t, err)
	require.NoError(t, store.Resolve(req.ID, true, "operator"))

	dataPath, readyPath, _ := store.replayGrantPaths(replayKey(call))
	for _, path := range []string{persistFile, dataPath, readyPath} {
		info, err := os.Stat(path)
		require.NoError(t, err, path)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), path)
	}
}

func TestDeduplicationRequiresIdenticalActionPayload(t *testing.T) {
	store := NewStore()
	defer store.Close()

	first := testCall()
	first.Tool = "write"
	first.Params = map[string]any{"path": "/tmp/first", "content": "same"}
	req1, err := store.Create(first, testDecision())
	require.NoError(t, err)

	second := first
	second.Params = map[string]any{"path": "/tmp/second", "content": "same"}
	req2, err := store.Create(second, testDecision())
	require.NoError(t, err)

	assert.NotEqual(t, req1.ID, req2.ID)
}

func TestWaitForResolution(t *testing.T) {
	store := NewStore()
	req, _ := store.Create(testCall(), testDecision())

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

func TestApprovalStorePersistence(t *testing.T) {
	// Use a temp file for persistence.
	f, err := os.CreateTemp(t.TempDir(), "approvals-*.jsonl")
	require.NoError(t, err)
	f.Close()
	persistFile := f.Name()

	// 1. Create a store with a pending approval.
	store1 := NewStore(WithPersistenceFile(persistFile))
	call := testCall()
	call.AgentDepth = 2
	call.WorkDir = "/workspace/project"
	req, err := store1.Create(call, testDecision())
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
	assert.Equal(t, req.Call.AgentDepth, restored.Call.AgentDepth)
	assert.Equal(t, req.Call.Session, restored.Call.Session)
	assert.Equal(t, req.Call.RunID, restored.Call.RunID)
	assert.Equal(t, req.Call.ToolCallID, restored.Call.ToolCallID)
	assert.Equal(t, req.Call.WorkDir, restored.Call.WorkDir)

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
	err = store1.Resolve(req.ID, true, "cli")
	require.NoError(t, err)
	store1.Close()

	// Create a new store: resolved approval should NOT be restored.
	store2 := NewStore(WithPersistenceFile(persistFile))
	defer store2.Close()

	_, ok := store2.Get(req.ID)
	assert.False(t, ok, "resolved approval should not be restored from disk")
	assert.Empty(t, store2.List())
}

func TestApprovalJournalCompactionPreservesOtherStorePendingRecords(t *testing.T) {
	persistFile := filepath.Join(t.TempDir(), "approvals.jsonl")
	store1 := NewStore(WithPersistenceFile(persistFile))
	defer store1.Close()
	store2 := NewStore(WithPersistenceFile(persistFile))
	defer store2.Close()

	call1 := testCall()
	call1.ToolCallID = "tool-call-store-1"
	request1, err := store1.Create(call1, testDecision())
	require.NoError(t, err)

	call2 := testCall()
	call2.ToolCallID = "tool-call-store-2"
	request2, err := store2.Create(call2, testDecision())
	require.NoError(t, err)

	require.NoError(t, store1.Resolve(request1.ID, false, "operator"))

	restarted := NewStore(WithPersistenceFile(persistFile))
	defer restarted.Close()
	_, foundResolved := restarted.Get(request1.ID)
	assert.False(t, foundResolved)
	restored, foundPending := restarted.Get(request2.ID)
	require.True(t, foundPending, "one Store must not compact away another Store's pending approval")
	assert.Equal(t, StatusPending, restored.Status)
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

func TestApprovalCreateFailsClosedWhenPersistenceCannotBeHardened(t *testing.T) {
	// A directory at the configured journal path models a link/special-file or
	// ACL-hardening failure without relying on platform-specific permissions.
	persistFile := t.TempDir()
	store := NewStore(WithPersistenceFile(persistFile))
	defer store.Close()

	req, err := store.Create(testCall(), testDecision())
	require.Error(t, err)
	assert.Nil(t, req)
	assert.Empty(t, store.List(), "an unpersisted request must not remain actionable in memory")
}

func TestApprovalJournalRestoreRejectsPendingStateOverLimit(t *testing.T) {
	persistFile := filepath.Join(t.TempDir(), "approvals.jsonl")
	file, err := os.OpenFile(persistFile, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	require.NoError(t, err)
	encoder := json.NewEncoder(file)
	now := time.Now().UTC()
	for index := 0; index <= maxPendingApprovals; index++ {
		require.NoError(t, encoder.Encode(persistRecord{
			ID:        fmt.Sprintf("pending-%04d", index),
			Tool:      "exec",
			Params:    map[string]any{"command": "echo bounded"},
			CreatedAt: now,
			ExpiresAt: now.Add(time.Hour),
			Status:    "pending",
		}))
	}
	require.NoError(t, file.Close())

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := NewStore(WithPersistenceFile(persistFile), WithLogger(logger))
	defer store.Close()
	assert.Empty(t, store.List(), "an over-limit journal must fail closed instead of spawning unbounded expiry goroutines")
}

func TestApprovalJournalAppendRefusesAggregateSizeLimit(t *testing.T) {
	persistFile := filepath.Join(t.TempDir(), "approvals.jsonl")
	file, err := os.OpenFile(persistFile, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	require.NoError(t, err)
	require.NoError(t, file.Truncate(maxApprovalJournalBytes))
	require.NoError(t, file.Close())

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := NewStore(WithPersistenceFile(persistFile), WithLogger(logger))
	defer store.Close()
	req, err := store.Create(testCall(), testDecision())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "journal would exceed")
	assert.Nil(t, req)
	assert.Empty(t, store.List(), "unpersisted approval must not remain live after aggregate limit failure")
}

func TestApprovalJournalReplayDoesNotRetainResolvedHistory(t *testing.T) {
	persistFile := filepath.Join(t.TempDir(), "approvals.jsonl")
	file, err := os.OpenFile(persistFile, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	require.NoError(t, err)
	encoder := json.NewEncoder(file)
	now := time.Now().UTC()
	for index := 0; index < maxPendingApprovals*2; index++ {
		id := fmt.Sprintf("historical-%04d", index)
		record := persistRecord{
			ID:        id,
			Tool:      "exec",
			CreatedAt: now,
			ExpiresAt: now.Add(time.Hour),
			Status:    "pending",
		}
		require.NoError(t, encoder.Encode(record))
		record.Status = "denied"
		record.ResolvedAt = now
		require.NoError(t, encoder.Encode(record))
	}
	require.NoError(t, file.Close())

	store := NewStore(WithPersistenceFile(persistFile))
	defer store.Close()
	assert.Empty(t, store.List())
}

func TestConsumePersistedReplayGrantRejectsOversizedDataPermanently(t *testing.T) {
	persistFile := filepath.Join(t.TempDir(), "approvals.jsonl")
	store := NewStore(WithPersistenceFile(persistFile))
	defer store.Close()
	call := testCall()
	call.RunID = "run-oversized-replay"
	call.ToolCallID = "call-oversized-replay"
	key := replayKey(call)
	require.NotEmpty(t, key)
	dataPath, readyPath, consumedPath := store.replayGrantPaths(key)
	require.NoError(t, os.MkdirAll(filepath.Dir(dataPath), 0o700))
	require.NoError(t, os.WriteFile(dataPath, bytes.Repeat([]byte("x"), maxReplayGrantBytes+1), 0o600))
	require.NoError(t, os.WriteFile(readyPath, nil, 0o600))

	grant, consumed, err := store.ConsumeApproved(call)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds")
	assert.False(t, consumed)
	assert.Nil(t, grant)
	_, statErr := os.Stat(consumedPath)
	assert.NoError(t, statErr, "malformed grant must remain permanently consumed fail-closed")
}

func TestWalkApprovalStateDirStopsAtEntryLimit(t *testing.T) {
	dir := t.TempDir()
	for index := 0; index < 3; index++ {
		require.NoError(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("%d.ready", index)), nil, 0o600))
	}
	visited := 0
	err := walkApprovalStateDir(dir, 2, func(os.DirEntry) error {
		visited++
		return nil
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "2-entry limit")
	assert.Equal(t, 2, visited)
}
