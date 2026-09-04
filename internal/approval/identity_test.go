// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package approval

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/peg/rampart/internal/engine"
	"github.com/stretchr/testify/require"
)

func TestPrivateApprovalRestartPreservesExactIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pending.jsonl")
	call := testCall()
	call.Params = map[string]any{"command": "review --token=synthetic-private-value ; echo suffix", "targets": []any{"first", "last"}, "nested": map[string]any{"password": "synthetic-nested-value"}}
	call.Input = map[string]any{"requester": "reviewer-one", "targets": []any{"first", "last"}}
	store := NewStore(WithPersistenceFile(path))
	req, _, err := store.CreateOrAutoApproved(call, testDecision(), "owner-one")
	require.NoError(t, err)
	require.True(t, req.HasRedactions())
	key := req.dedupKey
	require.True(t, strings.HasPrefix(key, "v3-"))
	require.NotContains(t, key, dedupKey(call))
	// Neither retained input aliases nor exposed review maps may alter the
	// immutable approval or the next operator-facing snapshot.
	req.Call.Params["command"] = "different displayed action"
	view, ok := store.Get(req.ID)
	require.True(t, ok)
	require.Contains(t, view.Call.Command(), "suffix")
	view.Call.Input["requester"] = "changed-view"
	store.Close()
	encoded, err := os.ReadFile(path)
	require.NoError(t, err)
	for _, secret := range []string{"synthetic-private-value", "synthetic-nested-value", "different displayed action", "changed-view", dedupKey(call)} {
		require.NotContains(t, string(encoded), secret)
	}

	restarted := NewStore(WithPersistenceFile(path))
	defer restarted.Close()
	restored, ok := restarted.Get(req.ID)
	require.True(t, ok)
	require.Equal(t, key, restored.dedupKey)
	require.True(t, restored.HasRedactions())
	require.True(t, restored.CanAuthorizeRun(), "parameter redaction must not disable an unchanged run identity")
	require.NoError(t, restarted.Resolve(req.ID, true, "operator"))
	for name, mutate := range map[string]func(*engine.ToolCall){
		"suffix": func(c *engine.ToolCall) {
			c.Params["command"] = "review --token=synthetic-private-value ; echo changed"
		},
		"secret":    func(c *engine.ToolCall) { c.Params["command"] = "review --token=different-private-value ; echo suffix" },
		"target":    func(c *engine.ToolCall) { c.Input["targets"] = []any{"first", "changed"} },
		"requester": func(c *engine.ToolCall) { c.Input["requester"] = "reviewer-two" },
		"context":   func(c *engine.ToolCall) { c.WorkDir = "/different-context" },
	} {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(call)
			require.NoError(t, err)
			var changed engine.ToolCall
			require.NoError(t, json.Unmarshal(data, &changed))
			mutate(&changed)
			_, consumed, err := restarted.ConsumeApprovedFor(changed, "owner-one")
			require.NoError(t, err)
			require.False(t, consumed)
		})
	}
	_, consumed, err := restarted.ConsumeApprovedFor(call, "owner-two")
	require.NoError(t, err)
	require.False(t, consumed)
	_, consumed, err = restarted.ConsumeApprovedFor(call, "owner-one")
	require.NoError(t, err)
	require.True(t, consumed)
	_, consumed, err = restarted.ConsumeApprovedFor(call, "owner-one")
	require.NoError(t, err)
	require.False(t, consumed)
}

func TestPrivateApprovalMigratesLegacyPendingAndExpiresLegacyGrants(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pending.jsonl")
	call := testCall()
	call.Params["command"] = "review --password=legacy-synthetic-secret"
	rec := persistRecord{ID: "legacy-pending", Tool: call.Tool, Agent: call.Agent, Session: call.Session, RunID: call.RunID, ToolCallID: call.ToolCallID, Params: call.Params, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute), Status: "pending"}
	data, err := json.Marshal(rec)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, append(data, '\n'), 0o600))
	// Publish an old-format allowance before upgrading. Its tombstone must
	// also prevent a downgraded reader from using it.
	legacyStore := &Store{persistFile: path}
	legacy := replayGrant{Version: 1, Fingerprint: replayKey(call), ApprovalID: "old-grant", ExpiresAt: time.Now().Add(time.Minute)}
	require.NoError(t, legacyStore.publishReplayGrant(legacy))
	store := NewStore(WithPersistenceFile(path))
	defer store.Close()
	require.NoError(t, store.identityErr)
	_, ready, consumedPath := store.replayGrantPaths(legacy.Fingerprint)
	_, err = os.Lstat(ready)
	require.True(t, os.IsNotExist(err))
	_, err = os.Lstat(consumedPath)
	require.NoError(t, err)
	pending, ok := store.Get(rec.ID)
	require.True(t, ok)
	require.True(t, pending.HasRedactions())
	migrated, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(migrated), "legacy-synthetic-secret")
	var migratedRecord persistRecord
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(migrated), &migratedRecord))
	require.Equal(t, privatePendingStatus, migratedRecord.Status)
	// Older binaries only accept pending/pending-v2 and v1/v2 replay paths.
	require.NotEqual(t, "pending", migratedRecord.Status)
	require.NotEqual(t, scopedPendingStatus, migratedRecord.Status)
	store.Close()
	store = NewStore(WithPersistenceFile(path))
	defer store.Close()
	require.NoError(t, store.identityErr)
	idempotent, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, string(migrated), string(idempotent))
	_, consumed, err := store.ConsumeApproved(call)
	require.NoError(t, err)
	require.False(t, consumed)
	require.NoError(t, store.Resolve(pending.ID, true, "operator"))
	_, consumed, err = store.ConsumeApproved(call)
	require.NoError(t, err)
	require.True(t, consumed)
}

func TestApprovalIdentityKeyLossAndUnsafeFilesFailClosed(t *testing.T) {
	for _, kind := range []string{"missing", "missing-replay", "malformed", "symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pending.jsonl")
			store := NewStore(WithPersistenceFile(path))
			req, err := store.Create(testCall(), testDecision())
			require.NoError(t, err)
			if kind == "missing-replay" {
				require.NoError(t, store.Resolve(req.ID, true, "operator"))
			}
			keyPath := path + ".identity-key"
			key, err := os.ReadFile(keyPath)
			require.NoError(t, err)
			require.NoError(t, os.Remove(keyPath))
			switch kind {
			case "malformed":
				require.NoError(t, os.WriteFile(keyPath, []byte("bad-key"), 0o600))
			case "symlink", "hardlink":
				other := filepath.Join(filepath.Dir(path), "other-key")
				require.NoError(t, os.WriteFile(other, key, 0o600))
				if kind == "symlink" {
					err = os.Symlink(other, keyPath)
				} else {
					err = os.Link(other, keyPath)
				}
				if err != nil {
					store.Close()
					t.Skipf("link unavailable: %v", err)
				}
			}
			require.Error(t, store.Resolve(req.ID, true, "operator"))
			store.Close()
			restarted := NewStore(WithPersistenceFile(path))
			defer restarted.Close()
			require.Error(t, restarted.identityErr)
			_, err = restarted.Create(testCall(), testDecision())
			require.Error(t, err)
			_, consumed, err := restarted.ConsumeApproved(testCall())
			require.Error(t, err)
			require.False(t, consumed)
			if strings.HasPrefix(kind, "missing") {
				_, err := os.Lstat(keyPath)
				require.True(t, os.IsNotExist(err), "must not regenerate missing key")
			}
		})
	}
}

func TestConcurrentApprovalStoresShareIdentityKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pending.jsonl")
	stores := make([]*Store, 4)
	var wg sync.WaitGroup
	for i := range stores {
		wg.Add(1)
		go func(i int) { defer wg.Done(); stores[i] = NewStore(WithPersistenceFile(path)) }(i)
	}
	wg.Wait()
	for _, store := range stores {
		defer store.Close()
		require.NoError(t, store.identityErr)
		require.Equal(t, stores[0].identityKey, store.identityKey)
	}
}

func TestRedactedRunScopeCannotGrantFutureAuthorityAfterRestart(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, field := range []string{"agent", "session", "run"} {
			t.Run(fmt.Sprintf("legacy_%v_%s", legacy, field), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "pending.jsonl")
				call := testCall()
				switch field {
				case "agent":
					call.Agent = "scope --token=synthetic-identity"
				case "session":
					call.Session = "scope --token=synthetic-identity"
				case "run":
					call.RunID = "scope --token=synthetic-identity"
				}
				id := "legacy-redacted-scope"
				if legacy {
					data, err := json.Marshal(persistRecord{ID: id, Tool: call.Tool, Agent: call.Agent, Session: call.Session, RunID: call.RunID, ToolCallID: call.ToolCallID, Params: call.Params, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute), Status: "pending"})
					require.NoError(t, err)
					require.NoError(t, os.WriteFile(path, append(data, '\n'), 0600))
				} else {
					before := NewStore(WithPersistenceFile(path))
					req, err := before.Create(call, testDecision())
					require.NoError(t, err)
					id = req.ID
					require.False(t, req.CanAuthorizeRun())
					before.Close()
				}
				restarted := NewStore(WithPersistenceFile(path))
				defer restarted.Close()
				req, ok := restarted.Get(id)
				require.True(t, ok)
				snapshot, err := restarted.BeginRunScopeSnapshot(req.Call, []string{id}, time.Minute)
				if err == nil {
					restarted.AbortRunScopeSnapshot(snapshot)
				}
				require.Error(t, err, "redacted identity must not become authority for a literal redaction-marker scope")
				require.NoError(t, restarted.Resolve(id, true, "operator"))
				_, consumed, err := restarted.ConsumeApproved(call)
				require.NoError(t, err)
				require.True(t, consumed, "the individually reviewed original action must remain resumable")
			})
		}
	}
}

type changingApprovalOperand struct{ calls int }

func (value *changingApprovalOperand) MarshalJSON() ([]byte, error) {
	value.calls++
	if value.calls == 1 {
		return []byte(`"first-target"`), nil
	}
	return []byte(`"different-target"`), nil
}

func TestApprovalSnapshotsCallerValuesOnceBeforeIdentityAndReview(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pending.jsonl")
	call := testCall()
	operand := &changingApprovalOperand{}
	call.Params["target"] = operand
	call.Params["sequence"] = int64(9007199254740993)
	before := NewStore(WithPersistenceFile(path))
	req, err := before.Create(call, testDecision())
	require.NoError(t, err)
	require.Equal(t, 1, operand.calls, "raw caller-owned marshalers must run only during initial capture")
	require.Equal(t, "first-target", req.Call.Params["target"])
	require.Equal(t, json.Number("9007199254740993"), req.Call.Params["sequence"])
	before.Close()

	restarted := NewStore(WithPersistenceFile(path))
	defer restarted.Close()
	restored, ok := restarted.Get(req.ID)
	require.True(t, ok)
	require.Equal(t, "first-target", restored.Call.Params["target"])
	require.Equal(t, json.Number("9007199254740993"), restored.Call.Params["sequence"], "journal restoration must preserve the displayed integer")
	require.NoError(t, restarted.Resolve(req.ID, true, "operator"))
	call.Params["target"] = "different-target"
	_, consumed, err := restarted.ConsumeApproved(call)
	require.NoError(t, err)
	require.False(t, consumed)
	call.Params["target"] = "first-target"
	call.Params["sequence"] = int64(9007199254740992)
	_, consumed, err = restarted.ConsumeApproved(call)
	require.NoError(t, err)
	require.False(t, consumed, "adjacent integers above float64 precision must not share authority")
	call.Params["sequence"] = int64(9007199254740993)
	_, consumed, err = restarted.ConsumeApproved(call)
	require.NoError(t, err)
	require.True(t, consumed)
}
