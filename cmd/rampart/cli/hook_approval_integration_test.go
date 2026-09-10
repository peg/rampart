// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/peg/rampart/internal/approval"
	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/internal/proxy"
	"github.com/stretchr/testify/require"
)

// Exercise both production endpoints: a client-only mock cannot detect a
// server that accepts the request while silently discarding action fields.
func TestHookApprovalClientServerContract(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy.yaml")
	require.NoError(t, os.WriteFile(policy, []byte("version: '1'\ndefault_action: deny\npolicies: []\n"), 0600))
	eng, err := engine.New(engine.NewFileStore(policy), testLogger())
	require.NoError(t, err)
	sink, err := audit.NewJSONLSink(filepath.Join(dir, "audit"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sink.Close()) })
	srv := proxy.New(eng, sink, proxy.WithToken("contract-test-token"), proxy.WithLogger(testLogger()))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	served := make(chan error, 1)
	go func() { served <- srv.Serve(listener) }()
	base := "http://" + listener.Addr().String()
	httpClient := &http.Client{Timeout: 5 * time.Second}
	request := func(method, path string, value any) []byte {
		t.Helper()
		data, err := json.Marshal(value)
		require.NoError(t, err)
		req, err := http.NewRequest(method, base+path, bytes.NewReader(data))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer contract-test-token")
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
		return body
	}
	request("GET", "/healthz", nil) // server is installed before cleanup can run
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require.NoError(t, srv.Shutdown(ctx))
		require.NoError(t, <-served)
	})
	call := engine.ToolCall{
		ID: "original-audit-event", Tool: "write", Agent: "codex", AgentDepth: 1,
		Session: "session", RunID: "run", ToolCallID: "host-call", WorkDir: dir,
		Params: map[string]any{"file_path": "first.txt", "content": "harmless marker", "targets": []any{"first.txt", "last.txt"}, "revision": json.Number("9007199254740993"), "password": "synthetic-private-value"},
		Input:  map[string]any{"original_tool": "apply_patch"},
	}
	client := &hookApprovalClient{serveURL: base, token: "contract-test-token", logger: testLogger(), errWriter: io.Discard}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan hookDecisionType, 1)
	go func() { result <- client.requestApprovalCtx(ctx, call, "review the complete write", 10*time.Second) }()
	var pending *approval.Request
	require.Eventually(t, func() bool {
		items := srv.Approvals().List()
		if len(items) == 1 {
			pending = items[0]
			return true
		}
		return false
	}, 5*time.Second, 10*time.Millisecond)
	view := request("GET", "/v1/approvals/"+pending.ID, nil)
	var detail struct{ Action approval.ActionReview }
	decoder := json.NewDecoder(bytes.NewReader(view))
	decoder.UseNumber()
	require.NoError(t, decoder.Decode(&detail))
	require.Equal(t, call.ToolCallID, detail.Action.ToolCallID)
	require.Equal(t, call.Session, detail.Action.Session)
	require.Equal(t, call.RunID, detail.Action.RunID)
	require.Equal(t, call.WorkDir, detail.Action.WorkDir)
	require.Equal(t, call.AgentDepth, detail.Action.AgentDepth)
	require.Equal(t, "harmless marker", detail.Action.Params["content"])
	require.Equal(t, call.Params["targets"], detail.Action.Params["targets"])
	require.Equal(t, call.Params["revision"], detail.Action.Params["revision"])
	require.Equal(t, call.Input, detail.Action.Input)
	require.NotContains(t, string(view), "synthetic-private-value")
	request("POST", "/v1/approvals/"+pending.ID+"/resolve", map[string]any{"approved": true, "resolved_by": "contract-test"})
	select {
	case decision := <-result:
		require.Equal(t, hookAllow, decision)
	case <-time.After(5 * time.Second):
		t.Fatal("approved hook did not resume")
	}
	require.NoError(t, sink.Flush())
	files, err := filepath.Glob(filepath.Join(dir, "audit", "*.jsonl"))
	require.NoError(t, err)
	require.NotEmpty(t, files)
	var resolutions []audit.Event
	for _, path := range files {
		events, _, err := audit.ReadEventsFromOffset(path, 0)
		require.NoError(t, err)
		for _, event := range events {
			if event.Request["action"] == "approval_resolved" {
				resolutions = append(resolutions, event)
			}
		}
	}
	require.Len(t, resolutions, 1)
	require.Equal(t, call.ID, resolutions[0].Request["event_id"])
	require.Equal(t, call.ToolCallID, resolutions[0].ToolCallID)
	require.Equal(t, call.Session, resolutions[0].Session)
}
