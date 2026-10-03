// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peg/rampart/internal/audit"
	"github.com/stretchr/testify/require"
)

func TestHTTPPolicyFeedbackRedactsPresentation(t *testing.T) {
	const policy = `version: "1"
default_action: allow
policies:
  - name: "review --token=synthetic-policy"
    match:
      tool: exec
    rules:
      - action: deny
        message: "review --token=synthetic-reason"
`
	srv, token, _ := setupTestServer(t, policy, "enforce")
	t.Cleanup(srv.approvals.Close)
	for _, path := range []string{"/v1/tool/exec", "/v1/preflight/exec", "/v1/test"} {
		t.Run(path, func(t *testing.T) {
			body := `{"agent":"test","command":"echo note --token=synthetic-action","params":{"command":"echo note --token=synthetic-action"}}`
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			srv.handler().ServeHTTP(response, req)
			if path == "/v1/tool/exec" {
				require.Equal(t, http.StatusForbidden, response.Code)
			} else {
				require.Equal(t, http.StatusOK, response.Code)
			}
			for _, secret := range []string{"synthetic-policy", "synthetic-reason", "synthetic-action"} {
				require.NotContains(t, response.Body.String(), secret)
			}
			require.Contains(t, response.Body.String(), "[REDACTED]")
			require.NotContains(t, response.Body.String(), "rampart allow")
		})
	}
}

func TestHTTPApprovalResolutionLinksPersistedPolicyRecord(t *testing.T) {
	srv, token, _ := setupTestServer(t, "version: '1'\ndefault_action: ask\npolicies: []\n", "enforce")
	t.Cleanup(srv.approvals.Close)
	dir := t.TempDir()
	sink, err := audit.NewJSONLSink(dir)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sink.Close()) })
	srv.sink = audit.NewRedactingSink(sink)
	host := httptest.NewServer(srv.handler())
	t.Cleanup(host.Close)
	request := func(path, body string, wantStatus int) map[string]any {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, host.URL+path, strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		response, err := host.Client().Do(req)
		require.NoError(t, err)
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equal(t, wantStatus, response.StatusCode, string(data))
		require.NotContains(t, string(data), "synthetic-action")
		var result map[string]any
		require.NoError(t, json.Unmarshal(data, &result))
		return result
	}
	const body = `{"agent":"test","session":"s","run_id":"run","tool_call_id":"call","params":{"command":"echo note --token=synthetic-action"}}`
	initial := request("/v1/tool/exec", body, http.StatusAccepted)
	approvalID, ok := initial["approval_id"].(string)
	require.True(t, ok)
	originID, ok := initial["audit_id"].(string)
	require.True(t, ok)
	repeated := request("/v1/tool/exec", body, http.StatusAccepted)
	require.Equal(t, approvalID, repeated["approval_id"])
	require.NotEqual(t, originID, repeated["audit_id"], "each evaluation keeps its own audit record")
	request("/v1/approvals/"+approvalID+"/resolve", `{"approved":true,"resolved_by":"operator"}`, http.StatusOK)
	resumed := request("/v1/tool/exec", body, http.StatusOK)
	require.Equal(t, approvalID, resumed["approval_id"])
	require.Equal(t, true, resumed["allowed"], "redacted display must preserve the original approval identity")
	request("/v1/tool/exec", body, http.StatusAccepted)
	require.NoError(t, sink.Flush())
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	require.NoError(t, err)
	require.Len(t, files, 1)
	events, _, err := audit.ReadEventsFromOffset(files[0], 0)
	require.NoError(t, err)
	ids := make(map[string]bool, len(events))
	var linked bool
	for _, event := range events {
		require.False(t, ids[event.ID], "audit record IDs must be unique")
		ids[event.ID] = true
		if event.Request["action"] == "approval_resolved" {
			require.Equal(t, originID, event.Request["event_id"])
			require.Equal(t, approvalID, event.Request["approval_id"])
			linked = true
		}
		encoded, err := json.Marshal(event)
		require.NoError(t, err)
		require.NotContains(t, string(encoded), "synthetic-action")
	}
	require.True(t, ids[originID])
	require.True(t, linked)
	count, err := audit.VerifyManagedChain(dir)
	require.NoError(t, err)
	require.EqualValues(t, len(events), count)
}

func TestPolicyAuditFailureDoesNotCreateApproval(t *testing.T) {
	srv, token, _ := setupTestServer(t, "version: '1'\ndefault_action: ask\npolicies: []\n", "enforce")
	t.Cleanup(srv.approvals.Close)
	srv.sink = &failOnWriteSink{failAt: 1}
	req := httptest.NewRequest(http.MethodPost, "/v1/tool/exec", bytes.NewBufferString(`{"params":{"command":"echo note"}}`))
	req.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	srv.handler().ServeHTTP(response, req)
	require.Equal(t, http.StatusServiceUnavailable, response.Code)
	require.NotContains(t, response.Body.String(), "approval_id")
	require.Empty(t, srv.approvals.List())
}
