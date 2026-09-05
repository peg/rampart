// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApprovalReviewAPIKeepsFullRedactedAction(t *testing.T) {
	const policy = `version: "1"
default_action: ask
policies:
  - name: review-exec
    match:
      tool: exec
    rules:
      - action: ask
`
	srv, token, _ := setupTestServer(t, policy, "enforce")
	request := func(method, path string, value any) *httptest.ResponseRecorder {
		t.Helper()
		data, err := json.Marshal(value)
		require.NoError(t, err)
		req := httptest.NewRequest(method, path, bytes.NewReader(data))
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		srv.handler().ServeHTTP(rr, req)
		return rr
	}
	command := "echo " + strings.Repeat("x", 180) + " ; echo final-target --token=synthetic-private"
	body := map[string]any{
		"agent": "review-agent", "session": "review-session", "run_id": "review-run", "tool_call_id": "review-call",
		"params": map[string]any{"command": command, "workdir": "/synthetic-workspace", "rampart_original_tool": "bash", "targets": []string{"first", "last"}, "nested": map[string]any{"password": "synthetic-nested"}},
	}
	for _, hosted := range []bool{true, false} {
		body["openclaw_hosted"], body["skip_pending_approval"] = hosted, hosted
		rr := request(http.MethodPost, "/v1/tool/exec", body)
		expectedStatus := http.StatusAccepted
		if hosted {
			expectedStatus = http.StatusOK
		}
		require.Equal(t, expectedStatus, rr.Code, rr.Body.String())
		var result struct {
			Action struct {
				Version int
				Tool    string
				WorkDir string
				Params  map[string]any
			}
			ApprovalID string `json:"approval_id"`
		}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &result))
		require.Equal(t, 1, result.Action.Version)
		require.Equal(t, "exec", result.Action.Tool)
		require.Equal(t, "bash", result.Action.Params["rampart_original_tool"])
		require.Equal(t, "/synthetic-workspace", result.Action.WorkDir)
		require.Contains(t, result.Action.Params["command"], "final-target")
		for _, secret := range []string{"synthetic-private", "synthetic-nested"} {
			require.NotContains(t, rr.Body.String(), secret)
		}
		if hosted {
			require.Empty(t, srv.approvals.List())
			continue
		}
		require.NotEmpty(t, result.ApprovalID)
		for _, path := range []string{"/v1/approvals", "/v1/approvals/" + result.ApprovalID} {
			view := request(http.MethodGet, path, nil)
			require.Equal(t, http.StatusOK, view.Code)
			require.Contains(t, view.Body.String(), `"action"`)
			require.Contains(t, view.Body.String(), "final-target")
			require.Contains(t, view.Body.String(), "last")
			for _, secret := range []string{"synthetic-private", "synthetic-nested"} {
				require.NotContains(t, view.Body.String(), secret)
			}
		}
		persistent := request(http.MethodPost, "/v1/approvals/"+result.ApprovalID+"/resolve", map[string]any{"approved": true, "persist": true})
		require.Equal(t, http.StatusBadRequest, persistent.Code)
		require.Len(t, srv.approvals.List(), 1, "unsupported persistence must leave the original approval pending")
	}
	preview := request(http.MethodPost, "/v1/preflight/exec", body)
	require.Equal(t, http.StatusOK, preview.Code)
	require.Contains(t, preview.Body.String(), `"action"`)
	require.NotContains(t, preview.Body.String(), "synthetic-private")
}
