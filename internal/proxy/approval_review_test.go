// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/peg/rampart/internal/approval"
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

func TestToolApprovalPreservesJSONNumbersBeforeReviewAndReplay(t *testing.T) {
	for _, field := range []string{"params", "input"} {
		t.Run(field, func(t *testing.T) {
			srv, token, _ := setupTestServer(t, "version: \"1\"\ndefault_action: ask\npolicies: []\n", "enforce")
			t.Cleanup(srv.approvals.Close)
			request := func(path, body string) *httptest.ResponseRecorder {
				t.Helper()
				req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
				req.Header.Set("Authorization", "Bearer "+token)
				rr := httptest.NewRecorder()
				srv.handler().ServeHTTP(rr, req)
				return rr
			}
			body := fmt.Sprintf(`{"agent":"numeric-agent","session":"numeric-session","run_id":"numeric-run","tool_call_id":"numeric-call",%q:{"sequence":9007199254740993,"nested":[0.1234567890123456789,1e20]}}`, field)
			initial := request("/v1/tool/mcp", body)
			require.Equal(t, http.StatusAccepted, initial.Code, initial.Body.String())
			var response struct {
				ApprovalID string                `json:"approval_id"`
				Action     approval.ActionReview `json:"action"`
			}
			decoder := json.NewDecoder(initial.Body)
			decoder.UseNumber()
			require.NoError(t, decoder.Decode(&response))
			values := response.Action.Params
			if field == "input" {
				values = response.Action.Input
			}
			require.Equal(t, json.Number("9007199254740993"), values["sequence"])
			require.Equal(t, []any{json.Number("0.1234567890123456789"), json.Number("1e20")}, values["nested"])

			resolved := request("/v1/approvals/"+response.ApprovalID+"/resolve", `{"approved":true,"resolved_by":"operator"}`)
			require.Equal(t, http.StatusOK, resolved.Code, resolved.Body.String())
			changed := request("/v1/tool/mcp", strings.Replace(body, "9007199254740993", "9007199254740992", 1))
			require.Equal(t, http.StatusAccepted, changed.Code, "a rounded adjacent integer must not consume approval: %s", changed.Body.String())
			replay := request("/v1/tool/mcp", body)
			require.Equal(t, http.StatusOK, replay.Code, replay.Body.String())
			require.Contains(t, replay.Body.String(), `"approval_id":"`+response.ApprovalID+`"`)
			require.Equal(t, http.StatusAccepted, request("/v1/tool/mcp", body).Code, "the exact action is approved only once")
		})
	}
}
