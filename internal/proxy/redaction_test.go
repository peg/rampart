// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package proxy

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/engine"
	"github.com/stretchr/testify/require"
)

func TestPendingApprovalRedactsDiagnosticsAuditAndSSE(t *testing.T) {
	var diagnostics bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&diagnostics, nil))
	eng, err := engine.New(engine.NewMemoryStore([]byte("version: \"1\"\ndefault_action: ask\npolicies: []\n"), "test"), nil)
	require.NoError(t, err)
	defer eng.Stop()
	dir := t.TempDir()
	sink, err := audit.NewJSONLSink(dir)
	require.NoError(t, err)
	defer sink.Close()
	// Existing chain bytes must survive addition of newly redacted records.
	require.NoError(t, sink.Write(audit.Event{ID: audit.NewEventID(), Timestamp: time.Now().UTC(), Agent: "historic", Tool: "read"}))
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	require.NoError(t, err)
	require.Len(t, files, 1)
	historical, err := os.ReadFile(files[0])
	require.NoError(t, err)
	srv := New(eng, audit.NewRedactingSink(sink), WithLogger(logger), WithToken("test-token"))
	defer srv.approvals.Close()
	events, unsubscribe := srv.sse.subscribe()
	defer unsubscribe()

	body := map[string]any{
		"agent": "token=synthetic-agent", "session": "token=synthetic-session",
		"run_id": "token=synthetic-run", "tool_call_id": "token=synthetic-call",
		"params": map[string]any{"command": "echo --token=synthetic-command"},
	}
	request := func(method, path string, value any) *httptest.ResponseRecorder {
		data, marshalErr := json.Marshal(value)
		require.NoError(t, marshalErr)
		req := httptest.NewRequest(method, path, bytes.NewReader(data))
		req.Header.Set("Authorization", "Bearer test-token")
		response := httptest.NewRecorder()
		srv.handler().ServeHTTP(response, req)
		return response
	}
	response := request(http.MethodPost, "/v1/tool/exec", body)
	require.Equal(t, http.StatusAccepted, response.Code, response.Body.String())
	var pending struct {
		ApprovalID string `json:"approval_id"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &pending))
	require.NotEmpty(t, pending.ApprovalID)
	live := <-events // The tool's audit event precedes the approval-list update.
	require.Contains(t, string(live), `"type":"audit"`)
	stored, err := os.ReadFile(files[0])
	require.NoError(t, err)
	require.True(t, bytes.HasPrefix(stored, historical), "historical chain bytes changed")
	for _, output := range []string{diagnostics.String(), string(live), string(stored)} {
		for _, secret := range []string{"synthetic-agent", "synthetic-session", "synthetic-run", "synthetic-call", "synthetic-command"} {
			require.NotContains(t, output, secret)
		}
		require.Contains(t, output, "[REDACTED]")
	}
	for _, line := range strings.Split(strings.TrimSpace(string(stored)), "\n") {
		var event audit.Event
		require.NoError(t, json.Unmarshal([]byte(line), &event))
		valid, verifyErr := event.VerifyHash()
		require.NoError(t, verifyErr)
		require.True(t, valid, "new redaction must precede hashing")
	}

	// Redaction affects output only: the original full action can still consume
	// its one-time authorization, while a different action requires a new ask.
	resolution := request(http.MethodPost, "/v1/approvals/"+pending.ApprovalID+"/resolve", map[string]any{"approved": true})
	require.Equal(t, http.StatusOK, resolution.Code, resolution.Body.String())
	body["params"] = map[string]any{"command": "echo --token=different-synthetic-command"}
	require.Equal(t, http.StatusAccepted, request(http.MethodPost, "/v1/tool/exec", body).Code)
	body["params"] = map[string]any{"command": "echo --token=synthetic-command"}
	resumed := request(http.MethodPost, "/v1/tool/exec", body)
	require.Equal(t, http.StatusOK, resumed.Code, resumed.Body.String())
	require.Contains(t, resumed.Body.String(), `"allowed":true`)
}
