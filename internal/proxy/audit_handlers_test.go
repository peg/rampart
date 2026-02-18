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

package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupAuditTestServer(t *testing.T, auditDir string) (*httptest.Server, string) {
	t.Helper()
	srv, token, _ := setupTestServer(t, testPolicyYAML, "enforce")
	srv.auditDir = auditDir
	ts := httptest.NewServer(srv.handler())
	t.Cleanup(ts.Close)
	return ts, token
}

func writeAuditFile(t *testing.T, dir, date string, events []map[string]any) {
	t.Helper()
	path := filepath.Join(dir, date+".jsonl")
	var lines []string
	for _, evt := range events {
		b, err := json.Marshal(evt)
		require.NoError(t, err)
		lines = append(lines, string(b))
	}
	require.NoError(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644))
}

func doGet(t *testing.T, ts *httptest.Server, token, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func TestAuditEvents(t *testing.T) {
	dir := t.TempDir()
	today := time.Now().UTC().Format("2006-01-02")

	events := []map[string]any{
		{"id": "01", "timestamp": "2026-02-18T00:00:00Z", "agent": "claude", "tool": "exec", "decision": map[string]any{"action": "allow"}},
		{"id": "02", "timestamp": "2026-02-18T00:01:00Z", "agent": "claude", "tool": "read", "decision": map[string]any{"action": "deny"}},
		{"id": "03", "timestamp": "2026-02-18T00:02:00Z", "agent": "other", "tool": "exec", "decision": map[string]any{"action": "allow"}},
	}
	writeAuditFile(t, dir, today, events)

	ts, token := setupAuditTestServer(t, dir)

	t.Run("basic", func(t *testing.T) {
		resp := doGet(t, ts, token, "/v1/audit/events")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var body map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		evts := body["events"].([]any)
		assert.Equal(t, 3, len(evts))
		assert.Equal(t, today, body["date"])
		// Most recent first
		assert.Equal(t, "03", evts[0].(map[string]any)["id"])
	})

	t.Run("filter_tool", func(t *testing.T) {
		resp := doGet(t, ts, token, "/v1/audit/events?tool=read")
		defer resp.Body.Close()
		var body map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		evts := body["events"].([]any)
		assert.Equal(t, 1, len(evts))
	})

	t.Run("filter_action", func(t *testing.T) {
		resp := doGet(t, ts, token, "/v1/audit/events?action=deny")
		defer resp.Body.Close()
		var body map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		evts := body["events"].([]any)
		assert.Equal(t, 1, len(evts))
	})

	t.Run("filter_agent", func(t *testing.T) {
		resp := doGet(t, ts, token, "/v1/audit/events?agent=other")
		defer resp.Body.Close()
		var body map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		evts := body["events"].([]any)
		assert.Equal(t, 1, len(evts))
	})

	t.Run("pagination", func(t *testing.T) {
		resp := doGet(t, ts, token, "/v1/audit/events?limit=2")
		defer resp.Body.Close()
		var body map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		evts := body["events"].([]any)
		assert.Equal(t, 2, len(evts))
		assert.Equal(t, float64(2), body["next_offset"])
	})

	t.Run("no_auth", func(t *testing.T) {
		resp := doGet(t, ts, "", "/v1/audit/events")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

func TestAuditDates(t *testing.T) {
	dir := t.TempDir()
	writeAuditFile(t, dir, "2026-02-18", []map[string]any{{"id": "01"}})
	writeAuditFile(t, dir, "2026-02-17", []map[string]any{{"id": "02"}})

	ts, token := setupAuditTestServer(t, dir)

	resp := doGet(t, ts, token, "/v1/audit/dates")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	dates := body["dates"].([]any)
	assert.Equal(t, 2, len(dates))
	// Most recent first
	assert.Equal(t, "2026-02-18", dates[0])
	assert.Equal(t, true, body["configured"])
}

func TestAuditExport(t *testing.T) {
	dir := t.TempDir()
	writeAuditFile(t, dir, "2026-02-18", []map[string]any{
		{"id": "01", "tool": "exec"},
		{"id": "02", "tool": "read"},
	})

	ts, token := setupAuditTestServer(t, dir)

	t.Run("success", func(t *testing.T) {
		resp := doGet(t, ts, token, "/v1/audit/export?date=2026-02-18")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "application/jsonl", resp.Header.Get("Content-Type"))
		assert.Contains(t, resp.Header.Get("Content-Disposition"), "rampart-audit-2026-02-18.jsonl")

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		lines := strings.Split(strings.TrimSpace(string(body)), "\n")
		assert.Equal(t, 2, len(lines))
	})

	t.Run("missing_date", func(t *testing.T) {
		resp := doGet(t, ts, token, "/v1/audit/export")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("not_found", func(t *testing.T) {
		resp := doGet(t, ts, token, "/v1/audit/export?date=2020-01-01")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

func TestAuditStats(t *testing.T) {
	dir := t.TempDir()
	writeAuditFile(t, dir, "2026-02-17", []map[string]any{
		{"id": "01", "agent": "claude", "tool": "exec", "decision": map[string]any{"action": "allow"}},
		{"id": "02", "agent": "claude", "tool": "read", "decision": map[string]any{"action": "deny"}},
	})
	writeAuditFile(t, dir, "2026-02-18", []map[string]any{
		{"id": "03", "agent": "other", "tool": "exec", "decision": map[string]any{"action": "allow"}},
	})

	ts, token := setupAuditTestServer(t, dir)

	resp := doGet(t, ts, token, "/v1/audit/stats?from=2026-02-17&to=2026-02-18")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, float64(3), body["total_events"])

	byAction := body["by_action"].(map[string]any)
	assert.Equal(t, float64(2), byAction["allow"])
	assert.Equal(t, float64(1), byAction["deny"])

	byTool := body["by_tool"].(map[string]any)
	assert.Equal(t, float64(2), byTool["exec"])
	assert.Equal(t, float64(1), byTool["read"])

	byAgent := body["by_agent"].(map[string]any)
	assert.Equal(t, float64(2), byAgent["claude"])
	assert.Equal(t, float64(1), byAgent["other"])
}

func TestAuditNoDir(t *testing.T) {
	ts, token := setupAuditTestServer(t, "")

	for _, path := range []string{"/v1/audit/events", "/v1/audit/dates", "/v1/audit/export?date=2026-01-01", "/v1/audit/stats"} {
		resp := doGet(t, ts, token, path)
		resp.Body.Close()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, "path: %s", path)
	}
}

func writeHookAuditFile(t *testing.T, dir, date string, events []map[string]any) {
	t.Helper()
	path := filepath.Join(dir, "audit-hook-"+date+".jsonl")
	var lines []string
	for _, evt := range events {
		b, err := json.Marshal(evt)
		require.NoError(t, err)
		lines = append(lines, string(b))
	}
	require.NoError(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644))
}

func TestAuditDates_WithHookFiles(t *testing.T) {
	dir := t.TempDir()
	// Serve writes one date, hook writes another — both should appear.
	writeAuditFile(t, dir, "2026-02-17", []map[string]any{{"id": "serve-01"}})
	writeHookAuditFile(t, dir, "2026-02-18", []map[string]any{{"id": "hook-01"}})

	ts, token := setupAuditTestServer(t, dir)

	resp := doGet(t, ts, token, "/v1/audit/dates")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	dates := body["dates"].([]any)
	assert.Equal(t, 2, len(dates), "expected both serve and hook dates")
	assert.Equal(t, "2026-02-18", dates[0])
	assert.Equal(t, "2026-02-17", dates[1])
}

func TestAuditEvents_HookFilesIncluded(t *testing.T) {
	dir := t.TempDir()
	// Serve file is empty; hook file has events — dashboard should see them.
	writeAuditFile(t, dir, "2026-02-18", []map[string]any{})
	writeHookAuditFile(t, dir, "2026-02-18", []map[string]any{
		{"id": "hook-01", "decision": map[string]any{"action": "allow"}},
		{"id": "hook-02", "decision": map[string]any{"action": "deny"}},
	})

	ts, token := setupAuditTestServer(t, dir)

	resp := doGet(t, ts, token, "/v1/audit/events?date=2026-02-18")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	total := int(body["total_in_file"].(float64))
	assert.Equal(t, 2, total, "expected hook file events to be counted")
}
