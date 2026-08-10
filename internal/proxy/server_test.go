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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/peg/rampart/internal/approval"
	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/internal/signing"
	"github.com/peg/rampart/internal/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testPolicyYAML = `
version: "1"
default_action: allow
policies:
  - name: block-destructive
    match:
      tool: exec
    rules:
      - action: deny
        when:
          command_matches: ["rm -rf *"]
        message: "destructive command blocked"
  - name: log-sudo
    match:
      tool: exec
    rules:
      - action: log
        when:
          command_matches: ["sudo *"]
        message: "sudo usage flagged"
  - name: allow-git
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["git *"]
        message: "git allowed"
`

const responsePolicyYAML = `
version: "1"
default_action: allow
policies:
  - name: allow-exec
    match:
      tool: exec
    rules:
      - action: allow
        when:
          default: true
  - name: block-credential-leaks
    match:
      tool: exec
    rules:
      - action: deny
        when:
          response_matches:
            - "AKIA[0-9A-Z]{16}"
        message: "Sensitive credential detected in response"
`

func TestHTTPToolNameCanonicalizationPreservesPolicyScope(t *testing.T) {
	srv, token, sink := setupTestServer(t, testPolicyYAML, "enforce")
	tests := []struct {
		name       string
		path       string
		wantStatus int
	}{
		{name: "tool endpoint", path: "/v1/tool/Exec", wantStatus: http.StatusForbidden},
		{name: "preflight endpoint", path: "/v1/preflight/EXEC", wantStatus: http.StatusOK},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, test.path,
				strings.NewReader(`{"agent":"main","session":"s1","params":{"command":"rm -rf /"}}`))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()

			srv.handler().ServeHTTP(recorder, req)

			require.Equal(t, test.wantStatus, recorder.Code)
			var response map[string]any
			require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
			require.Equal(t, "deny", response["decision"])
			require.Equal(t, "exec", sink.lastEvent().Tool)
		})
	}
}

type mockSink struct {
	mu     sync.Mutex
	events []audit.Event
}

type failOnWriteSink struct {
	mu     sync.Mutex
	writes int
	failAt int
}

type createAutoRaceResult struct {
	request      *approval.Request
	autoApproved bool
	err          error
}

type createAutoRaceSink struct {
	once   sync.Once
	store  *approval.Store
	call   engine.ToolCall
	result chan createAutoRaceResult
}

func (s *createAutoRaceSink) Write(audit.Event) error {
	s.once.Do(func() {
		go func() {
			request, autoApproved, err := s.store.CreateOrAutoApproved(
				s.call,
				engine.Decision{Action: engine.ActionRequireApproval, Message: "raced bulk publication"},
			)
			s.result <- createAutoRaceResult{request: request, autoApproved: autoApproved, err: err}
		}()
	})
	return nil
}

func (s *createAutoRaceSink) Flush() error { return nil }

func (s *createAutoRaceSink) Close() error { return nil }

func (s *failOnWriteSink) Write(audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes++
	if s.writes == s.failAt {
		return fmt.Errorf("audit storage unavailable")
	}
	return nil
}

func (s *failOnWriteSink) Flush() error { return nil }

func (s *failOnWriteSink) Close() error { return nil }

func (s *failOnWriteSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writes
}

func (m *mockSink) Write(e audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e)
	return nil
}

func (m *mockSink) Flush() error { return nil }

func (m *mockSink) Close() error { return nil }

func (m *mockSink) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

func (m *mockSink) lastEvent() audit.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.events) == 0 {
		return audit.Event{}
	}
	return m.events[len(m.events)-1]
}

func (m *mockSink) snapshot() []audit.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	events := make([]audit.Event, len(m.events))
	copy(events, m.events)
	return events
}

func setupTestServer(t *testing.T, configYAML, mode string) (*Server, string, *mockSink) {
	t.Helper()
	homeDir := t.TempDir()
	return setupTestServerWithHome(t, configYAML, mode, homeDir)
}

func setupTestServerWithHome(t *testing.T, configYAML, mode, homeDir string) (*Server, string, *mockSink) {
	t.Helper()

	dir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)
	policyPath := filepath.Join(dir, "policy.yaml")
	require.NoError(t, os.WriteFile(policyPath, []byte(configYAML), 0o644))

	store := engine.PolicyStore(engine.NewFileStore(policyPath))
	policyDir := filepath.Join(homeDir, ".rampart", "policies")
	if _, err := os.Stat(policyDir); err == nil {
		store = engine.NewMultiStore(policyPath, policyDir, slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil)))
	}
	eng, err := engine.New(store, slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil)))
	require.NoError(t, err)

	sink := &mockSink{}
	token := "test-token"
	srv := New(
		eng,
		sink,
		WithMode(mode),
		WithToken(token),
		WithLogger(slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))),
	)

	return srv, token, sink
}

func postToolCall(t *testing.T, ts *httptest.Server, token string, body string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/tool/exec", bytes.NewBufferString(body))
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func decodeBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()

	var data map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&data))
	return data
}

func TestToolCall_Allow(t *testing.T) {
	srv, token, _ := setupTestServer(t, testPolicyYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	resp := postToolCall(t, ts, token, `{"agent":"main","session":"s1","params":{"command":"git push"}}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body := decodeBody(t, resp)
	assert.Equal(t, "allow", body["decision"])
}

func TestToolCall_CallerEffectiveCommandCannotHideRawCommand(t *testing.T) {
	srv, token, sink := setupTestServer(t, testPolicyYAML, "enforce")
	req := httptest.NewRequest(http.MethodPost, "/v1/tool/exec", strings.NewReader(
		`{"agent":"main","session":"s1","params":{"command":"rm -rf /","command_effective":"echo safe"}}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	srv.handler().ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusForbidden, recorder.Code)
	var response map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	assert.Equal(t, "deny", response["decision"])
	require.Equal(t, 1, sink.count())
	assert.Equal(t, "deny", sink.lastEvent().Decision.Action)
}

func TestToolCall_OnceRuleAuthorizesExactlyOneConcurrentRequest(t *testing.T) {
	srv, token, _ := setupTestServer(t, `
version: "1"
default_action: deny
policies:
  - name: one-shot
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["deploy prod"]
        once: true
`, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	const contenders = 24
	start := make(chan struct{})
	var wg sync.WaitGroup
	var allowed atomic.Int32
	var denied atomic.Int32
	errs := make(chan error, contenders)

	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/tool/exec",
				strings.NewReader(`{"agent":"main","session":"s1","params":{"command":"deploy prod"}}`))
			if err != nil {
				errs <- err
				return
			}
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				errs <- err
				return
			}
			defer resp.Body.Close()
			switch resp.StatusCode {
			case http.StatusOK:
				allowed.Add(1)
			case http.StatusForbidden:
				denied.Add(1)
			default:
				errs <- fmt.Errorf("unexpected status %d", resp.StatusCode)
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	assert.Equal(t, int32(1), allowed.Load(), "a once rule must authorize exactly one request")
	assert.Equal(t, int32(contenders-1), denied.Load())
}

func TestToolCall_Deny(t *testing.T) {
	srv, token, _ := setupTestServer(t, testPolicyYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	resp := postToolCall(t, ts, token, `{"agent":"main","session":"s1","params":{"command":"rm -rf /"}}`)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	body := decodeBody(t, resp)
	assert.Equal(t, "deny", body["decision"])
	assert.NotEmpty(t, body["policy"])
}

func TestToolCall_Log(t *testing.T) {
	srv, token, _ := setupTestServer(t, testPolicyYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	resp := postToolCall(t, ts, token, `{"agent":"main","session":"s1","params":{"command":"sudo reboot"}}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body := decodeBody(t, resp)
	assert.Equal(t, "watch", body["decision"])
}

func TestToolCall_MissingAuth(t *testing.T) {
	srv, _, _ := setupTestServer(t, testPolicyYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	resp := postToolCall(t, ts, "", `{"agent":"main","session":"s1","params":{"command":"git push"}}`)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	body := decodeBody(t, resp)
	assert.Contains(t, body["error"], "missing authorization token")
}

func TestToolCall_InvalidAuth(t *testing.T) {
	srv, _, _ := setupTestServer(t, testPolicyYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	resp := postToolCall(t, ts, "wrong", `{"agent":"main","session":"s1","params":{"command":"git push"}}`)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	body := decodeBody(t, resp)
	assert.Contains(t, body["error"], "invalid authorization token")
}

func TestToolCall_BadBody(t *testing.T) {
	srv, token, _ := setupTestServer(t, testPolicyYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	resp := postToolCall(t, ts, token, `{`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decodeBody(t, resp)
	assert.Contains(t, body["error"], "invalid request body")
}

func TestToolCall_MonitorMode(t *testing.T) {
	srv, token, _ := setupTestServer(t, testPolicyYAML, "monitor")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	resp := postToolCall(t, ts, token, `{"agent":"main","session":"s1","params":{"command":"rm -rf /"}}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body := decodeBody(t, resp)
	assert.Equal(t, "allow", body["decision"])
	assert.Equal(t, true, body["allowed"])
	assert.Equal(t, false, body["enforced"])
	assert.Equal(t, "deny", body["policy_decision"])
}

func TestToolCall_DisabledMode(t *testing.T) {
	srv, token, _ := setupTestServer(t, testPolicyYAML, "disabled")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	resp := postToolCall(t, ts, token, `{"agent":"main","session":"s1","params":{"command":"rm -rf /"}}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body := decodeBody(t, resp)
	assert.Equal(t, "allow", body["decision"])
	assert.Equal(t, "policy evaluation disabled", body["message"])
}

func TestHealthCheck(t *testing.T) {
	srv, _, _ := setupTestServer(t, testPolicyYAML, "monitor")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/healthz")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body := decodeBody(t, resp)
	assert.Equal(t, "rampart", body["service"])
	assert.Equal(t, "ok", body["status"])
	assert.Equal(t, "monitor", body["mode"])
}

func TestNotFound(t *testing.T) {
	srv, _, _ := setupTestServer(t, testPolicyYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/nonexistent")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestToolCall_AuditWritten(t *testing.T) {
	srv, token, sink := setupTestServer(t, testPolicyYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	resp := postToolCall(t, ts, token, `{"agent":"main","session":"sess-1","params":{"command":"git push"}}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_ = decodeBody(t, resp)

	require.Equal(t, 1, sink.count())
	evt := sink.lastEvent()
	assert.Equal(t, "main", evt.Agent)
	assert.Equal(t, "sess-1", evt.Session)
	assert.Equal(t, "exec", evt.Tool)
	assert.Equal(t, "allow", evt.Decision.Action)
}

func TestToolCall_AuditFailureFailsClosedInEnforceMode(t *testing.T) {
	srv, token, _ := setupTestServer(t, testPolicyYAML, "enforce")
	failing := &failOnWriteSink{failAt: 1}
	srv.sink = failing

	req := httptest.NewRequest(http.MethodPost, "/v1/tool/exec",
		strings.NewReader(`{"agent":"main","session":"s1","params":{"command":"git push"}}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	srv.handler().ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "audit storage is unavailable")
	assert.Equal(t, 1, failing.count())
}

func TestToolCall_AuditFailureDoesNotBlockMonitorMode(t *testing.T) {
	srv, token, _ := setupTestServer(t, testPolicyYAML, "monitor")
	failing := &failOnWriteSink{failAt: 1}
	srv.sink = failing

	req := httptest.NewRequest(http.MethodPost, "/v1/tool/exec",
		strings.NewReader(`{"agent":"main","session":"s1","params":{"command":"git push"}}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	srv.handler().ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)
	var response map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	assert.Equal(t, "allow", response["decision"])
	assert.Equal(t, 1, failing.count())
}

func TestToolCall_MonitorModeReportsPolicyDenyWithoutEnforcingIt(t *testing.T) {
	srv, token, sink := setupTestServer(t, testPolicyYAML, "monitor")

	req := httptest.NewRequest(http.MethodPost, "/v1/tool/exec",
		strings.NewReader(`{"agent":"main","session":"s1","params":{"command":"rm -rf /tmp/example"}}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	srv.handler().ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)
	var response map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	assert.Equal(t, true, response["allowed"])
	assert.Equal(t, "allow", response["decision"])
	assert.Equal(t, "deny", response["policy_decision"])
	assert.Equal(t, false, response["enforced"])
	require.Equal(t, 1, sink.count())
	assert.Equal(t, "deny", sink.lastEvent().Decision.Action, "audit retains the observed policy decision")
}

func TestToolCall_AutoApprovalAuditFailureFailsClosed(t *testing.T) {
	srv, token, _ := setupTestServer(t, `
version: "1"
default_action: allow
policies:
  - name: approve-deploy
    match:
      tool: exec
    rules:
      - action: ask
        when:
          command_matches: ["deploy prod"]
`, "enforce")
	failing := &failOnWriteSink{failAt: 2}
	srv.sink = failing
	srv.approvals.AutoApproveRun(engine.ToolCall{Agent: "main", Session: "s1", RunID: "approved-run"}, time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/v1/tool/exec",
		strings.NewReader(`{"agent":"main","session":"s1","run_id":"approved-run","params":{"command":"deploy prod"}}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	srv.handler().ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "audit storage is unavailable")
	assert.Equal(t, 2, failing.count(), "initial ask and final auto-allow decisions should both be attempted")
}

func TestToolCall_AutoApprovalStillEvaluatesResponse(t *testing.T) {
	srv, token, sink := setupTestServer(t, `
version: "1"
default_action: allow
policies:
  - name: approve-deploy
    match:
      tool: exec
    rules:
      - action: ask
        when:
          command_matches: ["deploy prod"]
  - name: block-credential-leaks
    match:
      tool: exec
    rules:
      - action: deny
        when:
          response_matches: ["AKIA[0-9A-Z]{16}"]
`, "enforce")
	srv.approvals.AutoApproveRun(engine.ToolCall{Agent: "main", Session: "s1", RunID: "approved-run"}, time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/v1/tool/exec", strings.NewReader(
		`{"agent":"main","session":"s1","run_id":"approved-run","params":{"command":"deploy prod"},"response":"leaked AKIA1234567890ABCDEF"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	srv.handler().ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)
	var response map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	assert.Equal(t, "deny", response["decision"])
	assert.Equal(t, false, response["allowed"])
	assert.Equal(t, redactedResponse, response["response"])

	events := sink.snapshot()
	require.Len(t, events, 3, "initial ask, auto-allow, and response decisions must all be audited")
	assert.Equal(t, "allow", events[1].Decision.Action)
	assert.Equal(t, "deny", events[2].Decision.Action)
	assert.Equal(t, events[1].ID, events[2].Request["request_audit_id"])
}

func TestToolCall_ApprovedExactReplayIsAllowedOnce(t *testing.T) {
	srv, token, sink := setupTestServer(t, `
version: "1"
default_action: allow
policies:
  - name: approve-deploy
    match:
      tool: exec
    rules:
      - action: ask
        when:
          command_matches: ["deploy prod"]
`, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	body := `{"agent":"main","session":"s1","run_id":"run-exact","tool_call_id":"call-exact","cwd":"/workspace/project","params":{"command":"deploy prod"}}`
	initial := postToolCall(t, ts, token, body)
	require.Equal(t, http.StatusAccepted, initial.StatusCode)
	initialResult := decodeBody(t, initial)
	approvalID, ok := initialResult["approval_id"].(string)
	require.True(t, ok)
	require.NotEmpty(t, approvalID)

	resolveReq, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/approvals/"+approvalID+"/resolve",
		strings.NewReader(`{"approved":true,"resolved_by":"operator"}`))
	require.NoError(t, err)
	resolveReq.Header.Set("Authorization", "Bearer "+token)
	resolveReq.Header.Set("Content-Type", "application/json")
	resolveResp, err := http.DefaultClient.Do(resolveReq)
	require.NoError(t, err)
	defer resolveResp.Body.Close()
	require.Equal(t, http.StatusOK, resolveResp.StatusCode)

	replay := postToolCall(t, ts, token, body)
	require.Equal(t, http.StatusOK, replay.StatusCode)
	replayResult := decodeBody(t, replay)
	assert.Equal(t, true, replayResult["allowed"])
	assert.Equal(t, "allow", replayResult["decision"])
	assert.Equal(t, approvalID, replayResult["approval_id"])
	assert.Equal(t, "approved", replayResult["approval_status"])
	assert.Equal(t, "once", replayResult["approval_scope"])
	assert.Equal(t, "operator", replayResult["approval_resolved_by"])

	events := sink.snapshot()
	require.GreaterOrEqual(t, len(events), 4)
	policyEvent := events[len(events)-2]
	allowEvent := events[len(events)-1]
	assert.Equal(t, "ask", policyEvent.Decision.Action)
	assert.Equal(t, "allow", allowEvent.Decision.Action)
	assert.Equal(t, "run-exact", allowEvent.RunID)
	assert.Equal(t, "call-exact", allowEvent.ToolCallID)
	assert.Equal(t, "/workspace/project", allowEvent.Request["workdir"])
	assert.Equal(t, approvalID, allowEvent.Request["approval_id"])
	assert.Equal(t, "approved", allowEvent.Request["approval_status"])
	assert.Equal(t, "once", allowEvent.Request["approval_scope"])
	assert.Equal(t, "operator", allowEvent.Request["approval_resolved_by"])
	assert.Equal(t, policyEvent.ID, allowEvent.Request["approval_policy_audit_id"])
	assert.Equal(t, policyEvent.ID, replayResult["approval_policy_audit_id"])

	secondReplay := postToolCall(t, ts, token, body)
	require.Equal(t, http.StatusAccepted, secondReplay.StatusCode)
	secondResult := decodeBody(t, secondReplay)
	assert.Equal(t, "pending", secondResult["approval_status"])
	assert.NotEqual(t, approvalID, secondResult["approval_id"], "the consumed grant must not authorize another replay")
	require.Len(t, srv.approvals.List(), 1)
}

func TestToolCall_ResponseDeniedAndRedacted(t *testing.T) {
	srv, token, sink := setupTestServer(t, responsePolicyYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	body := `{"agent":"main","session":"s1","params":{"command":"echo"},"response":"leaked AKIA1234567890ABCDEF"}`
	resp := postToolCall(t, ts, token, body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	data := decodeBody(t, resp)
	assert.Equal(t, false, data["allowed"])
	assert.Equal(t, "deny", data["decision"])
	assert.Equal(t, "Sensitive credential detected in response", data["message"])
	assert.Equal(t, redactedResponse, data["response"])
	assert.Equal(t, "block-credential-leaks", data["policy"])
	require.Equal(t, 2, sink.count())
	events := sink.snapshot()
	responseEvent := events[1]
	assert.Equal(t, "response", responseEvent.Request["rampart_phase"])
	assert.Equal(t, len("leaked AKIA1234567890ABCDEF"), responseEvent.Request["response_bytes"])
	assert.Equal(t, events[0].ID, responseEvent.Request["request_audit_id"])
	assert.Equal(t, "deny", responseEvent.Decision.Action)
	require.NotNil(t, responseEvent.Response)
	assert.Contains(t, responseEvent.Response.Flags, "response-redacted")
}

func TestToolCall_ResponseAllowed(t *testing.T) {
	srv, token, sink := setupTestServer(t, responsePolicyYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	body := `{"agent":"main","session":"s1","params":{"command":"echo"},"response":"all clear"}`
	resp := postToolCall(t, ts, token, body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	data := decodeBody(t, resp)
	assert.Equal(t, "allow", data["decision"])
	assert.Equal(t, "all clear", data["response"])
	require.Equal(t, 2, sink.count())
	events := sink.snapshot()
	responseEvent := events[1]
	assert.Equal(t, "response", responseEvent.Request["rampart_phase"])
	assert.Equal(t, len("all clear"), responseEvent.Request["response_bytes"])
	assert.Equal(t, events[0].ID, responseEvent.Request["request_audit_id"])
	assert.Equal(t, "allow", responseEvent.Decision.Action)
	require.NotNil(t, responseEvent.Response)
	assert.Equal(t, []string{"response-evaluated"}, responseEvent.Response.Flags)
}

func TestToolCall_ResponseAuditFailureFailsClosedInEnforceMode(t *testing.T) {
	srv, token, _ := setupTestServer(t, responsePolicyYAML, "enforce")
	failing := &failOnWriteSink{failAt: 2}
	srv.sink = failing

	req := httptest.NewRequest(http.MethodPost, "/v1/tool/exec",
		strings.NewReader(`{"agent":"main","session":"s1","params":{"command":"echo"},"response":"all clear"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	srv.handler().ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "audit storage is unavailable")
	assert.Equal(t, 2, failing.count())
}

func TestToolCall_ResponseAuditFailureDoesNotBlockMonitorMode(t *testing.T) {
	srv, token, _ := setupTestServer(t, responsePolicyYAML, "monitor")
	failing := &failOnWriteSink{failAt: 2}
	srv.sink = failing

	req := httptest.NewRequest(http.MethodPost, "/v1/tool/exec",
		strings.NewReader(`{"agent":"main","session":"s1","params":{"command":"echo"},"response":"leaked AKIA1234567890ABCDEF"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	srv.handler().ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)
	var response map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	assert.Equal(t, true, response["allowed"])
	assert.Equal(t, "allow", response["decision"])
	assert.Equal(t, "deny", response["response_policy_decision"])
	assert.Equal(t, "leaked AKIA1234567890ABCDEF", response["response"])
	assert.Equal(t, 2, failing.count())
}

func TestPreflightEnforcementHonorsMonitorMode(t *testing.T) {
	srv, token, sink := setupTestServer(t, testPolicyYAML, "monitor")
	req := httptest.NewRequest(http.MethodPost, "/v1/preflight/exec",
		strings.NewReader(`{"agent":"main","session":"s1","run_id":"run-preflight","tool_call_id":"call-preflight","enforce":true,"params":{"command":"rm -rf /tmp/example"}}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	srv.handler().ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)
	var response map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	assert.Equal(t, true, response["allowed"])
	assert.Equal(t, "allow", response["decision"])
	assert.Equal(t, "deny", response["policy_decision"])
	assert.Equal(t, true, response["enforcement_requested"])
	assert.Equal(t, false, response["enforced"])
	require.Equal(t, 1, sink.count())
	assert.Equal(t, "deny", sink.lastEvent().Decision.Action)
	assert.Equal(t, "run-preflight", sink.lastEvent().RunID)
	assert.Equal(t, "call-preflight", sink.lastEvent().ToolCallID)
}

func TestPreflightEnforcementAdvancesCallCount(t *testing.T) {
	srv, token, _ := setupTestServer(t, `
version: "1"
default_action: allow
policies:
  - name: exec-limit
    match:
      tool: exec
    rules:
      - action: deny
        when:
          call_count:
            gte: 2
            window: 1h
`, "enforce")

	post := func(enforce bool) map[string]any {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/v1/preflight/exec",
			strings.NewReader(fmt.Sprintf(`{"agent":"wrapped","session":"wrap","enforce":%t,"params":{"command":"echo safe"}}`, enforce)))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		srv.handler().ServeHTTP(recorder, req)
		require.Equal(t, http.StatusOK, recorder.Code)
		var response map[string]any
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
		return response
	}

	// Preview calls must not spend runtime call-count state.
	require.Equal(t, "allow", post(false)["decision"])
	require.Equal(t, "allow", post(false)["decision"])

	first := post(true)
	second := post(true)
	require.Equal(t, "allow", first["decision"])
	require.Equal(t, true, first["allowed"])
	require.Equal(t, true, first["enforced"])
	require.Equal(t, "deny", second["decision"])
	require.Equal(t, false, second["allowed"])
	require.Equal(t, true, second["enforced"])
}

func TestPreflightEnforcementAuditFailureFailsClosed(t *testing.T) {
	srv, token, _ := setupTestServer(t, testPolicyYAML, "enforce")
	failing := &failOnWriteSink{failAt: 1}
	srv.sink = failing

	req := httptest.NewRequest(http.MethodPost, "/v1/preflight/exec",
		strings.NewReader(`{"agent":"wrapped","session":"wrap","enforce":true,"params":{"command":"git status"}}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	srv.handler().ServeHTTP(recorder, req)

	require.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	var response map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	require.Contains(t, response["error"], "audit storage is unavailable")
	_, assertedEnforced := response["enforced"]
	require.False(t, assertedEnforced, "failed preflight must not assert completed enforcement")
	_, assertedAllowed := response["allowed"]
	require.False(t, assertedAllowed, "failed preflight must not return an executable allow")
	require.Equal(t, 1, failing.count())
}

func TestPreflightInputURLUsesAuthoritativeDerivedDomain(t *testing.T) {
	srv, token, _ := setupTestServer(t, `
version: "1"
default_action: allow
policies:
  - name: block-exfil-domain
    match:
      tool: fetch
    rules:
      - action: deny
        when:
          domain_matches: ["webhook.site"]
`, "enforce")
	req := httptest.NewRequest(http.MethodPost, "/v1/preflight/fetch", strings.NewReader(
		`{"agent":"main","session":"s1","input":{"url":"https://webhook.site/collect","domain":"github.com"}}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	srv.handler().ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)
	var response map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	assert.Equal(t, "deny", response["decision"])
	assert.Equal(t, false, response["allowed"])
}

func TestPreflightTopLevelURLCanonicalization(t *testing.T) {
	const policy = `
version: "1"
default_action: allow
policies:
  - name: block-exfil-domain
    match:
      tool: fetch
    rules:
      - action: deny
        when:
          domain_matches: ["webhook.site"]
`

	t.Run("matching aliases are accepted and domain is URL-derived", func(t *testing.T) {
		srv, token, _ := setupTestServer(t, policy, "enforce")
		req := httptest.NewRequest(http.MethodPost, "/v1/preflight/fetch", strings.NewReader(
			`{"agent":"main","session":"s1","url":"https://webhook.site/collect","params":{"url":"https://webhook.site/collect","domain":"github.com","scheme":"file"}}`))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()

		srv.handler().ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusOK, recorder.Code)
		var response map[string]any
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
		assert.Equal(t, "deny", response["decision"])
		assert.Equal(t, false, response["allowed"])
	})

	t.Run("conflicting aliases are rejected", func(t *testing.T) {
		srv, token, _ := setupTestServer(t, policy, "enforce")
		req := httptest.NewRequest(http.MethodPost, "/v1/preflight/fetch", strings.NewReader(
			`{"agent":"main","session":"s1","url":"https://example.com/safe","input":{"href":"https://webhook.site/collect"}}`))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()

		srv.handler().ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusBadRequest, recorder.Code)
		var response map[string]any
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
		assert.Contains(t, response["error"], "conflicting url aliases")
	})
}

func TestServerTimeouts(t *testing.T) {
	srv, _, _ := setupTestServer(t, testPolicyYAML, "enforce")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	go func() { _ = srv.Serve(ln) }()
	time.Sleep(50 * time.Millisecond)
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	srv.mu.Lock()
	httpSrv := srv.server
	srv.mu.Unlock()

	require.NotNil(t, httpSrv)
	assert.Equal(t, 30*time.Second, httpSrv.ReadTimeout)
	assert.Equal(t, 30*time.Second, httpSrv.WriteTimeout)
	assert.Equal(t, 120*time.Second, httpSrv.IdleTimeout)
}

func TestListenAndServeTimeouts(t *testing.T) {
	srv, _, _ := setupTestServer(t, testPolicyYAML, "enforce")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	ln.Close() // free the port for ListenAndServe

	go func() { _ = srv.ListenAndServe(addr) }()
	// Give it a moment to start
	time.Sleep(50 * time.Millisecond)
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	srv.mu.Lock()
	httpSrv := srv.server
	srv.mu.Unlock()

	require.NotNil(t, httpSrv)
	assert.Equal(t, 30*time.Second, httpSrv.ReadTimeout)
	assert.Equal(t, 30*time.Second, httpSrv.WriteTimeout)
	assert.Equal(t, 120*time.Second, httpSrv.IdleTimeout)
}

func TestShutdownBeforeServeStopsBackgroundResources(t *testing.T) {
	srv, _, _ := setupTestServer(t, testPolicyYAML, "enforce")

	require.NoError(t, srv.Shutdown(context.Background()))
	require.NoError(t, srv.Shutdown(context.Background()), "shutdown must be idempotent")

	select {
	case <-srv.stopCleanup:
	default:
		t.Fatal("expired-rule cleanup stop channel remains open")
	}
}

func TestServeReturnsNilAfterShutdown(t *testing.T) {
	srv, _, _ := setupTestServer(t, testPolicyYAML, "enforce")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(ln) }()
	require.Eventually(t, func() bool {
		srv.mu.Lock()
		defer srv.mu.Unlock()
		return srv.server != nil
	}, time.Second, 5*time.Millisecond)

	require.NoError(t, srv.Shutdown(context.Background()))
	require.NoError(t, <-serveDone)
}

func TestStripLeadingComments(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"no comments", "ls -la", "ls -la"},
		{"single comment", "# list files\nls -la", "ls -la"},
		{"multiple comments", "# step 1\n# step 2\nls -la", "ls -la"},
		{"comment with blank line", "# desc\n\nls -la", "ls -la"},
		{"no stripping needed", "git push origin main", "git push origin main"},
		{"all comments returns empty", "# just a comment\n# another", ""},
		{"inline comment preserved", "ls -la # list files", "ls -la # list files"},
		{"multiline command", "# build\ndocker build -t app .\ndocker push app", "docker build -t app .\ndocker push app"},
		{"empty string", "", ""},
		{"whitespace comment", "  # padded comment\necho hi", "echo hi"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripLeadingComments(tt.input)
			if got != tt.want {
				t.Errorf("stripLeadingComments(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestApprovalResolveURL_UnsignedConfiguredBaseIsSuppressed(t *testing.T) {
	srv := New(nil, nil, WithResolveBaseURL("https://approve.example.com/"), WithToken("test-token"))
	expiresAt := time.Now().Add(5 * time.Minute).UTC()

	got := srv.approvalResolveURL("approval/1", expiresAt)
	assert.Empty(t, got)
}

func TestApprovalResolveURL_UnsignedListenerBaseIsSuppressed(t *testing.T) {
	srv := New(nil, nil, WithToken("test-token"))
	srv.listenAddr = "127.0.0.1:54321"
	expiresAt := time.Now().Add(5 * time.Minute).UTC()

	got := srv.approvalResolveURL("approval-1", expiresAt)
	assert.Empty(t, got)
}

func TestAutoAllowedRuleCreatedSupportsLegacyAndHashedNames(t *testing.T) {
	want := "2026-07-28T12:34:56Z"
	assert.Equal(t, want, autoAllowedRuleCreated("auto-allow-git-push-20260728T123456Z"))
	assert.Equal(t, want, autoAllowedRuleCreated("auto-allow-git-push-20260728T123456Z-0123456789abcdef01234567"))
	assert.Empty(t, autoAllowedRuleCreated("auto-allow-git-push-no-time"))
}

func TestApprovalResolveURL_SignedWhenSignerConfigured(t *testing.T) {
	signer := signing.NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	expiresAt := time.Now().Add(10 * time.Minute).UTC()
	srv := New(
		nil,
		nil,
		WithResolveBaseURL("https://approve.example.com"),
		WithSigner(signer),
		WithToken("test-token"),
	)

	got := srv.approvalResolveURL("approval-1", expiresAt)
	parsed, err := url.Parse(got)
	require.NoError(t, err)

	assert.Equal(t, "https", parsed.Scheme)
	assert.Equal(t, "approve.example.com", parsed.Host)
	assert.Equal(t, "/v1/approvals/approval-1/resolve", parsed.Path)

	sig := parsed.Query().Get("sig")
	exp := parsed.Query().Get("exp")
	require.NotEmpty(t, sig)
	require.NotEmpty(t, exp)
	assert.True(t, signer.ValidateSignature("approval-1", sig, expiresAt.Unix()))
}

func TestResolveApproval_SignedURLBypassesBearerAuth(t *testing.T) {
	eng := buildApprovalEngine(t)
	signer := signing.NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	sink := &mockSink{}
	srv := New(eng, sink, WithToken("secret-token"), WithMode("enforce"), WithSigner(signer))
	handler := srv.handler()

	// Create a pending approval.
	pending, _ := srv.approvals.Create(engine.ToolCall{Tool: "exec"}, engine.Decision{})
	expiresAt := pending.ExpiresAt.UTC()
	signedURL := signer.SignURL("http://localhost", pending.ID, expiresAt)

	// Parse sig and exp from the signed URL.
	parsedURL, err := url.Parse(signedURL)
	require.NoError(t, err)

	// Resolve with signature (no Bearer token).
	body := `{"approved":true,"resolved_by":"impersonated-admin"}`
	resolveURL := fmt.Sprintf("/v1/approvals/%s/resolve?%s", pending.ID, parsedURL.RawQuery)
	req := httptest.NewRequest(http.MethodPost, resolveURL, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Deliberately NOT setting Authorization header.
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "signed URL should bypass Bearer auth")

	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, pending.ID, resp["id"])
	assert.Equal(t, true, resp["approved"])
	resolved, ok := srv.approvals.Get(pending.ID)
	require.True(t, ok)
	assert.Equal(t, "signed-link", resolved.ResolvedBy)
	events := sink.snapshot()
	require.Len(t, events, 1)
	assert.Equal(t, "signed-link", events[0].Request["resolved_by"])
}

func TestResolveApproval_BadSignatureRejected(t *testing.T) {
	eng := buildApprovalEngine(t)
	signer := signing.NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	srv := New(eng, nil, WithToken("secret-token"), WithMode("enforce"), WithSigner(signer))
	handler := srv.handler()

	pending, _ := srv.approvals.Create(engine.ToolCall{Tool: "exec"}, engine.Decision{})

	body := `{"approved":true,"resolved_by":"attacker"}`
	resolveURL := fmt.Sprintf("/v1/approvals/%s/resolve?sig=forged&exp=9999999999", pending.ID)
	req := httptest.NewRequest(http.MethodPost, resolveURL, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code, "forged signature should be rejected")
}

func TestResolveApproval_NoSigFallsThroughToBearerAuth(t *testing.T) {
	eng := buildApprovalEngine(t)
	signer := signing.NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	srv := New(eng, nil, WithToken("secret-token"), WithMode("enforce"), WithSigner(signer))
	handler := srv.handler()

	pending, _ := srv.approvals.Create(engine.ToolCall{Tool: "exec"}, engine.Decision{})

	// No sig params, but valid Bearer token.
	body := `{"approved":true,"resolved_by":"api-user"}`
	resolveURL := fmt.Sprintf("/v1/approvals/%s/resolve", pending.ID)
	req := httptest.NewRequest(http.MethodPost, resolveURL, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret-token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "Bearer token should still work without sig")
}

func TestResolveApproval_RejectsUnsupportedAutomaticPersistence(t *testing.T) {
	eng := buildApprovalEngine(t)
	srv := New(eng, nil, WithToken("secret-token"), WithMode("enforce"))
	handler := srv.handler()

	pending, err := srv.approvals.Create(engine.ToolCall{
		Tool:  "mcp.custom",
		Input: map[string]any{"target": "production"},
	}, engine.Decision{Action: engine.ActionAsk})
	require.NoError(t, err)

	body := `{"approved":true,"resolved_by":"operator","persist":true}`
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/v1/approvals/%s/resolve", pending.ID), strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret-token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "explicit policy")
	unchanged, ok := srv.approvals.Get(pending.ID)
	require.True(t, ok)
	assert.Equal(t, approval.StatusPending, unchanged.Status, "rejected persistence must not consume the pending approval")
}

func TestResolveURLBaseEmptyAddr(t *testing.T) {
	eng := buildApprovalEngine(t)
	srv := New(eng, nil, WithToken("tok"))
	srv.listenAddr = ""
	srv.resolveBaseURL = ""
	assert.Equal(t, "", srv.resolveURLBase(), "empty listen addr should return empty, not fallback")
}

func TestResolveURLBaseFromListenAddr(t *testing.T) {
	eng := buildApprovalEngine(t)
	srv := New(eng, nil, WithToken("tok"))
	srv.listenAddr = ":8080"
	srv.resolveBaseURL = ""
	assert.Equal(t, "http://localhost:8080", srv.resolveURLBase())
}

func TestResolveURLBaseFromTLSListenAddr(t *testing.T) {
	eng := buildApprovalEngine(t)
	srv := New(eng, nil, WithToken("tok"), WithTLS(true))
	srv.listenAddr = "127.0.0.1:8443"
	assert.Equal(t, "https://localhost:8443", srv.resolveURLBase())
}

func TestNewInvalidModeFailsClosedToEnforce(t *testing.T) {
	eng := buildApprovalEngine(t)
	srv := New(eng, nil, WithToken("tok"), WithMode("unexpected"))
	assert.Equal(t, defaultMode, srv.mode)
}

func TestApprovalDoubleResolveReturns410(t *testing.T) {
	eng := buildApprovalEngine(t)
	srv := New(eng, nil, WithToken("secret-token"), WithMode("enforce"))
	handler := srv.handler()

	pending, err := srv.approvals.Create(engine.ToolCall{
		Tool:    "exec",
		Params:  map[string]any{"command": "test"},
		Agent:   "test",
		Session: "s1",
	}, engine.Decision{Action: engine.ActionRequireApproval, Message: "needs approval"})
	require.NoError(t, err)

	body := `{"approved":true,"resolved_by":"test"}`
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/v1/approvals/%s/resolve", pending.ID), strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret-token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/v1/approvals/%s/resolve", pending.ID), strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret-token")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusGone, rr.Code)
}

func buildApprovalEngine(t *testing.T) *engine.Engine {
	t.Helper()
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy.yaml")
	os.WriteFile(policy, []byte("default_action: allow\npolicies: []\n"), 0o644)
	store := engine.NewFileStore(policy)
	eng, err := engine.New(store, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err)
	return eng
}

func TestCreateApproval(t *testing.T) {
	configYAML := `version: "1"
default_action: allow
policies: []`

	srv, token, _ := setupTestServer(t, configYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	body := `{"tool":"exec","command":"kubectl delete pod foo","agent":"claude-code","path":"/tmp","message":"needs approval"}`
	req, err := http.NewRequest("POST", ts.URL+"/v1/approvals", bytes.NewBufferString(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	var result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))

	if result["id"] == nil || result["id"].(string) == "" {
		t.Fatal("expected non-empty approval id")
	}
	if result["status"] != "pending" {
		t.Fatalf("expected pending status, got %v", result["status"])
	}

	// Verify it shows up in GET /v1/approvals/{id}
	approvalID := result["id"].(string)
	getReq, _ := http.NewRequest("GET", ts.URL+"/v1/approvals/"+approvalID, nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	getResp, err := http.DefaultClient.Do(getReq)
	require.NoError(t, err)
	defer getResp.Body.Close()

	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET approval: expected 200, got %d", getResp.StatusCode)
	}

	var getResult map[string]any
	require.NoError(t, json.NewDecoder(getResp.Body).Decode(&getResult))
	if getResult["tool"] != "exec" {
		t.Fatalf("expected tool=exec, got %v", getResult["tool"])
	}
	if getResult["agent"] != "claude-code" {
		t.Fatalf("expected agent=claude-code, got %v", getResult["agent"])
	}
}

func TestOpenClawHostedAskSkipsPendingApprovalCreationForAdmin(t *testing.T) {
	configYAML := `version: "1"
default_action: deny
policies:
  - name: require-human
    match:
      tool: exec
    rules:
      - action: ask
        when:
          command_matches:
            - "sudo *"
        message: "needs approval"
`

	srv, token, _ := setupTestServer(t, configYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	body := `{"agent":"main","session":"discord/direct/test","run_id":"run-1","tool_call_id":"tool-call-1","openclaw_hosted":true,"skip_pending_approval":true,"params":{"command":"sudo true"}}`
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/tool/exec", bytes.NewBufferString(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var got map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, "ask", got["decision"])
	assert.Equal(t, "needs approval", got["message"])
	_, hasApprovalID := got["approval_id"]
	assert.False(t, hasApprovalID, "trusted OpenClaw-hosted evaluation should not create Rampart approval_id")
	assert.Len(t, srv.approvals.List(), 0, "trusted OpenClaw-hosted evaluation should not enqueue Rampart approvals")
	require.Equal(t, 1, srv.sink.(*mockSink).count(), "trusted OpenClaw-hosted evaluation should write one audit event")
	ev := srv.sink.(*mockSink).lastEvent()
	assert.Equal(t, "ask", ev.Decision.Action)
	assert.Equal(t, "exec", ev.Tool)
}

func TestOpenClawHostedAskDoesNotSkipPendingApprovalCreationForAgentToken(t *testing.T) {
	configYAML := `version: "1"
default_action: deny
policies:
  - name: require-human
    match:
      tool: exec
    rules:
      - action: ask
        when:
          command_matches:
            - "sudo *"
        message: "needs approval"
`

	srv, _, _ := setupTestServer(t, configYAML, "enforce")
	dir := t.TempDir()
	tokenStore, err := token.NewStore(filepath.Join(dir, "tokens.json"))
	require.NoError(t, err)
	plaintext, _, err := tokenStore.Create("claude-code", "", "", []string{token.ScopeEval}, nil)
	require.NoError(t, err)
	srv.tokenStore = tokenStore
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	body := `{"agent":"main","session":"discord/direct/test","run_id":"run-1","tool_call_id":"tool-call-1","openclaw_hosted":true,"skip_pending_approval":true,"params":{"command":"sudo true"}}`
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/tool/exec", bytes.NewBufferString(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+plaintext)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusAccepted, resp.StatusCode)

	var got map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, "ask", got["decision"])
	assert.Equal(t, "needs approval", got["message"])
	_, hasApprovalID := got["approval_id"]
	assert.True(t, hasApprovalID, "agent token must still receive Rampart approval_id")
	pending := srv.approvals.List()
	require.Len(t, pending, 1, "agent token must still enqueue Rampart approvals")
	assert.Equal(t, "discord/direct/test", pending[0].Call.Session)
	assert.Equal(t, "run-1", pending[0].Call.RunID)
	assert.Equal(t, "tool-call-1", pending[0].Call.ToolCallID)
}

func TestGenericHostedAskSkipsPendingApprovalCreationForAdmin(t *testing.T) {
	configYAML := `version: "1"
default_action: deny
policies:
  - name: require-human
    match:
      tool: exec
    rules:
      - action: ask
        when:
          command_matches:
            - "sudo *"
        message: "needs approval"
`

	srv, token, sink := setupTestServer(t, configYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	body := `{"agent":"hermes","session":"discord/thread/test","run_id":"run-1","tool_call_id":"tool-call-1","approval_owner":{"host":"hermes","mode":"hosted","surface":"discord","supports_exact_resume":true,"supports_allow_always":true,"supports_result_callback":true},"params":{"command":"sudo true"}}`
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/tool/exec", bytes.NewBufferString(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var got map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, "ask", got["decision"])
	assert.Equal(t, "hosted", got["approval_mode"])
	assert.Equal(t, "tool-call-1", got["tool_call_id"])
	require.NotEmpty(t, got["audit_id"])
	_, hasApprovalID := got["approval_id"]
	assert.False(t, hasApprovalID, "hosted evaluation must not create Rampart approval_id")
	assert.Len(t, srv.approvals.List(), 0, "hosted evaluation must not enqueue Rampart approvals")

	owner, ok := got["approval_owner"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "hermes", owner["host"])
	assert.Equal(t, "hosted", owner["mode"])
	approval, ok := got["approval"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "needs approval", approval["reason"])

	require.Equal(t, 1, sink.count(), "hosted evaluation should write exactly one policy audit event")
	ev := sink.lastEvent()
	assert.Equal(t, got["audit_id"], ev.ID)
	assert.Equal(t, "tool-call-1", ev.ToolCallID)
	assert.Equal(t, "run-1", ev.RunID)
	assert.Equal(t, "ask", ev.Decision.Action)
	require.NotNil(t, ev.ApprovalOwner)
	assert.Equal(t, "hermes", ev.ApprovalOwner["host"])
}

func TestHostedAskRequiresExactResumeForAdmin(t *testing.T) {
	configYAML := `version: "1"
default_action: deny
policies:
  - name: require-human
    match:
      tool: exec
    rules:
      - action: ask
        when:
          command_matches:
            - "sudo *"
        message: "needs approval"
`

	srv, token, _ := setupTestServer(t, configYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	body := `{"agent":"hermes","session":"discord/thread/test","approval_owner":{"host":"hermes","mode":"hosted"},"params":{"command":"sudo true"}}`
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/tool/exec", bytes.NewBufferString(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Len(t, srv.approvals.List(), 0, "invalid hosted request must not fall back to hidden Rampart approval queue")
}

func TestHostedApprovalResolveRecordsAuditWithoutPendingApproval(t *testing.T) {
	srv, token, sink := setupTestServer(t, testPolicyYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	body := `{"agent":"hermes","session":"discord/thread/test","run_id":"run-1","tool":"exec","tool_call_id":"tool-call-1","host_approval_id":"hermes-approval-1","approval_owner":{"host":"hermes","mode":"hosted","surface":"discord","supports_exact_resume":true},"outcome":"approved","scope":"once","resolved_by":"operator","message":"approved in Hermes"}`
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/hosted-approvals/audit-1/resolve", bytes.NewBufferString(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var got map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, "audit-1", got["audit_id"])
	assert.Equal(t, "recorded", got["status"])
	assert.Equal(t, "approved", got["outcome"])
	assert.Len(t, srv.approvals.List(), 0, "hosted resolution callback must not create Rampart pending approvals")

	require.Equal(t, 1, sink.count())
	ev := sink.lastEvent()
	assert.Equal(t, "exec", ev.Tool)
	assert.Equal(t, "tool-call-1", ev.ToolCallID)
	assert.Equal(t, "run-1", ev.RunID)
	assert.Equal(t, "approved", ev.Decision.Action)
	assert.Equal(t, "approved in Hermes", ev.Decision.Message)
	assert.Equal(t, "hosted_approval_resolved", ev.Request["action"])
	assert.Equal(t, "audit-1", ev.Request["audit_id"])
	assert.Equal(t, "hermes-approval-1", ev.Request["host_approval_id"])
}

func TestUserOverridesBypassApprovalQueue(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("USERPROFILE", tmpHome)
	overridesDir := filepath.Join(tmpHome, ".rampart", "policies")
	require.NoError(t, os.MkdirAll(overridesDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(overridesDir, "user-overrides.yaml"), []byte(`# Rampart user override policies
policies:
  - name: user-allow-local-api
    match:
      tool:
        - exec
    rules:
      - when:
          command_matches: ['curl -fsS http://192.0.2.10:8989/api/v3/system/status']
        action: allow
        message: User allowed (always)
`), 0o644))

	configYAML := `version: "1"
default_action: deny
policies:
  - name: require-human
    match:
      tool: exec
    rules:
      - action: ask
        when:
          command_matches:
            - "curl *"
        message: "needs approval"
`

	srv, token, sink := setupTestServerWithHome(t, configYAML, "enforce", tmpHome)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	body := `{"agent":"main","session":"discord/direct/test","params":{"command":"curl -fsS http://192.0.2.10:8989/api/v3/system/status"}}`
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/tool/exec", bytes.NewBufferString(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var got map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, "allow", got["decision"])
	assert.Equal(t, "user-allow-local-api", got["policy"])
	assert.Len(t, srv.approvals.List(), 0, "durable user overrides should bypass approval queue")
	assert.Equal(t, 1, sink.count(), "durable user override should write exactly one audit event")
	assert.Equal(t, "allow", sink.lastEvent().Decision.Action)
}

func TestResolveApproval_AuditTrail(t *testing.T) {
	tests := []struct {
		name           string
		approved       bool
		persist        bool
		wantResolution string
	}{
		{"approved", true, false, "approved"},
		{"denied", false, false, "denied"},
		{"persisted_allow", true, true, "approved"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			eng := buildApprovalEngine(t)
			sink := &mockSink{}
			srv := New(eng, sink, WithToken("tok"), WithMode("enforce"),
				WithLogger(slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))))
			handler := srv.handler()

			pending, err := srv.approvals.Create(engine.ToolCall{
				Tool:    "exec",
				Params:  map[string]any{"command": "rm -rf /tmp/test"},
				Agent:   "claude",
				Session: "s1",
			}, engine.Decision{Action: engine.ActionRequireApproval, Message: "needs approval"})
			require.NoError(t, err)

			body := fmt.Sprintf(`{"approved":%t,"resolved_by":"dashboard","persist":%t}`, tt.approved, tt.persist)
			req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/v1/approvals/%s/resolve", pending.ID), strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer tok")
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code)

			// The decision event is always honest about what existed at its
			// publication boundary. A durable request receives a second audit
			// record authorizing the later policy transaction; it never rewrites
			// the resolution event into a premature "always_allowed" claim.
			events := sink.snapshot()
			require.NotEmpty(t, events, "expected at least one audit event")
			resolution := events[0]
			assert.Equal(t, "approval_resolved", resolution.Request["action"])
			assert.Equal(t, "exec", resolution.Request["tool"])
			assert.Equal(t, tt.wantResolution, resolution.Request["resolution"])
			assert.Equal(t, "dashboard", resolution.Request["resolved_by"])
			assert.Equal(t, pending.ID, resolution.Request["approval_id"])
			assert.Equal(t, tt.approved && tt.persist, resolution.Request["persist_requested"])
			assert.Equal(t, false, resolution.Request["persist"])
			if tt.approved && tt.persist {
				require.Len(t, events, 2)
				assert.Equal(t, "approval_persistence_authorized", events[1].Request["action"])
				assert.Equal(t, pending.ID, events[1].Request["approval_id"])
				assert.Equal(t, "authorized", events[1].Decision.Action)
			}
		})
	}
}

func TestResolveApproval_PersistFailureIsNotReportedAsAlwaysAllowed(t *testing.T) {
	homeFile := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(homeFile, []byte("blocked"), 0o600))
	t.Setenv("HOME", homeFile)
	t.Setenv("USERPROFILE", homeFile)

	eng := buildApprovalEngine(t)
	sink := &mockSink{}
	srv := New(eng, sink, WithToken("tok"), WithMode("enforce"),
		WithLogger(slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))))
	pending, err := srv.approvals.Create(engine.ToolCall{
		Tool:    "exec",
		Params:  map[string]any{"command": "git status"},
		Agent:   "claude",
		Session: "s1",
	}, engine.Decision{Action: engine.ActionRequireApproval, Message: "needs approval"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/v1/approvals/%s/resolve", pending.ID),
		strings.NewReader(`{"approved":true,"resolved_by":"dashboard","persist":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer tok")
	recorder := httptest.NewRecorder()
	srv.handler().ServeHTTP(recorder, req)

	require.Equal(t, http.StatusOK, recorder.Code)
	var response map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	assert.Equal(t, false, response["persisted"])
	resolved, ok := srv.approvals.Get(pending.ID)
	require.True(t, ok)
	assert.False(t, resolved.Persisted)
	events := sink.snapshot()
	require.Len(t, events, 2)
	assert.Equal(t, "approved", events[0].Request["resolution"])
	assert.Equal(t, true, events[0].Request["persist_requested"])
	assert.Equal(t, false, events[0].Request["persist"])
	assert.Equal(t, "approval_persistence_authorized", events[1].Request["action"])
	assert.Equal(t, "authorized", events[1].Decision.Action)
}

func TestResolveApproval_AuditFailureLeavesApprovalPendingAndUnusable(t *testing.T) {
	eng := buildApprovalEngine(t)
	failing := &failOnWriteSink{failAt: 1}
	srv := New(eng, failing, WithToken("tok"), WithMode("enforce"),
		WithLogger(slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))))
	call := engine.ToolCall{
		Tool:       "exec",
		Params:     map[string]any{"command": "deploy prod"},
		Agent:      "claude",
		Session:    "s1",
		RunID:      "run-audit-failure",
		ToolCallID: "call-audit-failure",
	}
	pending, err := srv.approvals.Create(call, engine.Decision{Action: engine.ActionRequireApproval})
	require.NoError(t, err)

	resolve := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/v1/approvals/%s/resolve", pending.ID),
			strings.NewReader(`{"approved":true,"resolved_by":"dashboard"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer tok")
		recorder := httptest.NewRecorder()
		srv.handler().ServeHTTP(recorder, req)
		return recorder
	}

	recorder := resolve()
	assert.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	current, ok := srv.approvals.Get(pending.ID)
	require.True(t, ok)
	assert.Equal(t, approval.StatusPending, current.Status)
	select {
	case <-pending.Done():
		t.Fatal("audit failure woke the approval waiter")
	default:
	}
	grant, consumed, consumeErr := srv.approvals.ConsumeApproved(call)
	require.NoError(t, consumeErr)
	assert.False(t, consumed)
	assert.Nil(t, grant)

	// The same approval remains retryable once durable audit storage returns.
	srv.sink = &mockSink{}
	recorder = resolve()
	assert.Equal(t, http.StatusOK, recorder.Code)
	grant, consumed, consumeErr = srv.approvals.ConsumeApproved(call)
	require.NoError(t, consumeErr)
	require.True(t, consumed)
	assert.Equal(t, pending.ID, grant.ID)
}

func TestResolveApproval_DurableAuditFailureKeepsOneTimeApprovalButSkipsPolicy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	eng := buildApprovalEngine(t)
	// The resolution audit succeeds; the separate durable-authorization audit fails.
	failing := &failOnWriteSink{failAt: 2}
	srv := New(eng, failing, WithToken("tok"), WithMode("enforce"),
		WithLogger(slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))))
	call := engine.ToolCall{
		Tool:       "exec",
		Params:     map[string]any{"command": "git status"},
		Agent:      "claude",
		Session:    "s1",
		RunID:      "run-persist-audit-failure",
		ToolCallID: "call-persist-audit-failure",
	}
	pending, err := srv.approvals.Create(call, engine.Decision{Action: engine.ActionRequireApproval})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/v1/approvals/%s/resolve", pending.ID),
		strings.NewReader(`{"approved":true,"resolved_by":"dashboard","persist":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer tok")
	recorder := httptest.NewRecorder()
	srv.handler().ServeHTTP(recorder, req)

	require.Equal(t, http.StatusOK, recorder.Code)
	var response map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	assert.Equal(t, false, response["persisted"])
	current, ok := srv.approvals.Get(pending.ID)
	require.True(t, ok)
	assert.Equal(t, approval.StatusApproved, current.Status)
	assert.False(t, current.Persisted)
	assert.Equal(t, 2, failing.count())
	_, statErr := os.Stat(engine.DefaultAutoAllowedPath())
	assert.True(t, os.IsNotExist(statErr), "durable rule was installed without its required audit record")

	grant, consumed, consumeErr := srv.approvals.ConsumeApproved(call)
	require.NoError(t, consumeErr)
	require.True(t, consumed, "failed durable persistence must preserve the already-audited one-time approval")
	assert.Equal(t, pending.ID, grant.ID)
}

func TestBulkResolve_AuditFailureDoesNotInstallAutoApproval(t *testing.T) {
	eng := buildApprovalEngine(t)
	failing := &failOnWriteSink{failAt: 2}
	srv := New(eng, failing, WithToken("tok"), WithMode("enforce"),
		WithLogger(slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))))

	calls := []engine.ToolCall{
		{Tool: "exec", Params: map[string]any{"command": "deploy one"}, Agent: "claude", Session: "s1", RunID: "run-bulk", ToolCallID: "call-one"},
		{Tool: "exec", Params: map[string]any{"command": "deploy two"}, Agent: "claude", Session: "s1", RunID: "run-bulk", ToolCallID: "call-two"},
	}
	requests := make([]*approval.Request, 0, len(calls))
	for _, call := range calls {
		pending, err := srv.approvals.Create(call, engine.Decision{Action: engine.ActionRequireApproval})
		require.NoError(t, err)
		requests = append(requests, pending)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/approvals/bulk-resolve",
		strings.NewReader(`{"agent":"claude","session":"s1","run_id":"run-bulk","action":"approve","resolved_by":"dashboard"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer tok")
	recorder := httptest.NewRecorder()
	srv.handler().ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	assert.Equal(t, 2, failing.count())
	approvedCount := 0
	pendingCount := 0
	for _, request := range requests {
		current, ok := srv.approvals.Get(request.ID)
		require.True(t, ok)
		switch current.Status {
		case approval.StatusApproved:
			approvedCount++
		case approval.StatusPending:
			pendingCount++
		}
	}
	assert.Equal(t, 1, approvedCount, "only the individually journaled and audited approval may publish")
	assert.Equal(t, 1, pendingCount, "the approval whose audit failed must remain pending")
	assert.False(t, srv.approvals.IsAutoApproved(calls[0]), "partial bulk resolution installed future authorization")
}

func TestBulkResolve_ConcurrentCreateCannotLeaveOrphanPending(t *testing.T) {
	eng := buildApprovalEngine(t)
	srv := New(eng, nil, WithToken("tok"), WithMode("enforce"),
		WithLogger(slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))))
	initial := engine.ToolCall{
		Tool:       "exec",
		Params:     map[string]any{"command": "deploy initial"},
		Agent:      "claude",
		Session:    "s1",
		RunID:      "run-create-race",
		ToolCallID: "call-initial",
	}
	_, err := srv.approvals.Create(initial, engine.Decision{Action: engine.ActionRequireApproval})
	require.NoError(t, err)

	racedCall := initial
	racedCall.Params = map[string]any{"command": "deploy raced"}
	racedCall.ToolCallID = "call-raced"
	tracingSink := &createAutoRaceSink{
		store:  srv.approvals,
		call:   racedCall,
		result: make(chan createAutoRaceResult, 1),
	}
	srv.sink = tracingSink

	req := httptest.NewRequest(http.MethodPost, "/v1/approvals/bulk-resolve",
		strings.NewReader(`{"agent":"claude","session":"s1","run_id":"run-create-race","action":"approve","resolved_by":"dashboard"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer tok")
	recorder := httptest.NewRecorder()
	srv.handler().ServeHTTP(recorder, req)

	require.Equal(t, http.StatusOK, recorder.Code)
	var raced createAutoRaceResult
	select {
	case raced = <-tracingSink.result:
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent create did not complete")
	}
	require.NoError(t, raced.err)
	if raced.autoApproved {
		assert.Nil(t, raced.request)
	} else {
		require.NotNil(t, raced.request)
		resolved, ok := srv.approvals.Get(raced.request.ID)
		require.True(t, ok)
		assert.Equal(t, approval.StatusApproved, resolved.Status, "creation won the race but bulk publication did not catch it")
	}
	assert.Empty(t, srv.approvals.List(), "bulk publication left an orphan same-scope approval pending")
	assert.True(t, srv.approvals.IsAutoApproved(racedCall))
}

// TestGetPolicy is removed — GET /v1/policy was removed in v0.9.9.
// Use GET /v1/status for status info, GET /v1/policies for full policy detail.

func TestGetStatus(t *testing.T) {
	srv, token, _ := setupTestServer(t, testPolicyYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	// Simulate a few PreToolUse calls.
	resp1 := postToolCall(t, ts, token, `{"agent":"main","session":"s1","params":{"command":"git status"}}`)
	assert.Equal(t, http.StatusOK, resp1.StatusCode)
	resp2 := postToolCall(t, ts, token, `{"agent":"main","session":"s1","params":{"command":"git log"}}`)
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/v1/status", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	callCounts, ok := body["call_counts"].(map[string]any)
	require.True(t, ok, "call_counts should be an object")
	count, ok := callCounts["exec"].(float64)
	require.True(t, ok, "exec count should be a number")
	assert.GreaterOrEqual(t, int(count), 2)
}

// TestGetPolicy_NoAuth is removed — GET /v1/policy was removed in v0.9.9.

func TestPolicySummaryEndpoint(t *testing.T) {
	srv, token, _ := setupTestServer(t, testPolicyYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/v1/policy/summary", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		DefaultAction string `json:"default_action"`
		Rules         []struct {
			Name    string `json:"name"`
			Action  string `json:"action"`
			Summary string `json:"summary"`
		} `json:"rules"`
		Summary string `json:"summary"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	assert.Equal(t, "allow", body.DefaultAction)
	assert.NotEmpty(t, body.Summary)
	require.Len(t, body.Rules, 3)
	assert.Equal(t, "block-destructive", body.Rules[0].Name)
	assert.Equal(t, "deny", body.Rules[0].Action)
	assert.Equal(t, "destructive command blocked", body.Rules[0].Summary)
}

func TestCreateApproval_NoAuth(t *testing.T) {
	configYAML := `version: "1"
default_action: allow
policies: []`

	srv, _, _ := setupTestServer(t, configYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	body := `{"tool":"exec","command":"echo hi","agent":"test","message":"test"}`
	req, err := http.NewRequest("POST", ts.URL+"/v1/approvals", bytes.NewBufferString(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

// TestHandleTest_HTTP covers the POST /v1/test endpoint that powers the policy REPL.
func TestHandleTest_HTTP(t *testing.T) {
	srv, token, _ := setupTestServer(t, testPolicyYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	postTest := func(t *testing.T, body string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/test", bytes.NewBufferString(body))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}

	t.Run("deny command returns deny action", func(t *testing.T) {
		resp := postTest(t, `{"command":"rm -rf /","tool":"exec"}`)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		var result map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
		assert.Equal(t, "deny", result["action"])
		assert.Equal(t, "rm -rf /", result["command"])
		assert.Equal(t, "exec", result["tool"])
	})

	t.Run("allowed command returns allow action", func(t *testing.T) {
		resp := postTest(t, `{"command":"git status","tool":"exec"}`)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		var result map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
		assert.Equal(t, "allow", result["action"])
	})

	t.Run("defaults to exec tool when omitted", func(t *testing.T) {
		resp := postTest(t, `{"command":"git status"}`)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		var result map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
		assert.Equal(t, "exec", result["tool"])
	})

	t.Run("missing command returns 400", func(t *testing.T) {
		resp := postTest(t, `{"tool":"exec"}`)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("invalid JSON returns 400", func(t *testing.T) {
		resp := postTest(t, `not json`)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("no auth returns 401", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/test", bytes.NewBufferString(`{"command":"git status"}`))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("response includes policy_scope field", func(t *testing.T) {
		resp := postTest(t, `{"command":"git log","tool":"exec"}`)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		var result map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
		assert.Equal(t, "global", result["policy_scope"])
	})

	t.Run("read tool uses path param", func(t *testing.T) {
		// Using read tool — command is treated as path.
		resp := postTest(t, `{"command":"/etc/passwd","tool":"read"}`)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		var result map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
		// action could be allow or deny depending on policy, but the response is valid
		assert.NotEmpty(t, result["action"])
	})
}

// ── W2: Bulk resolve + auto-approve cache ──────────────────────────────────

func TestBulkResolve_ApprovesAllInRun(t *testing.T) {
	configYAML := `version: "1"
default_action: allow
policies: []`

	srv, token, sink := setupTestServer(t, configYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	runID := "run-test-abc123"

	// Create two approvals with the same run_id.
	createApproval := func(agent, cmd string) string {
		body := fmt.Sprintf(`{"tool":"exec","command":%q,"agent":%q,"run_id":%q,"message":"needs approval"}`, cmd, agent, runID)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/approvals", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		var result map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
		return result["id"].(string)
	}

	id1 := createApproval("claude-code", "rm -rf /tmp/a")
	id2 := createApproval("claude-code", "rm -rf /tmp/b")
	collidingID := createApproval("codex", "rm -rf /tmp/c")

	// Bulk-resolve: approve the run.
	bulkBody := fmt.Sprintf(`{"agent":"claude-code","session":"hook","run_id":%q,"action":"approve","resolved_by":"test"}`, runID)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/approvals/bulk-resolve", strings.NewReader(bulkBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var bulkResult map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&bulkResult))
	assert.Equal(t, float64(2), bulkResult["resolved"])

	ids, ok := bulkResult["ids"].([]any)
	require.True(t, ok)
	assert.Len(t, ids, 2)
	gotIDs := map[string]bool{ids[0].(string): true, ids[1].(string): true}
	assert.True(t, gotIDs[id1], "id1 should be in resolved ids")
	assert.True(t, gotIDs[id2], "id2 should be in resolved ids")

	// Both approvals should now be resolved.
	getStatus := func(id string) string {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/approvals/"+id, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return ""
		}
		defer resp.Body.Close()
		var r map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&r)
		s, _ := r["status"].(string)
		return s
	}
	assert.Equal(t, "approved", getStatus(id1))
	assert.Equal(t, "approved", getStatus(id2))
	assert.Equal(t, "pending", getStatus(collidingID), "same run_id in another agent scope must remain pending")
	events := sink.snapshot()
	require.Len(t, events, 2)
	for _, event := range events {
		assert.Equal(t, true, event.Request["bulk"])
		assert.Equal(t, true, event.Request["auto_approve"])
		assert.NotZero(t, event.Request["auto_approve_ttl_seconds"])
		assert.Equal(t, runID, event.RunID)
	}
}

func TestBulkResolve_EmptyRunIDRejected(t *testing.T) {
	configYAML := `version: "1"
default_action: allow
policies: []`

	srv, token, _ := setupTestServer(t, configYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	// Every identity field is required — never batch-resolve a caller-selected
	// run ID across agents or sessions.
	for _, body := range []string{
		`{"agent":"","session":"hook","run_id":"run","action":"approve"}`,
		`{"agent":"claude-code","session":"","run_id":"run","action":"approve"}`,
		`{"agent":"claude-code","session":"hook","run_id":"","action":"approve"}`,
		`{"agent":"claude-code","session":"hook","run_id":"   ","action":"approve"}`,
		`{"action":"approve"}`,
	} {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/approvals/bulk-resolve", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "body: %s", body)
	}
}

func TestBulkResolve_NoAuth(t *testing.T) {
	configYAML := `version: "1"
default_action: allow
policies: []`

	srv, _, _ := setupTestServer(t, configYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/approvals/bulk-resolve",
		strings.NewReader(`{"agent":"claude-code","session":"hook","run_id":"x","action":"approve"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestBulkResolve_ZeroResolved_WhenNoPendingForRun(t *testing.T) {
	configYAML := `version: "1"
default_action: allow
policies: []`

	srv, token, _ := setupTestServer(t, configYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	// Bulk-resolve a run that has no pending approvals.
	body := `{"agent":"claude-code","session":"hook","run_id":"run-nonexistent","action":"approve"}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/approvals/bulk-resolve", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	assert.Equal(t, float64(0), result["resolved"])
	// ids should be an empty array, not null.
	ids, ok := result["ids"].([]any)
	assert.True(t, ok, "ids should be a JSON array")
	assert.Empty(t, ids)
}

func TestAutoApproveCache_SubsequentCallsSkipQueue(t *testing.T) {
	configYAML := `version: "1"
default_action: allow
policies: []`

	srv, token, _ := setupTestServer(t, configYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	runID := "run-auto-approve-test"

	// Create and bulk-approve two approvals to seed the auto-approve cache.
	for _, cmd := range []string{"rm /tmp/x", "rm /tmp/y"} {
		body := fmt.Sprintf(`{"tool":"exec","command":%q,"agent":"claude-code","run_id":%q,"message":"needs approval"}`, cmd, runID)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/approvals", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()
	}

	bulkBody := fmt.Sprintf(`{"agent":"claude-code","session":"hook","run_id":%q,"action":"approve"}`, runID)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/approvals/bulk-resolve", strings.NewReader(bulkBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()

	// Now a NEW approval from the same run should be auto-approved (status="approved", not "pending").
	newBody := fmt.Sprintf(`{"tool":"exec","command":"rm /tmp/z","agent":"claude-code","run_id":%q,"message":"new call"}`, runID)
	req2, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/approvals", strings.NewReader(newBody))
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()

	assert.Equal(t, http.StatusOK, resp2.StatusCode, "auto-approved should return 200 not 201")
	var result map[string]any
	require.NoError(t, json.NewDecoder(resp2.Body).Decode(&result))
	assert.Equal(t, "approved", result["status"], "subsequent call from auto-approved run should be auto-approved")

	// A run ID is caller-selected and may collide across agents. The cached
	// approval must not authorize a different identity using the same value.
	collisionBody := fmt.Sprintf(`{"tool":"exec","command":"rm /tmp/other","agent":"codex","run_id":%q,"message":"colliding run"}`, runID)
	collisionReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/approvals", strings.NewReader(collisionBody))
	collisionReq.Header.Set("Authorization", "Bearer "+token)
	collisionReq.Header.Set("Content-Type", "application/json")
	collisionResp, err := http.DefaultClient.Do(collisionReq)
	require.NoError(t, err)
	defer collisionResp.Body.Close()
	assert.Equal(t, http.StatusCreated, collisionResp.StatusCode)
	collisionResult := decodeBody(t, collisionResp)
	assert.Equal(t, "pending", collisionResult["status"])
}

// ── W3: run_groups in list response ───────────────────────────────────────

func TestListApprovals_RunGroups(t *testing.T) {
	configYAML := `version: "1"
default_action: allow
policies: []`

	srv, token, _ := setupTestServer(t, configYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	runID := "run-group-test-xyz"

	// Create a two-item exact scope, one colliding run ID in another agent, and
	// one solo approval. Only the exact scope should form a group.
	createApproval := func(agent, cmd, rid string) {
		body := fmt.Sprintf(`{"tool":"exec","command":%q,"agent":%q,"run_id":%q,"message":"approval"}`, cmd, agent, rid)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/approvals", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()
	}

	createApproval("claude-code", "cmd-a", runID)
	time.Sleep(5 * time.Millisecond) // ensure distinct created_at ordering
	createApproval("claude-code", "cmd-b", runID)
	createApproval("codex", "cmd-collision", runID)
	createApproval("claude-code", "cmd-solo", "") // no run_id — should not appear in run_groups

	// List approvals.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/approvals", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))

	// run_groups must be present.
	runGroups, ok := result["run_groups"].([]any)
	require.True(t, ok, "run_groups should be a JSON array")

	require.Len(t, runGroups, 1, "colliding run IDs in distinct agent scopes must not be co-grouped")
	// Exactly one group with our complete scope.
	var found map[string]any
	for _, g := range runGroups {
		group := g.(map[string]any)
		if group["agent"] == "claude-code" && group["session"] == "hook" && group["run_id"] == runID {
			found = group
			break
		}
	}
	require.NotNil(t, found, "run_id %q should appear in run_groups", runID)
	assert.Equal(t, "claude-code", found["agent"])
	assert.Equal(t, "hook", found["session"])
	assert.Equal(t, float64(2), found["count"])
	assert.NotEmpty(t, found["earliest_created_at"])

	items, ok := found["items"].([]any)
	require.True(t, ok)
	assert.Len(t, items, 2)

	// Solo approval should not create a group.
	for _, g := range runGroups {
		group := g.(map[string]any)
		assert.NotEqual(t, "", group["run_id"], "solo (empty run_id) should not appear in run_groups")
	}

	// Flat approvals array should still have all 4 items.
	approvals, ok := result["approvals"].([]any)
	require.True(t, ok)
	assert.Len(t, approvals, 4)
}

func TestListApprovals_RunGroupsSortedByEarliestCreatedAt(t *testing.T) {
	configYAML := `version: "1"
default_action: allow
policies: []`

	srv, token, _ := setupTestServer(t, configYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	// Create two groups: group B created first, group A created second.
	// run_groups should return B before A (chronological, not by run_id).
	// Use distinct commands per group to avoid deduplication.
	createPair := func(runID, cmdPrefix string) {
		for i, cmd := range []string{cmdPrefix + "-1", cmdPrefix + "-2"} {
			_ = i
			body := fmt.Sprintf(`{"tool":"exec","command":%q,"agent":"claude-code","run_id":%q,"message":"m"}`, cmd, runID)
			req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/approvals", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			resp, _ := http.DefaultClient.Do(req)
			resp.Body.Close()
		}
	}

	createPair("run-B", "sort-b-cmd")
	time.Sleep(10 * time.Millisecond)
	createPair("run-A", "sort-a-cmd")

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/approvals", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	var result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))

	runGroups := result["run_groups"].([]any)
	require.Len(t, runGroups, 2)

	first := runGroups[0].(map[string]any)["run_id"].(string)
	second := runGroups[1].(map[string]any)["run_id"].(string)
	assert.Equal(t, "run-B", first, "group created first should sort first")
	assert.Equal(t, "run-A", second)
}

func TestNotificationActionMatchesApprovalAliases(t *testing.T) {
	for _, configured := range []string{"ask", "require_approval"} {
		for _, actual := range []string{"ask", "require_approval"} {
			if !notificationActionMatches(configured, actual) {
				t.Errorf("notificationActionMatches(%q, %q) = false, want true", configured, actual)
			}
		}
	}
	if notificationActionMatches("deny", "ask") {
		t.Fatal("deny notification filter must not match ask")
	}
	for _, configured := range []string{"watch", "log"} {
		for _, actual := range []string{"watch", "log"} {
			if !notificationActionMatches(configured, actual) {
				t.Errorf("notificationActionMatches(%q, %q) = false, want true", configured, actual)
			}
		}
	}
}
