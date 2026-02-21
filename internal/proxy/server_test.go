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
	"testing"
	"time"

	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/internal/signing"
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

type mockSink struct {
	mu     sync.Mutex
	events []audit.Event
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

func setupTestServer(t *testing.T, configYAML, mode string) (*Server, string, *mockSink) {
	t.Helper()

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	require.NoError(t, os.WriteFile(policyPath, []byte(configYAML), 0o644))

	store := engine.NewFileStore(policyPath)
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
	assert.Contains(t, body["error"], "missing authorization header")
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
	assert.Equal(t, "deny", body["decision"])
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

func TestToolCall_ResponseDeniedAndRedacted(t *testing.T) {
	srv, token, _ := setupTestServer(t, responsePolicyYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	body := `{"agent":"main","session":"s1","params":{"command":"echo"},"response":"leaked AKIA1234567890ABCDEF"}`
	resp := postToolCall(t, ts, token, body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	data := decodeBody(t, resp)
	assert.Equal(t, "deny", data["decision"])
	assert.Equal(t, "Sensitive credential detected in response", data["message"])
	assert.Equal(t, redactedResponse, data["response"])
	assert.Equal(t, "block-credential-leaks", data["policy"])
}

func TestToolCall_ResponseAllowed(t *testing.T) {
	srv, token, _ := setupTestServer(t, responsePolicyYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	body := `{"agent":"main","session":"s1","params":{"command":"echo"},"response":"all clear"}`
	resp := postToolCall(t, ts, token, body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	data := decodeBody(t, resp)
	assert.Equal(t, "allow", data["decision"])
	assert.Equal(t, "all clear", data["response"])
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

func TestApprovalResolveURL_UsesConfiguredBaseURL(t *testing.T) {
	srv := New(nil, nil, WithResolveBaseURL("https://approve.example.com/"), WithToken("test-token"))
	expiresAt := time.Now().Add(5 * time.Minute).UTC()

	got := srv.approvalResolveURL("approval/1", expiresAt)
	want := "https://approve.example.com/v1/approvals/approval%2F1/resolve"
	assert.Equal(t, want, got)
}

func TestApprovalResolveURL_FallbacksToLocalhostWithListenerPort(t *testing.T) {
	srv := New(nil, nil, WithToken("test-token"))
	srv.listenAddr = "127.0.0.1:54321"
	expiresAt := time.Now().Add(5 * time.Minute).UTC()

	got := srv.approvalResolveURL("approval-1", expiresAt)
	want := "http://localhost:54321/v1/approvals/approval-1/resolve"
	assert.Equal(t, want, got)
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
	srv := New(eng, nil, WithToken("secret-token"), WithMode("enforce"), WithSigner(signer))
	handler := srv.handler()

	// Create a pending approval.
	pending, _ := srv.approvals.Create(engine.ToolCall{Tool: "exec"}, engine.Decision{})
	expiresAt := pending.ExpiresAt.UTC()
	signedURL := signer.SignURL("http://localhost", pending.ID, expiresAt)

	// Parse sig and exp from the signed URL.
	parsedURL, err := url.Parse(signedURL)
	require.NoError(t, err)

	// Resolve with signature (no Bearer token).
	body := `{"approved":true,"resolved_by":"discord-user"}`
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

func TestResolveApproval_AuditTrail(t *testing.T) {
	tests := []struct {
		name           string
		approved       bool
		persist        bool
		wantResolution string
	}{
		{"approved", true, false, "approved"},
		{"denied", false, false, "denied"},
		{"always_allowed", true, true, "always_allowed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

			// Verify audit event was written.
			require.GreaterOrEqual(t, sink.count(), 1, "expected at least one audit event")
			last := sink.lastEvent()
			assert.Equal(t, "approval_resolved", last.Request["action"])
			assert.Equal(t, "exec", last.Request["tool"])
			assert.Equal(t, tt.wantResolution, last.Request["resolution"])
			assert.Equal(t, "dashboard", last.Request["resolved_by"])
			assert.Equal(t, pending.ID, last.Request["approval_id"])
			assert.Equal(t, tt.approved && tt.persist, last.Request["persist"])
		})
	}
}

func TestGetPolicy(t *testing.T) {
	tests := []struct {
		name           string
		mode           string
		configPath     string
		wantConfigPath string
		wantMode       string
	}{
		{
			name:           "file config enforce mode",
			mode:           "enforce",
			configPath:     "/etc/rampart/policy.yaml",
			wantConfigPath: "/etc/rampart/policy.yaml",
			wantMode:       "enforce",
		},
		{
			name:           "embedded standard policy",
			mode:           "monitor",
			configPath:     "embedded:standard",
			wantConfigPath: "embedded:standard",
			wantMode:       "monitor",
		},
		{
			name:           "default empty configPath",
			mode:           "enforce",
			configPath:     "",
			wantConfigPath: "rampart.yaml",
			wantMode:       "enforce",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, token, _ := setupTestServer(t, testPolicyYAML, tt.mode)
			if tt.configPath != "" {
				srv.configPath = tt.configPath
			}

			ts := httptest.NewServer(srv.handler())
			defer ts.Close()

			req, err := http.NewRequest(http.MethodGet, ts.URL+"/v1/policy", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+token)

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var body map[string]any
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

			assert.Equal(t, tt.wantConfigPath, body["config_path"])
			assert.Equal(t, tt.wantMode, body["mode"])
			assert.NotNil(t, body["default_action"])
			assert.NotNil(t, body["policy_count"])
			assert.NotNil(t, body["rule_count"])
			assert.NotNil(t, body["call_counts"])

			// Verify counts are plausible.
			policyCount, ok := body["policy_count"].(float64)
			require.True(t, ok, "policy_count should be a number")
			assert.Greater(t, int(policyCount), 0, "should have at least one policy")

			ruleCount, ok := body["rule_count"].(float64)
			require.True(t, ok, "rule_count should be a number")
			assert.Greater(t, int(ruleCount), 0, "should have at least one rule")
		})
	}
}

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

func TestGetPolicy_NoAuth(t *testing.T) {
	srv, _, _ := setupTestServer(t, testPolicyYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1/policy")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
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

	srv, token, _ := setupTestServer(t, configYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	runID := "run-test-abc123"

	// Create two approvals with the same run_id.
	createApproval := func(cmd string) string {
		body := fmt.Sprintf(`{"tool":"exec","command":%q,"agent":"claude-code","run_id":%q,"message":"needs approval"}`, cmd, runID)
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

	id1 := createApproval("rm -rf /tmp/a")
	id2 := createApproval("rm -rf /tmp/b")

	// Bulk-resolve: approve the run.
	bulkBody := fmt.Sprintf(`{"run_id":%q,"action":"approve","resolved_by":"test"}`, runID)
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
}

func TestBulkResolve_EmptyRunIDRejected(t *testing.T) {
	configYAML := `version: "1"
default_action: allow
policies: []`

	srv, token, _ := setupTestServer(t, configYAML, "enforce")
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	// Empty run_id must return 400 — never batch-approve everything.
	for _, body := range []string{
		`{"run_id":"","action":"approve"}`,
		`{"run_id":"   ","action":"approve"}`,
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
		strings.NewReader(`{"run_id":"x","action":"approve"}`))
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
	body := `{"run_id":"run-nonexistent","action":"approve"}`
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

	bulkBody := fmt.Sprintf(`{"run_id":%q,"action":"approve"}`, runID)
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

	// Create 3 approvals: 2 with same run_id (should form a group), 1 solo.
	createApproval := func(cmd, rid string) {
		body := fmt.Sprintf(`{"tool":"exec","command":%q,"agent":"claude-code","run_id":%q,"message":"approval"}`, cmd, rid)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/approvals", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()
	}

	createApproval("cmd-a", runID)
	time.Sleep(5 * time.Millisecond) // ensure distinct created_at ordering
	createApproval("cmd-b", runID)
	createApproval("cmd-solo", "") // no run_id — should not appear in run_groups

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

	// Exactly one group with our run_id.
	var found map[string]any
	for _, g := range runGroups {
		group := g.(map[string]any)
		if group["run_id"] == runID {
			found = group
			break
		}
	}
	require.NotNil(t, found, "run_id %q should appear in run_groups", runID)
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

	// Flat approvals array should still have all 3 items.
	approvals, ok := result["approvals"].([]any)
	require.True(t, ok)
	assert.Len(t, approvals, 3)
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
