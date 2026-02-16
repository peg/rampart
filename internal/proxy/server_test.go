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
	assert.Equal(t, "log", body["decision"])
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
