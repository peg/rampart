// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/peg/rampart/internal/approval"
	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/internal/mcp"
	"github.com/stretchr/testify/require"
)

// fakeApprovalServe stands in for rampart serve: it records the created
// approval and answers polls with pollStatus.
func fakeApprovalServe(t *testing.T, pollStatus string) (*httptest.Server, func() []byte) {
	t.Helper()
	return fakeApprovalServeNotified(t, pollStatus, true)
}

// fakeApprovalServeNotified queues every approval and reports notified as
// whether it told reviewers about it.
func fakeApprovalServeNotified(t *testing.T, pollStatus string, notified bool) (*httptest.Server, func() []byte) {
	t.Helper()
	var mu sync.Mutex
	var created []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/healthz":
			writeTestRampartHealth(w)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/approvals":
			if r.Header.Get("Authorization") != "Bearer synthetic-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			created = body
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"action_version": approval.ExternalActionVersion, "id": "a1", "status": "pending", "notified": notified})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/approvals/a1":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "a1", "status": pollStatus})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []byte {
		mu.Lock()
		defer mu.Unlock()
		return created
	}
}

func isolateServeEnv(t *testing.T, url, token string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("RAMPART_SERVE_URL", "")
	t.Setenv("RAMPART_URL", url)
	t.Setenv("RAMPART_TOKEN", token)
}

func TestMCPProxyServeApprovalForwardsExactRequest(t *testing.T) {
	srv, created := fakeApprovalServe(t, "approved")
	isolateServeEnv(t, srv.URL, "synthetic-token")

	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	require.NoError(t, os.WriteFile(policyPath, []byte(`
default_action: allow
policies:
  - name: ask-all
    match:
      tool: "*"
    rules:
      - action: ask
        message: "review marker"
        when:
          default: true
`), 0o600))
	eng, err := engine.New(engine.NewFileStore(policyPath), testLogger())
	require.NoError(t, err)
	sink, err := audit.NewJSONLSink(t.TempDir(), audit.WithLogger(testLogger()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sink.Close() })

	childInR, childInW := io.Pipe()
	childOutR, childOutW := io.Pipe()
	proxy := mcp.NewProxy(eng, audit.NewRedactingSink(sink), childInW, childOutR,
		mcp.WithMode("enforce"), mcp.WithLogger(testLogger()),
		mcp.WithApprovalResolver(newMCPServeApprovalResolver(5*time.Second, io.Discard, testLogger(), nil)))

	line := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_marker","arguments":{"command":"echo marker","n":9007199254740993}}}` + "\n"
	var parentOut bytes.Buffer
	runErr := make(chan error, 1)
	go func() { runErr <- proxy.Run(context.Background(), strings.NewReader(line), &parentOut) }()

	forwarded := make(chan string, 1)
	go func() {
		got, _ := bufio.NewReader(childInR).ReadString('\n')
		forwarded <- got
	}()
	select {
	case got := <-forwarded:
		require.Equal(t, line, got)
	case <-time.After(5 * time.Second):
		t.Fatal("approved request was not forwarded")
	}
	_ = childOutW.Close()
	require.NoError(t, <-runErr)
	require.Empty(t, parentOut.String())

	req, err := approval.DecodeExternalRequest(bytes.NewReader(created()))
	require.NoError(t, err)
	require.Equal(t, "run_marker", req.Params["mcp_tool"])
	require.Equal(t, "echo marker", req.Params["command"])
	require.Equal(t, json.Number("9007199254740993"), req.Input["n"])
}

func TestMCPServeApprovalResolverFailsClosed(t *testing.T) {
	call := engine.ToolCall{ID: "e1", Tool: "exec", Agent: "mcp-client", Session: "mcp-proxy", Params: map[string]any{"command": "echo marker"}}
	for _, tc := range []struct {
		name       string
		pollStatus string
		token      string
		down       bool
		wantErr    string
	}{
		{name: "denied", pollStatus: "denied", token: "synthetic-token", wantErr: "denied"},
		{name: "expired", pollStatus: "expired", token: "synthetic-token", wantErr: "expired"},
		{name: "timeout while pending", pollStatus: "pending", token: "synthetic-token", wantErr: "timed out"},
		{name: "rejected token", pollStatus: "approved", token: "wrong-token", wantErr: "unavailable"},
		{name: "no token", pollStatus: "approved", wantErr: "no Rampart serve token"},
		{name: "serve unreachable", pollStatus: "approved", token: "synthetic-token", down: true, wantErr: "running Rampart service"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, created := fakeApprovalServe(t, tc.pollStatus)
			if tc.down {
				srv.Close()
			}
			isolateServeEnv(t, srv.URL, tc.token)
			resolve := newMCPServeApprovalResolver(1500*time.Millisecond, io.Discard, testLogger(), nil)
			err := resolve(context.Background(), call, engine.Decision{Action: engine.ActionAsk, Message: "review"})
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErr)
			if tc.token == "" || tc.down {
				require.Empty(t, created(), "no approval should be created")
			}
		})
	}
}

// One MCP ask must produce one reviewer notification: serve's, with a decision
// link, when serve queues it and notifies; otherwise the proxy's own.
func TestMCPProxyNotifiesOncePerDecision(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	require.NoError(t, os.WriteFile(policyPath, []byte(`
default_action: allow
policies:
  - name: ask-dangerous
    match:
      tool: "mcp-dangerous"
    rules:
      - action: ask
        message: "review marker"
        when:
          default: true
  - name: deny-destructive
    match:
      tool: "mcp-destructive"
    rules:
      - action: deny
        message: "deny marker"
        when:
          default: true
`), 0o600))

	for _, tc := range []struct {
		name        string
		tool        string
		serveDown   bool
		serveSilent bool     // serve queues the approval without notifying
		want        []string // proxy-side notifications as "action|command"
	}{
		{name: "ask queued and notified by serve", tool: "run_marker", want: nil},
		{name: "ask queued without a serve notification", tool: "run_marker", serveSilent: true, want: []string{"ask|run_marker — echo marker"}},
		{name: "ask not queued", tool: "run_marker", serveDown: true, want: []string{"ask|run_marker — echo marker"}},
		{name: "deny", tool: "drop_marker", want: []string{"deny|drop_marker — echo marker"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			notificationMutex.Lock()
			lastNotificationTime = time.Time{}
			notificationMutex.Unlock()
			t.Cleanup(func() {
				notificationMutex.Lock()
				lastNotificationTime = time.Time{}
				notificationMutex.Unlock()
			})

			var mu sync.Mutex
			var got []string
			webhook := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				var payload map[string]any
				_ = json.NewDecoder(r.Body).Decode(&payload)
				mu.Lock()
				got = append(got, payload["action"].(string)+"|"+payload["command"].(string))
				mu.Unlock()
			}))
			t.Cleanup(webhook.Close)

			srv, _ := fakeApprovalServeNotified(t, "approved", !tc.serveSilent)
			if tc.serveDown {
				srv.Close()
			}
			isolateServeEnv(t, srv.URL, "synthetic-token")

			eng, err := engine.New(engine.NewFileStore(policyPath), testLogger())
			require.NoError(t, err)
			sink, resolver := newMCPDecisionSink(&mockAuditSink{},
				&engine.NotifyConfig{URL: webhook.URL, On: []string{"ask", "deny"}}, "enforce", io.Discard, testLogger())

			childInR, childInW := io.Pipe()
			childOutR, childOutW := io.Pipe()
			go func() {
				_, _ = io.Copy(io.Discard, childInR)
				_ = childOutW.Close()
			}()
			proxy := mcp.NewProxy(eng, sink, childInW, childOutR,
				mcp.WithMode("enforce"), mcp.WithLogger(testLogger()), mcp.WithApprovalResolver(resolver))
			line := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tc.tool + `","arguments":{"command":"echo marker"}}}` + "\n"
			require.NoError(t, proxy.Run(context.Background(), strings.NewReader(line), io.Discard))

			// Notifications are asynchronous; allow any stray one to arrive.
			time.Sleep(500 * time.Millisecond)
			mu.Lock()
			defer mu.Unlock()
			require.Equal(t, tc.want, got)
		})
	}
}
