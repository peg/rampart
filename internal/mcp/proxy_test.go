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

package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/peg/rampart/internal/approval"
	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/engine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock audit sink
// ---------------------------------------------------------------------------

type mockSink struct {
	mu     sync.Mutex
	events []audit.Event
}

type failingSink struct{}

func (*failingSink) Write(audit.Event) error { return fmt.Errorf("disk unavailable") }
func (*failingSink) Flush() error            { return nil }
func (*failingSink) Close() error            { return nil }

type failOnNthSink struct {
	writes int
	failAt int
}

func (s *failOnNthSink) Write(audit.Event) error {
	s.writes++
	if s.writes == s.failAt {
		return fmt.Errorf("disk unavailable")
	}
	return nil
}

func (*failOnNthSink) Flush() error { return nil }
func (*failOnNthSink) Close() error { return nil }

func (m *mockSink) Write(event audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return nil
}

func (m *mockSink) Flush() error { return nil }
func (m *mockSink) Close() error { return nil }

func (m *mockSink) getEvents() []audit.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]audit.Event, len(m.events))
	copy(cp, m.events)
	return cp
}

// ---------------------------------------------------------------------------
// nopWriteCloser wraps a writer as io.WriteCloser
// ---------------------------------------------------------------------------

type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }

type failingWriteCloser struct{}

func (failingWriteCloser) Write([]byte) (int, error) { return 0, fmt.Errorf("write unavailable") }
func (failingWriteCloser) Close() error              { return nil }

type gatedWriteCloser struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
	writes  int
	err     error
}

func newGatedWriteCloser(err error) *gatedWriteCloser {
	return &gatedWriteCloser{
		started: make(chan struct{}),
		release: make(chan struct{}),
		err:     err,
	}
}

func (w *gatedWriteCloser) Write(data []byte) (int, error) {
	w.writes++
	w.once.Do(func() { close(w.started) })
	<-w.release
	if w.err != nil {
		return 0, w.err
	}
	return len(data), nil
}

func (*gatedWriteCloser) Close() error { return nil }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func makeToolsCallJSON(id any, toolName string, args map[string]any) string {
	params := map[string]any{"name": toolName}
	if args != nil {
		params["arguments"] = args
	}
	paramsBytes, _ := json.Marshal(params)
	msg := map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"id":      id,
		"params":  json.RawMessage(paramsBytes),
	}
	b, _ := json.Marshal(msg)
	return string(b)
}

func makeResponseJSON(id any, result any) string {
	resultBytes, _ := json.Marshal(result)
	msg := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  json.RawMessage(resultBytes),
	}
	b, _ := json.Marshal(msg)
	return string(b)
}

// buildTestEngine creates a real engine from inline YAML policy.
func buildTestEngine(t *testing.T, yamlContent string) *engine.Engine {
	t.Helper()
	tmpDir := t.TempDir()
	policyPath := tmpDir + "/policy.yaml"
	if err := os.WriteFile(policyPath, []byte(yamlContent), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	store := engine.NewFileStore(policyPath)
	eng, err := engine.New(store, silentLogger())
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	return eng
}

// ---------------------------------------------------------------------------
// Test: handleToolsCall — policy enforcement
// ---------------------------------------------------------------------------

func TestHandleToolsCall_Allow(t *testing.T) {
	eng := buildAllowAllEngine(t)
	childIn := &bytes.Buffer{}
	sink := &mockSink{}

	p := NewProxy(eng, sink, nopWriteCloser{childIn}, strings.NewReader(""), WithLogger(silentLogger()))
	p.parentOut = &bytes.Buffer{}

	line := []byte(makeToolsCallJSON(1, "read_file", map[string]any{"path": "/etc/hosts"}) + "\n")
	err := p.handleClientLine(line)
	if err != nil {
		t.Fatalf("handleClientLine: %v", err)
	}

	// Should forward to child
	if childIn.Len() == 0 {
		t.Fatal("expected line forwarded to child, got nothing")
	}

	// Should have pending call
	p.pendingMu.Lock()
	if len(p.pendingCalls) != 1 {
		t.Errorf("expected 1 pending call, got %d", len(p.pendingCalls))
	}
	p.pendingMu.Unlock()
}

func TestHandleToolsCall_EnforceRejectsCaseShadowedSecurityArguments(t *testing.T) {
	tests := make([]struct {
		name      string
		arguments string
	}, 0, len(securitySensitiveArgumentKeys)+1)
	for _, key := range securitySensitiveArgumentKeys {
		tests = append(tests, struct {
			name      string
			arguments string
		}{
			name:      key,
			arguments: fmt.Sprintf(`{"%s":"safe","%s":"dangerous"}`, key, strings.ToUpper(key)),
		})
	}
	// encoding/json uses Unicode simple folding, not ASCII-only casing.
	tests = append(tests, struct {
		name      string
		arguments string
	}{name: "unicode simple fold", arguments: `{"scheme":"https","ſcheme":"file"}`})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			childIn := &bytes.Buffer{}
			parentOut := &bytes.Buffer{}
			p := NewProxy(buildAllowAllEngine(t), &mockSink{}, nopWriteCloser{childIn}, strings.NewReader(""),
				WithMode("enforce"), WithLogger(silentLogger()))
			p.parentOut = parentOut

			line := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_command","arguments":` + test.arguments + `}}` + "\n")
			require.NoError(t, p.handleClientLine(line))
			assert.Empty(t, childIn.String(), "case-shadowed arguments reached child: %s", test.arguments)
			assert.Contains(t, parentOut.String(), "invalid tools/call arguments")
		})
	}
}

func TestHandleToolsCall_EnforcePreservesUnknownArguments(t *testing.T) {
	childIn := &bytes.Buffer{}
	p := NewProxy(buildAllowAllEngine(t), &mockSink{}, nopWriteCloser{childIn}, strings.NewReader(""),
		WithMode("enforce"), WithLogger(silentLogger()))
	p.parentOut = &bytes.Buffer{}

	line := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"custom_tool","arguments":{"customField":"value","path":"/tmp/safe"}}}` + "\n")
	require.NoError(t, p.handleClientLine(line))
	assert.Equal(t, line, childIn.Bytes())
}

func TestHandleToolsCall_AuditFailureFailsClosedInEnforceMode(t *testing.T) {
	eng := buildAllowAllEngine(t)
	childIn := &bytes.Buffer{}
	parentOut := &bytes.Buffer{}
	p := NewProxy(eng, &failingSink{}, nopWriteCloser{childIn}, strings.NewReader(""),
		WithMode("enforce"), WithLogger(silentLogger()))
	p.parentOut = parentOut

	err := p.handleClientLine([]byte(makeToolsCallJSON(1, "read_file", map[string]any{"path": "/etc/hosts"}) + "\n"))
	if err != nil {
		t.Fatalf("handleClientLine: %v", err)
	}
	if childIn.Len() != 0 {
		t.Fatal("request with an unpersisted enforcement decision reached the child")
	}
	if !strings.Contains(parentOut.String(), "audit storage is unavailable") {
		t.Fatalf("unexpected client response: %s", parentOut.String())
	}
}

func TestHandleToolsCall_AuditFailureRemainsObservableInMonitorMode(t *testing.T) {
	eng := buildAllowAllEngine(t)
	childIn := &bytes.Buffer{}
	p := NewProxy(eng, &failingSink{}, nopWriteCloser{childIn}, strings.NewReader(""),
		WithMode("monitor"), WithLogger(silentLogger()))
	p.parentOut = &bytes.Buffer{}

	err := p.handleClientLine([]byte(makeToolsCallJSON(1, "read_file", map[string]any{"path": "/etc/hosts"}) + "\n"))
	if err != nil {
		t.Fatalf("handleClientLine: %v", err)
	}
	if childIn.Len() == 0 {
		t.Fatal("monitor mode should not block on audit storage failure")
	}
}

func TestHandleToolsCall_WebhookResultAuditFailureFailsClosed(t *testing.T) {
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"decision":"allow"}`)
	}))
	defer webhook.Close()

	eng := buildTestEngine(t, fmt.Sprintf(`
version: "1"
default_action: allow
policies:
  - name: webhook-check
    match:
      tool: exec
    rules:
      - action: webhook
        when:
          command_matches: ["deploy prod"]
        webhook:
          url: %q
          timeout: 2s
          fail_open: false
`, webhook.URL))
	childIn := &bytes.Buffer{}
	parentOut := &bytes.Buffer{}
	sink := &failOnNthSink{failAt: 2}
	p := NewProxy(eng, sink, nopWriteCloser{childIn}, strings.NewReader(""),
		WithMode("enforce"), WithLogger(silentLogger()))
	p.parentOut = parentOut

	err := p.handleClientLine([]byte(makeToolsCallJSON(1, "execute_command", map[string]any{"command": "deploy prod"}) + "\n"))
	if err != nil {
		t.Fatalf("handleClientLine: %v", err)
	}
	if childIn.Len() != 0 {
		t.Fatal("request with an unpersisted webhook result reached the child")
	}
	if !strings.Contains(parentOut.String(), "audit storage is unavailable") {
		t.Fatalf("unexpected client response: %s", parentOut.String())
	}
	if sink.writes != 2 {
		t.Fatalf("audit writes = %d, want initial webhook and final result", sink.writes)
	}
}

func TestHandleToolsCall_Deny(t *testing.T) {
	eng := buildDenyAllEngine(t)
	childIn := &bytes.Buffer{}
	parentOut := &bytes.Buffer{}
	sink := &mockSink{}

	p := NewProxy(eng, sink, nopWriteCloser{childIn}, strings.NewReader(""),
		WithMode("enforce"), WithLogger(silentLogger()))
	p.parentOut = parentOut

	line := []byte(makeToolsCallJSON(1, "exec_command", map[string]any{"command": "rm -rf /"}) + "\n")
	err := p.handleClientLine(line)
	if err != nil {
		t.Fatalf("handleClientLine: %v", err)
	}

	// Should NOT forward to child
	if childIn.Len() != 0 {
		t.Error("denied request should not be forwarded to child")
	}

	// Should write error to parent
	if parentOut.Len() == 0 {
		t.Fatal("expected error response to parent")
	}

	var resp Response
	if err := json.Unmarshal(bytes.TrimSpace(parentOut.Bytes()), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Error == nil {
		t.Fatal("expected error in response")
	}
	if resp.Error.Code != jsonRPCDenyCode {
		t.Errorf("expected code %d, got %d", jsonRPCDenyCode, resp.Error.Code)
	}
	if !strings.Contains(resp.Error.Message, "Rampart") {
		t.Error("error message should contain 'Rampart'")
	}
}

func TestHandleToolsCall_ConflictingCommandAliasesFailClosed(t *testing.T) {
	eng := buildAllowAllEngine(t)
	childIn := &bytes.Buffer{}
	parentOut := &bytes.Buffer{}
	p := NewProxy(eng, &mockSink{}, nopWriteCloser{childIn}, strings.NewReader(""),
		WithMode("enforce"), WithLogger(silentLogger()))
	p.parentOut = parentOut

	line := []byte(makeToolsCallJSON(1, "execute_command", map[string]any{
		"command": "echo safe",
		"cmd":     "rm -rf /",
	}) + "\n")
	if err := p.handleClientLine(line); err != nil {
		t.Fatalf("handleClientLine: %v", err)
	}
	if childIn.Len() != 0 {
		t.Fatal("ambiguous request reached the child process")
	}
	if !strings.Contains(parentOut.String(), "ambiguous tool input") {
		t.Fatalf("unexpected client response: %s", parentOut.String())
	}
}

func TestHandleToolsCall_RequireApproval(t *testing.T) {
	eng := buildAskEngine(t)
	childIn := &bytes.Buffer{}
	parentOut := &bytes.Buffer{}
	sink := &mockSink{}
	store := approval.NewStore()
	t.Cleanup(store.Close)

	p := NewProxy(eng, sink, nopWriteCloser{childIn}, strings.NewReader(""),
		WithMode("enforce"), WithApprovalStore(store), WithLogger(silentLogger()))
	p.parentOut = parentOut

	line := []byte(makeToolsCallJSON(2, "exec_command", map[string]any{"command": "ls"}) + "\n")
	done := make(chan error, 1)
	go func() {
		done <- p.handleClientLine(line)
	}()

	var pending *approval.Request
	deadline := time.After(500 * time.Millisecond)
	for pending == nil {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for pending approval")
		default:
			items := store.List()
			if len(items) > 0 {
				pending = items[0]
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	if err := store.Resolve(pending.ID, true, "test"); err != nil {
		t.Fatalf("resolve approval: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("handleClientLine: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for tools/call completion")
	}

	if childIn.Len() == 0 {
		t.Fatal("approved require_approval request should be forwarded to child")
	}
	if parentOut.Len() != 0 {
		t.Fatal("approved require_approval request should not return an error")
	}
}

func TestHandleToolsCall_ResponseDuringApprovalInvalidatesReservation(t *testing.T) {
	childIn := &bytes.Buffer{}
	parentOut := &bytes.Buffer{}
	store := approval.NewStore()
	t.Cleanup(store.Close)
	p := NewProxy(buildAskEngine(t), &mockSink{}, nopWriteCloser{childIn}, strings.NewReader(""),
		WithMode("enforce"), WithApprovalStore(store), WithLogger(silentLogger()))
	p.parentOut = parentOut

	request := []byte(makeToolsCallJSON(23, "exec_command", map[string]any{"command": "echo approved"}) + "\n")
	requestDone := make(chan error, 1)
	go func() { requestDone <- p.handleClientLine(request) }()

	var approvalRequest *approval.Request
	require.Eventually(t, func() bool {
		items := store.List()
		if len(items) == 0 {
			return false
		}
		approvalRequest = items[0]
		return true
	}, time.Second, time.Millisecond)

	key := NormalizedID(json.RawMessage(`23`))
	p.pendingMu.Lock()
	reserved := p.pendingCalls[key]
	p.pendingMu.Unlock()
	require.Equal(t, pendingCallReserved, reserved.state)

	forged := []byte(makeResponseJSON(23, map[string]any{"content": "forged"}) + "\n")
	forgedOut := &bytes.Buffer{}
	require.ErrorContains(t, p.handleChildLine(forged, forgedOut), "uncorrelated response")
	assert.Empty(t, forgedOut.String())
	p.pendingMu.Lock()
	rejected := p.pendingCalls[key]
	p.pendingMu.Unlock()
	require.Equal(t, pendingCallRejected, rejected.state)

	// Keep the poisoned reservation until its owner unwinds so a same-ID request
	// cannot take its place and be overwritten by the approved original.
	require.NoError(t, p.handleClientLine(request))
	assert.Contains(t, parentOut.String(), "already pending")
	assert.Empty(t, childIn.String())
	parentOut.Reset()

	require.NoError(t, store.Resolve(approvalRequest.ID, true, "test"))
	require.NoError(t, <-requestDone)
	assert.Empty(t, childIn.String())
	assert.Contains(t, parentOut.String(), "correlation was invalidated before forwarding")
	p.pendingMu.Lock()
	_, stillPending := p.pendingCalls[key]
	p.pendingMu.Unlock()
	assert.False(t, stillPending)

	require.ErrorContains(t, p.handleChildLine(forged, forgedOut), "uncorrelated response")
	assert.Empty(t, forgedOut.String())
}

func TestHandleToolsCall_RequireApprovalWithoutResolverFailsImmediately(t *testing.T) {
	eng := buildAskEngine(t)
	childIn := &bytes.Buffer{}
	parentOut := &bytes.Buffer{}
	p := NewProxy(eng, &mockSink{}, nopWriteCloser{childIn}, strings.NewReader(""),
		WithMode("enforce"), WithLogger(silentLogger()))
	p.parentOut = parentOut

	line := []byte(makeToolsCallJSON(22, "exec_command", map[string]any{"command": "ls"}) + "\n")
	if err := p.handleClientLine(line); err != nil {
		t.Fatalf("handleClientLine: %v", err)
	}
	if childIn.Len() != 0 {
		t.Fatal("approval-required call must not reach the MCP server")
	}

	var response Response
	if err := json.Unmarshal(bytes.TrimSpace(parentOut.Bytes()), &response); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if response.Error == nil {
		t.Fatal("expected JSON-RPC error")
	}
	if !strings.Contains(response.Error.Message, "no approval resolver") {
		t.Fatalf("unexpected error message: %s", response.Error.Message)
	}
}

func TestHandleToolsCall_RequireApprovalDenied(t *testing.T) {
	eng := buildAskEngine(t)
	childIn := &bytes.Buffer{}
	parentOut := &bytes.Buffer{}
	sink := &mockSink{}
	store := approval.NewStore()
	t.Cleanup(store.Close)

	p := NewProxy(eng, sink, nopWriteCloser{childIn}, strings.NewReader(""),
		WithMode("enforce"), WithApprovalStore(store), WithLogger(silentLogger()))
	p.parentOut = parentOut

	line := []byte(makeToolsCallJSON(3, "exec_command", map[string]any{"command": "ls"}) + "\n")
	done := make(chan error, 1)
	go func() {
		done <- p.handleClientLine(line)
	}()

	var pending *approval.Request
	deadline := time.After(500 * time.Millisecond)
	for pending == nil {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for pending approval")
		default:
			items := store.List()
			if len(items) > 0 {
				pending = items[0]
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	if err := store.Resolve(pending.ID, false, "test"); err != nil {
		t.Fatalf("resolve approval: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("handleClientLine: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for tools/call completion")
	}

	if childIn.Len() != 0 {
		t.Fatal("denied require_approval request should not be forwarded")
	}
	if parentOut.Len() == 0 {
		t.Fatal("denied require_approval request should return an error")
	}
}

func TestHandleToolsCall_MonitorMode_PassesThrough(t *testing.T) {
	eng := buildDenyAllEngine(t)
	childIn := &bytes.Buffer{}
	sink := &mockSink{}

	p := NewProxy(eng, sink, nopWriteCloser{childIn}, strings.NewReader(""),
		WithMode("monitor"), WithLogger(silentLogger()))
	p.parentOut = &bytes.Buffer{}

	line := []byte(makeToolsCallJSON(1, "exec_command", map[string]any{"command": "rm -rf /"}) + "\n")
	err := p.handleClientLine(line)
	if err != nil {
		t.Fatalf("handleClientLine: %v", err)
	}

	// Monitor mode: should forward even denied calls
	if childIn.Len() == 0 {
		t.Error("monitor mode should forward all requests")
	}
}

func TestHandleToolsCall_MonitorModeDoesNotMutateEnforcementState(t *testing.T) {
	t.Run("once rule", func(t *testing.T) {
		eng := buildTestEngine(t, `
version: "1"
default_action: deny
policies:
  - name: one-shot
    match:
      tool: exec
    rules:
      - action: allow
        once: true
        when:
          command_matches: ["deploy prod"]
`)
		childIn := &bytes.Buffer{}
		p := NewProxy(eng, &mockSink{}, nopWriteCloser{childIn}, strings.NewReader(""),
			WithMode("monitor"), WithLogger(silentLogger()))
		p.parentOut = &bytes.Buffer{}

		for id := 1; id <= 2; id++ {
			if err := p.handleClientLine([]byte(makeToolsCallJSON(id, "execute_command", map[string]any{"command": "deploy prod"}) + "\n")); err != nil {
				t.Fatal(err)
			}
		}
		call := engine.ToolCall{Tool: "exec", Params: map[string]any{"command": "deploy prod"}}
		if decision := eng.Enforce(call, engine.EvalOptions{}); decision.Action != engine.ActionAllow {
			t.Fatalf("first real enforcement after monitor = %s, want allow", decision.Action)
		}
		if decision := eng.Enforce(call, engine.EvalOptions{}); decision.Action != engine.ActionDeny {
			t.Fatalf("second real enforcement = %s, want consumed once rule to deny", decision.Action)
		}
	})

	t.Run("call count", func(t *testing.T) {
		eng := buildTestEngine(t, `
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
`)
		childIn := &bytes.Buffer{}
		p := NewProxy(eng, &mockSink{}, nopWriteCloser{childIn}, strings.NewReader(""),
			WithMode("monitor"), WithLogger(silentLogger()))
		p.parentOut = &bytes.Buffer{}

		for id := 1; id <= 2; id++ {
			if err := p.handleClientLine([]byte(makeToolsCallJSON(id, "execute_command", map[string]any{"command": "echo safe"}) + "\n")); err != nil {
				t.Fatal(err)
			}
		}
		if got := eng.CallCounts(time.Hour)["exec"]; got != 0 {
			t.Fatalf("monitor telemetry count = %d, want 0", got)
		}
		call := engine.ToolCall{Tool: "exec", Params: map[string]any{"command": "echo safe"}}
		if decision := eng.Enforce(call, engine.EvalOptions{}); decision.Action != engine.ActionAllow {
			t.Fatalf("first real enforcement after monitor = %s, want allow", decision.Action)
		}
		if decision := eng.Enforce(call, engine.EvalOptions{}); decision.Action != engine.ActionDeny {
			t.Fatalf("second real enforcement = %s, want call-count deny", decision.Action)
		}
	})
}

func TestHandleToolsCall_Notification_NoDenyResponse(t *testing.T) {
	eng := buildDenyAllEngine(t)
	childIn := &bytes.Buffer{}
	parentOut := &bytes.Buffer{}
	sink := &mockSink{}

	p := NewProxy(eng, sink, nopWriteCloser{childIn}, strings.NewReader(""),
		WithMode("enforce"), WithLogger(silentLogger()))
	p.parentOut = parentOut

	// Notification: no id field
	msg := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"exec_command","arguments":{"command":"whoami"}}}` + "\n"
	err := p.handleClientLine([]byte(msg))
	if err != nil {
		t.Fatalf("handleClientLine: %v", err)
	}

	// No id → no error response, just silently drop
	if parentOut.Len() != 0 {
		t.Error("notification deny should not write error response")
	}
	if childIn.Len() != 0 {
		t.Error("denied notification should not forward")
	}
}

// ---------------------------------------------------------------------------
// Test: handleChildLine — response evaluation
// ---------------------------------------------------------------------------

func TestHandleChildLine_AllowedResponse(t *testing.T) {
	eng := buildAllowAllEngine(t)
	childIn := &bytes.Buffer{}
	parentOut := &bytes.Buffer{}
	sink := &mockSink{}

	p := NewProxy(eng, sink, nopWriteCloser{childIn}, strings.NewReader(""),
		WithLogger(silentLogger()))
	p.parentOut = parentOut

	// Register a pending call
	p.pendingMu.Lock()
	p.pendingCalls[NormalizedID(json.RawMessage(`1`))] = pendingCall{
		state: pendingCallResponseActive,
		call: engine.ToolCall{
			ID:      "test-id",
			Agent:   "mcp-client",
			Session: "mcp-proxy",
			Tool:    "read_file",
		},
		request: map[string]any{"mcp_method": "tools/call", "mcp_tool": "read_file"},
	}
	p.pendingMu.Unlock()

	respLine := []byte(makeResponseJSON(1, map[string]any{"content": []map[string]any{{"type": "text", "text": "hello"}}}) + "\n")
	err := p.handleChildLine(respLine, parentOut)
	if err != nil {
		t.Fatalf("handleChildLine: %v", err)
	}

	if parentOut.Len() == 0 {
		t.Fatal("expected response forwarded to parent")
	}
	events := sink.getEvents()
	if len(events) != 1 || events[0].ToolCallID != "test-id" {
		t.Fatalf("response audit correlation = %#v, want tool_call_id test-id", events)
	}

	// Pending call should be consumed
	p.pendingMu.Lock()
	if len(p.pendingCalls) != 0 {
		t.Error("pending call should be consumed after response")
	}
	p.pendingMu.Unlock()
}

func TestHandleToolsCall_ImmediateResponseWaitsForWriteCommitAndRejectsReplay(t *testing.T) {
	childIn := newGatedWriteCloser(nil)
	parentOut := &bytes.Buffer{}
	sink := &mockSink{}
	p := NewProxy(buildAllowAllEngine(t), sink, childIn, strings.NewReader(""),
		WithMode("enforce"), WithLogger(silentLogger()))
	p.parentOut = parentOut

	request := []byte(makeToolsCallJSON(24, "read_file", map[string]any{"path": "/tmp/safe"}) + "\n")
	requestDone := make(chan error, 1)
	go func() { requestDone <- p.handleClientLine(request) }()
	select {
	case <-childIn.started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for child write")
	}

	key := NormalizedID(json.RawMessage(`24`))
	p.pendingMu.Lock()
	writing := p.pendingCalls[key]
	p.pendingMu.Unlock()
	require.Equal(t, pendingCallWriting, writing.state)
	assert.NotEmpty(t, writing.call.ID)
	assert.Equal(t, "read_file", writing.request["mcp_tool"])

	response := []byte(makeResponseJSON(24, map[string]any{"content": "safe"}) + "\n")
	responseDone := make(chan error, 1)
	responseStarted := make(chan struct{})
	go func() {
		close(responseStarted)
		responseDone <- p.handleChildLine(response, parentOut)
	}()
	<-responseStarted
	select {
	case err := <-responseDone:
		t.Fatalf("response completed before child write committed: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	close(childIn.release)
	require.NoError(t, <-requestDone)
	require.NoError(t, <-responseDone)
	assert.Equal(t, 1, childIn.writes)
	assert.Equal(t, response, parentOut.Bytes())

	events := sink.getEvents()
	require.Len(t, events, 2)
	assert.NotEmpty(t, events[0].ToolCallID)
	assert.Equal(t, events[0].ToolCallID, events[1].ToolCallID)

	require.ErrorContains(t, p.handleChildLine(response, parentOut), "uncorrelated response")
	assert.Equal(t, response, parentOut.Bytes())
	assert.Equal(t, 1, childIn.writes)
}

func TestHandleChildLine_AuditFailureBlocksResponseInEnforceMode(t *testing.T) {
	eng := buildAllowAllEngine(t)
	parentOut := &bytes.Buffer{}
	p := NewProxy(eng, &failingSink{}, nopWriteCloser{&bytes.Buffer{}}, strings.NewReader(""),
		WithMode("enforce"), WithLogger(silentLogger()))
	p.parentOut = parentOut
	p.pendingCalls[NormalizedID(json.RawMessage(`1`))] = pendingCall{
		state: pendingCallResponseActive,
		call: engine.ToolCall{
			ID: "test-id", Agent: "mcp-client", Session: "mcp-proxy", Tool: "read_file",
		},
		request: map[string]any{"mcp_method": "tools/call", "mcp_tool": "read_file"},
	}

	respLine := []byte(makeResponseJSON(1, map[string]any{"content": "hello"}) + "\n")
	if err := p.handleChildLine(respLine, parentOut); err != nil {
		t.Fatalf("handleChildLine: %v", err)
	}
	var resp Response
	if err := json.Unmarshal(bytes.TrimSpace(parentOut.Bytes()), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Error == nil || !strings.Contains(resp.Error.Message, "audit storage is unavailable") {
		t.Fatalf("expected audit-storage denial, got %#v", resp.Error)
	}
}

func TestHandleChildLine_DeniedResponse(t *testing.T) {
	eng := buildResponseDenyEngine(t)
	childIn := &bytes.Buffer{}
	parentOut := &bytes.Buffer{}
	sink := &mockSink{}

	p := NewProxy(eng, sink, nopWriteCloser{childIn}, strings.NewReader(""),
		WithMode("enforce"), WithLogger(silentLogger()))
	p.parentOut = parentOut

	// Register pending call
	p.pendingMu.Lock()
	p.pendingCalls[NormalizedID(json.RawMessage(`1`))] = pendingCall{
		state: pendingCallResponseActive,
		call: engine.ToolCall{
			ID:      "test-id",
			Agent:   "mcp-client",
			Session: "mcp-proxy",
			Tool:    "read_file",
		},
		request: map[string]any{"mcp_method": "tools/call", "mcp_tool": "read_file"},
	}
	p.pendingMu.Unlock()

	respLine := []byte(makeResponseJSON(1, map[string]any{"content": []map[string]any{{"type": "text", "text": "SECRET_TOKEN_12345"}}}) + "\n")
	err := p.handleChildLine(respLine, parentOut)
	if err != nil {
		t.Fatalf("handleChildLine: %v", err)
	}

	var resp Response
	if err := json.Unmarshal(bytes.TrimSpace(parentOut.Bytes()), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Error == nil {
		t.Fatal("expected error response for denied response")
	}
	if resp.Error.Code != jsonRPCResponseDenyCode {
		t.Errorf("expected code %d, got %d", jsonRPCResponseDenyCode, resp.Error.Code)
	}
}

func TestHandleChildLine_DecodesEscapedResponseBeforePolicy(t *testing.T) {
	eng := buildResponseDenyEngine(t)
	parentOut := &bytes.Buffer{}
	p := NewProxy(eng, &mockSink{}, nopWriteCloser{&bytes.Buffer{}}, strings.NewReader(""),
		WithMode("enforce"), WithLogger(silentLogger()))
	p.parentOut = parentOut
	p.pendingCalls[NormalizedID(json.RawMessage(`1`))] = pendingCall{
		state:   pendingCallResponseActive,
		call:    engine.ToolCall{ID: "escaped", Tool: "read_file"},
		request: map[string]any{"mcp_method": "tools/call", "mcp_tool": "read_file"},
	}

	line := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":"\u0053\u0045\u0043\u0052\u0045\u0054\u005f\u0054\u004f\u004b\u0045\u004e"}}` + "\n")
	if err := p.handleChildLine(line, parentOut); err != nil {
		t.Fatal(err)
	}
	var response Response
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(parentOut.Bytes()), &response))
	require.NotNil(t, response.Error)
	assert.Equal(t, jsonRPCResponseDenyCode, response.Error.Code)
}

func TestHandleChildLine_RejectsAmbiguousCorrelatedResponse(t *testing.T) {
	eng := buildResponseDenyEngine(t)
	for _, line := range []string{
		`{"jsonrpc":"2.0","id":1,"result":{"content":"safe"},"error":{"code":-1,"message":"SECRET_TOKEN"}}`,
		`{"jsonrpc":"2.0","id":1}`,
		`{"jsonrpc":"1.0","id":1,"result":{"content":"safe"}}`,
	} {
		p := NewProxy(eng, &mockSink{}, nopWriteCloser{&bytes.Buffer{}}, strings.NewReader(""),
			WithMode("enforce"), WithLogger(silentLogger()))
		p.pendingCalls[NormalizedID(json.RawMessage(`1`))] = pendingCall{state: pendingCallResponseActive, call: engine.ToolCall{ID: "ambiguous", Tool: "read_file"}}
		parentOut := &bytes.Buffer{}
		err := p.handleChildLine([]byte(line+"\n"), parentOut)
		if err == nil || !strings.Contains(err.Error(), "reject child JSON-RPC response") {
			t.Fatalf("response %s error = %v, want fail-closed rejection", line, err)
		}
		if parentOut.Len() != 0 {
			t.Fatalf("ambiguous response reached parent: %s", parentOut.String())
		}
	}
}

func TestHandleChildLine_EnforceRejectsUncorrelatedResponses(t *testing.T) {
	eng := buildAllowAllEngine(t)
	for _, line := range []string{
		makeResponseJSON(999, "ok"),
		`{"jsonrpc":"2.0","id":999,"error":{"code":-32603,"message":"failed"}}`,
	} {
		parentOut := &bytes.Buffer{}
		p := NewProxy(eng, &mockSink{}, nopWriteCloser{&bytes.Buffer{}}, strings.NewReader(""),
			WithMode("enforce"), WithLogger(silentLogger()))
		err := p.handleChildLine([]byte(line+"\n"), parentOut)
		require.ErrorContains(t, err, "uncorrelated response")
		assert.Empty(t, parentOut.String())
	}
}

func TestHandleChildLine_MonitorPreservesUncorrelatedResponse(t *testing.T) {
	parentOut := &bytes.Buffer{}
	p := NewProxy(buildAllowAllEngine(t), &mockSink{}, nopWriteCloser{&bytes.Buffer{}}, strings.NewReader(""),
		WithMode("monitor"), WithLogger(silentLogger()))

	line := []byte(makeResponseJSON(999, "ok") + "\n")
	require.NoError(t, p.handleChildLine(line, parentOut))
	assert.Equal(t, line, parentOut.Bytes())
}

func TestPendingCorrelationSurvivesDelayAndRejectsReplacementAndReplay(t *testing.T) {
	for _, test := range []struct {
		name        string
		filterTools bool
		request     []byte
		response    []byte
	}{
		{
			name:     "generic",
			request:  []byte(`{"jsonrpc":"2.0","id":"delayed","method":"initialize","params":{}}` + "\n"),
			response: []byte(`{"jsonrpc":"2.0","id":"delayed","result":{"protocolVersion":"2025-06-18"}}` + "\n"),
		},
		{
			name:        "tools-list",
			filterTools: true,
			request:     []byte(`{"jsonrpc":"2.0","id":"delayed","method":"tools/list","params":{}}` + "\n"),
			response:    []byte(`{"jsonrpc":"2.0","id":"delayed","result":{"tools":[]}}` + "\n"),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			childIn := &bytes.Buffer{}
			parentOut := &bytes.Buffer{}
			p := NewProxy(buildAllowAllEngine(t), &mockSink{}, nopWriteCloser{childIn}, strings.NewReader(""),
				WithMode("enforce"), WithFilterTools(test.filterTools), WithLogger(silentLogger()))
			p.parentOut = parentOut

			require.NoError(t, p.handleClientLine(test.request))
			assert.Equal(t, test.request, childIn.Bytes())
			key := NormalizedID(json.RawMessage(`"delayed"`))
			assert.True(t, p.preparePendingResponse(key))

			// Correlation stores no age. Keeping the request pending while a
			// same-ID request arrives deterministically models an arbitrary delay.
			replacement := []byte(`{"jsonrpc":"2.0","id":"delayed","method":"resources/list","params":{}}` + "\n")
			require.NoError(t, p.handleClientLine(replacement))
			assert.Equal(t, test.request, childIn.Bytes())
			assert.Contains(t, parentOut.String(), "already pending")
			assert.True(t, p.preparePendingResponse(key))
			parentOut.Reset()

			require.NoError(t, p.handleChildLine(test.response, parentOut))
			assert.NotEmpty(t, parentOut.Bytes())
			assert.False(t, p.preparePendingResponse(key))

			require.ErrorContains(t, p.handleChildLine(test.response, parentOut), "uncorrelated response")
		})
	}
}

func TestGenericAndToolRequestIDsCannotCollide(t *testing.T) {
	for _, genericFirst := range []bool{true, false} {
		t.Run(fmt.Sprintf("generic-first-%t", genericFirst), func(t *testing.T) {
			childIn := &bytes.Buffer{}
			parentOut := &bytes.Buffer{}
			p := NewProxy(buildAllowAllEngine(t), &mockSink{}, nopWriteCloser{childIn}, strings.NewReader(""),
				WithMode("enforce"), WithLogger(silentLogger()))
			p.parentOut = parentOut

			generic := []byte(`{"jsonrpc":"2.0","id":7,"method":"initialize","params":{}}` + "\n")
			tool := []byte(makeToolsCallJSON(7, "read_file", map[string]any{"path": "/tmp/test"}) + "\n")
			first, second := tool, generic
			if genericFirst {
				first, second = generic, tool
			}
			require.NoError(t, p.handleClientLine(first))
			require.NoError(t, p.handleClientLine(second))
			assert.Equal(t, first, childIn.Bytes())
			assert.Contains(t, parentOut.String(), "already pending")
		})
	}
}

func TestGenericPendingCapacityIsCombinedAndBounded(t *testing.T) {
	newFullProxy := func(t *testing.T, mode string, childIn *bytes.Buffer) *Proxy {
		p := NewProxy(buildAllowAllEngine(t), &mockSink{}, nopWriteCloser{childIn}, strings.NewReader(""),
			WithMode(mode), WithLogger(silentLogger()))
		p.parentOut = &bytes.Buffer{}
		p.pendingCalls[NormalizedID(json.RawMessage(`"call"`))] = pendingCall{state: pendingCallResponseActive}
		p.pendingToolList[NormalizedID(json.RawMessage(`"list"`))] = struct{}{}
		for index := 0; index < maxPendingRequests-2; index++ {
			key := NormalizedID(json.RawMessage(fmt.Sprintf(`"generic-%d"`, index)))
			p.pendingGeneric[key] = struct{}{}
		}
		return p
	}

	line := []byte(`{"jsonrpc":"2.0","id":"overflow","method":"initialize","params":{}}` + "\n")
	childIn := &bytes.Buffer{}
	p := newFullProxy(t, "enforce", childIn)
	require.NoError(t, p.handleClientLine(line))
	assert.Empty(t, childIn.String())
	assert.Contains(t, p.parentOut.(*bytes.Buffer).String(), "pending request capacity reached")
	p.pendingMu.Lock()
	count := p.pendingCountLocked()
	p.pendingMu.Unlock()
	assert.Equal(t, maxPendingRequests, count)

	monitorChild := &bytes.Buffer{}
	monitor := newFullProxy(t, "monitor", monitorChild)
	require.NoError(t, monitor.handleClientLine(line))
	assert.Equal(t, line, monitorChild.Bytes())
	monitor.pendingMu.Lock()
	monitorCount := monitor.pendingCountLocked()
	monitor.pendingMu.Unlock()
	assert.Equal(t, maxPendingRequests, monitorCount)
}

func TestGenericReservationReleasedWhenChildWriteFails(t *testing.T) {
	p := NewProxy(buildAllowAllEngine(t), &mockSink{}, failingWriteCloser{}, strings.NewReader(""),
		WithMode("enforce"), WithLogger(silentLogger()))
	p.parentOut = &bytes.Buffer{}

	line := []byte(`{"jsonrpc":"2.0","id":"init-1","method":"initialize","params":{}}` + "\n")
	require.ErrorContains(t, p.handleClientLine(line), "write to child stdin")
	assert.False(t, p.preparePendingResponse(NormalizedID(json.RawMessage(`"init-1"`))))
}

func TestHandleChildLine_EnforceRejectsReplayedResponse(t *testing.T) {
	parentOut := &bytes.Buffer{}
	p := NewProxy(buildResponseDenyEngine(t), &mockSink{}, nopWriteCloser{&bytes.Buffer{}}, strings.NewReader(""),
		WithMode("enforce"), WithLogger(silentLogger()))
	p.pendingCalls[NormalizedID(json.RawMessage(`1`))] = pendingCall{
		state:   pendingCallResponseActive,
		call:    engine.ToolCall{ID: "replay", Tool: "read_file"},
		request: map[string]any{"mcp_method": "tools/call", "mcp_tool": "read_file"},
	}

	safe := []byte(makeResponseJSON(1, map[string]any{"content": "safe"}) + "\n")
	require.NoError(t, p.handleChildLine(safe, parentOut))
	assert.Equal(t, safe, parentOut.Bytes())

	secret := []byte(makeResponseJSON(1, map[string]any{"content": "SECRET_TOKEN"}) + "\n")
	err := p.handleChildLine(secret, parentOut)
	require.ErrorContains(t, err, "uncorrelated response")
	assert.Equal(t, safe, parentOut.Bytes())
}

func TestHandleChildLine_PreservesServerRequestsAndNotifications(t *testing.T) {
	parentOut := &bytes.Buffer{}
	p := NewProxy(buildAllowAllEngine(t), &mockSink{}, nopWriteCloser{&bytes.Buffer{}}, strings.NewReader(""),
		WithMode("enforce"), WithLogger(silentLogger()))
	p.pendingCalls[NormalizedID(json.RawMessage(`1`))] = pendingCall{
		state: pendingCallResponseActive,
		call:  engine.ToolCall{ID: "client-call", Tool: "read_file"},
	}

	for _, line := range [][]byte{
		[]byte(`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{}}` + "\n"),
		[]byte(`{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info"}}` + "\n"),
	} {
		require.NoError(t, p.handleChildLine(line, parentOut))
	}
	assert.Contains(t, parentOut.String(), `"method":"sampling/createMessage"`)
	assert.Contains(t, parentOut.String(), `"method":"notifications/message"`)
	_, stillPending := p.pendingCalls[NormalizedID(json.RawMessage(`1`))]
	assert.True(t, stillPending, "server request consumed client response correlation")

	mixed := []byte(`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","result":{"content":"SECRET_TOKEN"}}` + "\n")
	require.ErrorContains(t, p.handleChildLine(mixed, parentOut), "ambiguous child JSON-RPC request/response")
	assert.NotContains(t, parentOut.String(), "SECRET_TOKEN")
}

// ---------------------------------------------------------------------------
// Test: filterToolsListResponse
// ---------------------------------------------------------------------------

func TestFilterToolsListResponse_FiltersBlockedTools(t *testing.T) {
	eng := buildDenyExecEngine(t)
	sink := &mockSink{}

	p := NewProxy(eng, sink, nopWriteCloser{&bytes.Buffer{}}, strings.NewReader(""),
		WithFilterTools(true), WithMode("enforce"), WithLogger(silentLogger()))
	p.parentOut = &bytes.Buffer{}

	// Register pending tools/list
	p.pendingMu.Lock()
	p.pendingToolList[NormalizedID(json.RawMessage(`1`))] = struct{}{}
	p.pendingMu.Unlock()

	toolsResult := map[string]any{
		"tools": []any{
			map[string]any{"name": "read_file", "description": "Read a file"},
			map[string]any{"name": "execute_command", "description": "Run shell commands"},
			map[string]any{"name": "write_file", "description": "Write a file"},
		},
	}
	resultBytes, _ := json.Marshal(toolsResult)
	resp := Response{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Result:  resultBytes,
	}

	filtered, err := p.filterToolsListResponse(resp)
	if err != nil {
		t.Fatalf("filterToolsListResponse: %v", err)
	}

	var filteredResp Response
	if err := json.Unmarshal(bytes.TrimSpace(filtered), &filteredResp); err != nil {
		t.Fatalf("unmarshal filtered: %v", err)
	}

	var result map[string]any
	json.Unmarshal(filteredResp.Result, &result)
	tools := result["tools"].([]any)

	// execute_command should be filtered out
	for _, tool := range tools {
		toolMap := tool.(map[string]any)
		if toolMap["name"] == "execute_command" {
			t.Error("execute_command should have been filtered out")
		}
	}
}

func TestFilterToolsListResponse_RequireApprovalVisible(t *testing.T) {
	eng := buildAskEngine(t)
	sink := &mockSink{}

	p := NewProxy(eng, sink, nopWriteCloser{&bytes.Buffer{}}, strings.NewReader(""),
		WithFilterTools(true), WithMode("enforce"), WithLogger(silentLogger()))
	p.parentOut = &bytes.Buffer{}

	p.pendingMu.Lock()
	p.pendingToolList[NormalizedID(json.RawMessage(`1`))] = struct{}{}
	p.pendingMu.Unlock()

	toolsResult := map[string]any{
		"tools": []any{
			map[string]any{"name": "read_file", "description": "Read a file"},
			map[string]any{"name": "execute_command", "description": "Run shell commands"},
		},
	}
	resultBytes, _ := json.Marshal(toolsResult)
	resp := Response{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Result:  resultBytes,
	}

	filtered, err := p.filterToolsListResponse(resp)
	if err != nil {
		t.Fatalf("filterToolsListResponse: %v", err)
	}

	var filteredResp Response
	if err := json.Unmarshal(bytes.TrimSpace(filtered), &filteredResp); err != nil {
		t.Fatalf("unmarshal filtered: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(filteredResp.Result, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	tools, ok := result["tools"].([]any)
	if !ok {
		t.Fatalf("expected tools list, got %T", result["tools"])
	}
	if len(tools) != 2 {
		t.Fatalf("require_approval tools should stay visible, got %d tools", len(tools))
	}
}

// ---------------------------------------------------------------------------
// Test: JSON-RPC ID matching
// ---------------------------------------------------------------------------

func TestPendingCallIDMatching(t *testing.T) {
	tests := []struct {
		name string
		id   string
	}{
		{"numeric", `1`},
		{"string", `"abc-123"`},
		{"large number", `999999999`},
		{"uuid string", `"550e8400-e29b-41d4-a716-446655440000"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng := buildAllowAllEngine(t)
			childIn := &bytes.Buffer{}
			parentOut := &bytes.Buffer{}
			sink := &mockSink{}

			p := NewProxy(eng, sink, nopWriteCloser{childIn}, strings.NewReader(""),
				WithLogger(silentLogger()))
			p.parentOut = parentOut

			// Send tools/call with specific ID
			req := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/test"}}}`, tt.id)
			err := p.handleClientLine([]byte(req + "\n"))
			if err != nil {
				t.Fatalf("handleClientLine: %v", err)
			}

			// Verify pending
			normalizedID := NormalizedID(json.RawMessage(tt.id))
			p.pendingMu.Lock()
			_, ok := p.pendingCalls[normalizedID]
			p.pendingMu.Unlock()
			if !ok {
				t.Fatalf("pending call not found for id %s", tt.id)
			}

			// Send response with matching ID
			resp := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"ok"}]}}`, tt.id)
			err = p.handleChildLine([]byte(resp+"\n"), parentOut)
			if err != nil {
				t.Fatalf("handleChildLine: %v", err)
			}

			// Verify consumed
			p.pendingMu.Lock()
			_, stillPending := p.pendingCalls[normalizedID]
			p.pendingMu.Unlock()
			if stillPending {
				t.Error("pending call should be consumed after matching response")
			}
		})
	}
}

func TestCorrelatedResponseIDsUseDecodedJSONIdentity(t *testing.T) {
	for _, test := range []struct {
		name       string
		requestID  string
		responseID string
	}{
		{name: "escaped string", requestID: `"client-id"`, responseID: `"client-\u0069d"`},
		{name: "large integer exponent", requestID: `9007199254740993123456789`, responseID: `9007199254740993123456789e0`},
		{name: "integral decimal", requestID: `-42`, responseID: `-42.0`},
	} {
		t.Run(test.name, func(t *testing.T) {
			childIn := &bytes.Buffer{}
			parentOut := &bytes.Buffer{}
			p := NewProxy(buildResponseDenyEngine(t), &mockSink{}, nopWriteCloser{childIn}, strings.NewReader(""),
				WithMode("enforce"), WithLogger(silentLogger()))
			p.parentOut = parentOut

			req := []byte(`{"jsonrpc":"2.0","id":` + test.requestID + `,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/test"}}}` + "\n")
			require.NoError(t, p.handleClientLine(req))
			response := []byte(`{"jsonrpc":"2.0","id":` + test.responseID + `,"result":{"content":"SECRET_TOKEN"}}` + "\n")
			require.NoError(t, p.handleChildLine(response, parentOut))

			var blocked Response
			require.NoError(t, json.Unmarshal(bytes.TrimSpace(parentOut.Bytes()), &blocked))
			require.NotNil(t, blocked.Error, "equivalent response ID bypassed response policy")
			assert.Equal(t, jsonRPCResponseDenyCode, blocked.Error.Code)
		})
	}
}

func TestNormalizedIDPreservesJSONTypeAndLargeIntegerIdentity(t *testing.T) {
	assert.NotEqual(t, NormalizedID(json.RawMessage(`"1"`)), NormalizedID(json.RawMessage(`1`)))
	assert.Equal(t, NormalizedID(json.RawMessage(`9007199254740993123456789`)), NormalizedID(json.RawMessage(`9007199254740993123456789.0`)))
	assert.NotEqual(t, NormalizedID(json.RawMessage(`9007199254740993123456789`)), NormalizedID(json.RawMessage(`9007199254740993123456790`)))
	// encoding/json expands '<' to a six-byte escape, so enforce the bound
	// after canonicalization as well as on the received line.
	assert.Empty(t, NormalizedID(json.RawMessage(`"`+strings.Repeat("<", maxRequestIDBytes/2)+`"`)))
}

func TestValidRequestIDAcceptsEquivalentIntegralJSONNumbers(t *testing.T) {
	assert.True(t, validRequestID(json.RawMessage(`1.0`)))
	assert.True(t, validRequestID(json.RawMessage(`1e0`)))
	assert.True(t, validRequestID(json.RawMessage(`-0`)))
	assert.False(t, validRequestID(json.RawMessage(`1.5`)))
}

func TestMonitorModePreservesUntrackableRequestIDs(t *testing.T) {
	ids := []string{
		`1.5`, `null`, `true`, `[]`, `1e1000000`,
		`"` + strings.Repeat("x", maxRequestIDBytes) + `"`,
	}
	for _, method := range []string{"tools/call", "tools/list", "initialize"} {
		for index, id := range ids {
			t.Run(fmt.Sprintf("%s-%d", method, index), func(t *testing.T) {
				childIn := &bytes.Buffer{}
				p := NewProxy(buildAllowAllEngine(t), &mockSink{}, nopWriteCloser{childIn}, strings.NewReader(""),
					WithMode("monitor"), WithFilterTools(true), WithLogger(silentLogger()))
				p.parentOut = &bytes.Buffer{}
				params := `{}`
				if method == "tools/call" {
					params = `{"name":"read_file","arguments":{"path":"/tmp/test"}}`
				}
				line := []byte(`{"jsonrpc":"2.0","id":` + id + `,"method":"` + method + `","params":` + params + `}` + "\n")
				require.NoError(t, p.handleClientLine(line))
				assert.Equal(t, line, childIn.Bytes())
			})
		}
	}
}

func TestMonitorModePreservesUntrackableResponseID(t *testing.T) {
	parentOut := &bytes.Buffer{}
	p := NewProxy(buildAllowAllEngine(t), &mockSink{}, nopWriteCloser{&bytes.Buffer{}}, strings.NewReader(""),
		WithMode("monitor"), WithFilterTools(true), WithLogger(silentLogger()))
	p.parentOut = parentOut

	line := []byte(`{"jsonrpc":"2.0","id":"\ud800","result":{"content":"untracked"}}` + "\n")
	require.NoError(t, p.handleChildLine(line, parentOut))
	assert.Equal(t, line, parentOut.Bytes())
}

func TestNormalizedIDRejectsAmbiguousUnicodeAndPreservesValidPairs(t *testing.T) {
	assert.Empty(t, NormalizedID(json.RawMessage(`"\ud800"`)))
	assert.Empty(t, NormalizedID(json.RawMessage(`"\udc00"`)))
	assert.NotEqual(t, NormalizedID(json.RawMessage(`"\ud800\udc00"`)), NormalizedID(json.RawMessage(`"\ufffd"`)))
	assert.Equal(t, NormalizedID(json.RawMessage(`"\ud800\udc00"`)), NormalizedID(json.RawMessage(`"𐀀"`)))
}

func TestToolsListFilteringUsesCanonicalResponseID(t *testing.T) {
	childIn := &bytes.Buffer{}
	parentOut := &bytes.Buffer{}
	p := NewProxy(buildDenyExecEngine(t), &mockSink{}, nopWriteCloser{childIn}, strings.NewReader(""),
		WithMode("enforce"), WithFilterTools(true), WithLogger(silentLogger()))
	p.parentOut = parentOut

	require.NoError(t, p.handleClientLine([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`+"\n")))
	response := []byte(`{"jsonrpc":"2.0","id":1.0,"result":{"tools":[{"name":"read_file"},{"name":"execute_command"}]}}` + "\n")
	require.NoError(t, p.handleChildLine(response, parentOut))

	var filtered Response
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(parentOut.Bytes()), &filtered))
	var result struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	require.NoError(t, json.Unmarshal(filtered.Result, &result))
	require.Len(t, result.Tools, 1)
	assert.Equal(t, "read_file", result.Tools[0].Name)
}

func TestHandleChildLine_EnforceRejectsInvalidResponseID(t *testing.T) {
	for _, test := range []struct {
		name string
		id   string
	}{
		{name: "fractional", id: `1.5`},
		{name: "oversized", id: `"` + strings.Repeat("x", maxRequestIDBytes) + `"`},
		{name: "expansion", id: `1e1000000`},
		{name: "unpaired surrogate", id: `"\ud800"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			childIn := &bytes.Buffer{}
			parentOut := &bytes.Buffer{}
			p := NewProxy(buildResponseDenyEngine(t), &mockSink{}, nopWriteCloser{childIn}, strings.NewReader(""),
				WithMode("enforce"), WithLogger(silentLogger()))
			p.parentOut = parentOut

			require.NoError(t, p.handleClientLine([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/test"}}}`+"\n")))
			err := p.handleChildLine([]byte(`{"jsonrpc":"2.0","id":`+test.id+`,"result":{"content":"SECRET_TOKEN"}}`+"\n"), parentOut)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid response id")
			assert.Empty(t, parentOut.String())
		})
	}
}

// ---------------------------------------------------------------------------
// Test: Edge cases
// ---------------------------------------------------------------------------

func TestHandleClientLine_EnforceRejectsMalformedJSONAndBatch(t *testing.T) {
	eng := buildAllowAllEngine(t)
	for _, test := range []struct {
		name string
		line string
	}{
		{name: "malformed", line: "this is not json\n"},
		{name: "non-object", line: `"not an envelope"` + "\n"},
		{name: "batch", line: "[" + makeToolsCallJSON(1, "execute_command", map[string]any{"command": "echo bypass"}) + "]\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			childIn := &bytes.Buffer{}
			parentOut := &bytes.Buffer{}
			p := NewProxy(eng, &mockSink{}, nopWriteCloser{childIn}, strings.NewReader(""),
				WithMode("enforce"), WithLogger(silentLogger()))
			p.parentOut = parentOut

			if err := p.handleClientLine([]byte(test.line)); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if childIn.Len() != 0 {
				t.Fatal("invalid JSON-RPC envelope reached the child")
			}
			if !strings.Contains(parentOut.String(), "invalid JSON-RPC request envelope") {
				t.Fatalf("unexpected client response: %s", parentOut.String())
			}
		})
	}
}

func TestHandleClientLine_EnforceRejectsDuplicateJSONMembers(t *testing.T) {
	eng := buildAllowAllEngine(t)
	for _, line := range []string{
		// A child parser choosing the first method would execute tools/call while
		// Go's decoder evaluates the last method as benign.
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"initialize","params":{"name":"execute_command","arguments":{"command":"echo bypass"}}}` + "\n",
		// Reject parser differentials in nested tool arguments as well.
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_command","arguments":{"command":"echo allowed","command":"echo bypass"}}}` + "\n",
	} {
		childIn := &bytes.Buffer{}
		parentOut := &bytes.Buffer{}
		p := NewProxy(eng, &mockSink{}, nopWriteCloser{childIn}, strings.NewReader(""),
			WithMode("enforce"), WithLogger(silentLogger()))
		p.parentOut = parentOut

		if err := p.handleClientLine([]byte(line)); err != nil {
			t.Fatal(err)
		}
		if childIn.Len() != 0 {
			t.Fatal("ambiguous JSON reached child")
		}
		if !strings.Contains(parentOut.String(), "invalid JSON-RPC request envelope") {
			t.Fatalf("unexpected client response: %s", parentOut.String())
		}
	}
}

func TestHandleClientLine_EnforceRejectsCaseShadowedProtocolMembers(t *testing.T) {
	eng := buildAllowAllEngine(t)
	for _, line := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","Method":"initialize","params":{"name":"execute_command","arguments":{"command":"echo bypass"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_command","Name":"read_file","arguments":{"command":"echo bypass"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_command","arguments":{"command":"echo bypass"},"Arguments":{}}}`,
	} {
		childIn := &bytes.Buffer{}
		parentOut := &bytes.Buffer{}
		p := NewProxy(eng, &mockSink{}, nopWriteCloser{childIn}, strings.NewReader(""),
			WithMode("enforce"), WithLogger(silentLogger()))
		p.parentOut = parentOut
		require.NoError(t, p.handleClientLine([]byte(line+"\n")))
		assert.Zero(t, childIn.Len(), "case-shadowed request reached child")
		assert.Contains(t, parentOut.String(), "invalid")
	}
}

func TestHandleClientLine_MonitorPreservesDuplicateJSONMembers(t *testing.T) {
	eng := buildAllowAllEngine(t)
	childIn := &bytes.Buffer{}
	p := NewProxy(eng, &mockSink{}, nopWriteCloser{childIn}, strings.NewReader(""),
		WithMode("monitor"), WithLogger(silentLogger()))
	p.parentOut = &bytes.Buffer{}
	line := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","method":"ping"}` + "\n")
	require.NoError(t, p.handleClientLine(line))
	assert.Equal(t, string(line), childIn.String())
}

func TestHandleClientLine_MonitorPassesThroughMalformedJSON(t *testing.T) {
	eng := buildAllowAllEngine(t)
	childIn := &bytes.Buffer{}
	p := NewProxy(eng, &mockSink{}, nopWriteCloser{childIn}, strings.NewReader(""),
		WithMode("monitor"), WithLogger(silentLogger()))
	p.parentOut = &bytes.Buffer{}

	if err := p.handleClientLine([]byte("this is not json\n")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if childIn.Len() == 0 {
		t.Error("monitor mode should preserve malformed peer traffic for diagnostics")
	}
}

func TestHandleToolsCall_EnforceRejectsUntrackableOrIncompleteRequests(t *testing.T) {
	for _, test := range []struct {
		name string
		line string
	}{
		{
			name: "notification without id",
			line: `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"execute_command","arguments":{"command":"echo bypass"}}}` + "\n",
		},
		{
			name: "invalid params without id",
			line: `{"jsonrpc":"2.0","method":"tools/call","params":"not-an-object"}` + "\n",
		},
		{
			name: "missing tool name",
			line: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"command":"echo bypass"}}}` + "\n",
		},
		{
			name: "wrong protocol version",
			line: `{"jsonrpc":"1.0","id":1,"method":"tools/call","params":{"name":"execute_command","arguments":{"command":"echo bypass"}}}` + "\n",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			eng := buildAllowAllEngine(t)
			childIn := &bytes.Buffer{}
			p := NewProxy(eng, &mockSink{}, nopWriteCloser{childIn}, strings.NewReader(""),
				WithMode("enforce"), WithLogger(silentLogger()))
			p.parentOut = &bytes.Buffer{}
			if err := p.handleClientLine([]byte(test.line)); err != nil {
				t.Fatal(err)
			}
			if childIn.Len() != 0 {
				t.Fatal("invalid tools/call reached the child")
			}
		})
	}
}

func TestHandleClientLine_EmptyLine(t *testing.T) {
	eng := buildAllowAllEngine(t)
	childIn := &bytes.Buffer{}
	sink := &mockSink{}

	p := NewProxy(eng, sink, nopWriteCloser{childIn}, strings.NewReader(""),
		WithLogger(silentLogger()))
	p.parentOut = &bytes.Buffer{}

	// proxyClientToChild skips empty lines, but handleClientLine itself
	// would forward them. The proxy loop filters blanks.
}

func TestHandleToolsCall_InvalidParams(t *testing.T) {
	eng := buildAllowAllEngine(t)
	childIn := &bytes.Buffer{}
	parentOut := &bytes.Buffer{}
	sink := &mockSink{}

	p := NewProxy(eng, sink, nopWriteCloser{childIn}, strings.NewReader(""),
		WithMode("enforce"), WithLogger(silentLogger()))
	p.parentOut = parentOut

	// tools/call with invalid params (not an object)
	line := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"not-an-object"}` + "\n"
	err := p.handleClientLine([]byte(line))
	if err != nil {
		t.Fatalf("handleClientLine: %v", err)
	}

	// In enforce mode with id, should return error
	if parentOut.Len() == 0 {
		t.Fatal("expected error for invalid params in enforce mode")
	}
	var resp Response
	json.Unmarshal(bytes.TrimSpace(parentOut.Bytes()), &resp)
	if resp.Error == nil || resp.Error.Code != jsonRPCDenyCode {
		t.Error("expected deny error for invalid params")
	}
}

func TestHandleToolsCall_NilArguments(t *testing.T) {
	eng := buildAllowAllEngine(t)
	childIn := &bytes.Buffer{}
	sink := &mockSink{}

	p := NewProxy(eng, sink, nopWriteCloser{childIn}, strings.NewReader(""),
		WithMode("enforce"), WithLogger(silentLogger()))
	p.parentOut = &bytes.Buffer{}

	for index, params := range []string{
		`{"name":"read_file"}`,
		`{"name":"read_file","arguments":null}`,
	} {
		line := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":%s}`, index+1, params) + "\n"
		if err := p.handleClientLine([]byte(line)); err != nil {
			t.Fatalf("handleClientLine: %v", err)
		}
	}

	if lines := strings.Count(childIn.String(), "\n"); lines != 2 {
		t.Errorf("forwarded lines = %d, want 2", lines)
	}
}

func TestHandleChildLine_MalformedJSONFailsClosed(t *testing.T) {
	eng := buildAllowAllEngine(t)
	parentOut := &bytes.Buffer{}
	sink := &mockSink{}

	p := NewProxy(eng, sink, nopWriteCloser{&bytes.Buffer{}}, strings.NewReader(""),
		WithMode("enforce"), WithLogger(silentLogger()))

	err := p.handleChildLine([]byte("not json at all\n"), parentOut)
	if err == nil || !strings.Contains(err.Error(), "reject child JSON-RPC response") {
		t.Fatalf("malformed child response error = %v, want fail-closed rejection", err)
	}
	if parentOut.Len() != 0 {
		t.Fatalf("malformed child output reached parent: %q", parentOut.String())
	}
}

func TestHandleChildLine_MalformedJSONPassesThroughInMonitorMode(t *testing.T) {
	eng := buildAllowAllEngine(t)
	parentOut := &bytes.Buffer{}
	p := NewProxy(eng, &mockSink{}, nopWriteCloser{&bytes.Buffer{}}, strings.NewReader(""),
		WithMode("monitor"), WithLogger(silentLogger()))

	if err := p.handleChildLine([]byte("not json at all\n"), parentOut); err != nil {
		t.Fatalf("monitor mode malformed child response: %v", err)
	}
	if parentOut.String() != "not json at all\n" {
		t.Fatalf("monitor output = %q", parentOut.String())
	}
}

func TestHandleChildLine_DuplicateResponseKeysFailClosed(t *testing.T) {
	eng := buildAllowAllEngine(t)
	tests := []struct {
		name string
		line string
	}{
		{name: "id", line: `{"jsonrpc":"2.0","id":1,"id":2,"result":{"content":"safe"}}`},
		{name: "result", line: `{"jsonrpc":"2.0","id":1,"result":{"content":"safe"},"result":{"content":"secret"}}`},
		{name: "nested result", line: `{"jsonrpc":"2.0","id":1,"result":{"content":"safe","content":"secret"}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parentOut := &bytes.Buffer{}
			p := NewProxy(eng, &mockSink{}, nopWriteCloser{&bytes.Buffer{}}, strings.NewReader(""),
				WithMode("enforce"), WithLogger(silentLogger()))
			err := p.handleChildLine([]byte(test.line+"\n"), parentOut)
			if err == nil || !strings.Contains(err.Error(), "duplicate object member") {
				t.Fatalf("duplicate response error = %v", err)
			}
			if parentOut.Len() != 0 {
				t.Fatalf("ambiguous response reached parent: %q", parentOut.String())
			}
		})
	}
}

func TestHandleChildLine_CaseShadowedResponseKeysFailClosed(t *testing.T) {
	eng := buildAllowAllEngine(t)
	for _, line := range []string{
		`{"jsonrpc":"2.0","id":1,"ID":999,"result":{"content":"safe"}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"content":"safe"},"Result":{"content":"bypass"}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"content":"safe"},"reſult":{"content":"bypass"}}`,
	} {
		parentOut := &bytes.Buffer{}
		p := NewProxy(eng, &mockSink{}, nopWriteCloser{&bytes.Buffer{}}, strings.NewReader(""),
			WithMode("enforce"), WithLogger(silentLogger()))
		p.pendingCalls[NormalizedID(json.RawMessage(`1`))] = pendingCall{state: pendingCallResponseActive, call: engine.ToolCall{ID: "case-shadow", Tool: "read_file"}}
		err := p.handleChildLine([]byte(line+"\n"), parentOut)
		if err == nil || !strings.Contains(err.Error(), "noncanonical object member") {
			t.Fatalf("case-shadowed response error = %v", err)
		}
		assert.Zero(t, parentOut.Len())
	}
}

// ---------------------------------------------------------------------------
// Test: Concurrent requests
// ---------------------------------------------------------------------------

func TestConcurrentToolsCalls(t *testing.T) {
	eng := buildAllowAllEngine(t)
	childIn := &safeBuffer{}
	parentOut := &safeBuffer{}
	sink := &mockSink{}

	p := NewProxy(eng, sink, nopWriteCloser{childIn}, strings.NewReader(""),
		WithLogger(silentLogger()))
	p.parentOut = parentOut

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			line := []byte(makeToolsCallJSON(id, "read_file", map[string]any{"path": fmt.Sprintf("/tmp/%d", id)}) + "\n")
			if err := p.handleClientLine(line); err != nil {
				t.Errorf("handleClientLine(%d): %v", id, err)
			}
		}(i)
	}
	wg.Wait()

	p.pendingMu.Lock()
	count := len(p.pendingCalls)
	p.pendingMu.Unlock()
	if count != 50 {
		t.Errorf("expected 50 pending calls, got %d", count)
	}
}

type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (sb *safeBuffer) Write(p []byte) (int, error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.Write(p)
}

func (sb *safeBuffer) Len() int {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.Len()
}

// ---------------------------------------------------------------------------
// Test: Bidirectional proxy (Run)
// ---------------------------------------------------------------------------

func TestRun_NilStreams(t *testing.T) {
	eng := buildAllowAllEngine(t)
	p := NewProxy(eng, nil, nopWriteCloser{&bytes.Buffer{}}, strings.NewReader(""),
		WithLogger(silentLogger()))

	err := p.Run(context.Background(), nil, &bytes.Buffer{})
	if err == nil {
		t.Error("expected error for nil parentIn")
	}

	err = p.Run(context.Background(), strings.NewReader(""), nil)
	if err == nil {
		t.Error("expected error for nil parentOut")
	}
}

func TestRun_NilEngine(t *testing.T) {
	p := NewProxy(nil, nil, nopWriteCloser{&bytes.Buffer{}}, strings.NewReader(""),
		WithLogger(silentLogger()))

	err := p.Run(context.Background(), strings.NewReader(""), &bytes.Buffer{})
	if err == nil {
		t.Error("expected error for nil engine")
	}
}

func TestRun_EndToEnd(t *testing.T) {
	eng := buildAllowAllEngine(t)

	// Set up pipes for child stdin/stdout
	childStdinR, childStdinW := io.Pipe()
	childStdoutR, childStdoutW := io.Pipe()

	sink := &mockSink{}
	p := NewProxy(eng, sink, childStdinW, childStdoutR, WithLogger(silentLogger()))

	// Simulate child: echo back a response for each request
	go func() {
		defer childStdoutW.Close()
		scanner := bufio.NewScanner(childStdinR)
		for scanner.Scan() {
			line := scanner.Bytes()
			var req Request
			if err := json.Unmarshal(line, &req); err != nil {
				continue
			}
			resp := makeResponseJSON(json.RawMessage(req.ID), map[string]any{
				"content": []map[string]any{{"type": "text", "text": "result"}},
			})
			fmt.Fprintln(childStdoutW, resp)
		}
	}()

	parentIn := strings.NewReader(makeToolsCallJSON(1, "read_file", map[string]any{"path": "/tmp/x"}) + "\n")
	parentOut := &bytes.Buffer{}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := p.Run(ctx, parentIn, parentOut)
	if err != nil {
		t.Logf("Run ended: %v", err) // EOF is normal
	}

	// Give a moment for the response to propagate
	time.Sleep(50 * time.Millisecond)

	if parentOut.Len() > 0 {
		var resp Response
		if err := json.Unmarshal(bytes.TrimSpace(parentOut.Bytes()), &resp); err == nil {
			if resp.Error != nil {
				t.Errorf("unexpected error in response: %s", resp.Error.Message)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Test: Security bypass scenarios
// ---------------------------------------------------------------------------

func TestSecurityBypass_MethodCaseSensitivity(t *testing.T) {
	eng := buildDenyAllEngine(t)
	childIn := &bytes.Buffer{}
	parentOut := &bytes.Buffer{}
	sink := &mockSink{}

	p := NewProxy(eng, sink, nopWriteCloser{childIn}, strings.NewReader(""),
		WithMode("enforce"), WithLogger(silentLogger()))
	p.parentOut = parentOut

	// Try uppercase method — should NOT be caught as tools/call
	line := `{"jsonrpc":"2.0","id":1,"method":"Tools/Call","params":{"name":"exec_command","arguments":{"command":"whoami"}}}` + "\n"
	err := p.handleClientLine([]byte(line))
	if err != nil {
		t.Fatalf("handleClientLine: %v", err)
	}

	// This bypasses the check (method is case-sensitive in JSON-RPC).
	// Document that this is expected behavior — MCP method names are case-sensitive.
	// The line should be forwarded to child since it doesn't match "tools/call".
	if childIn.Len() == 0 {
		t.Log("Non-matching method forwarded (expected — method names are case-sensitive)")
	}
}

func TestSecurityBypass_ExtraFieldsInParams(t *testing.T) {
	eng := buildDenyAllEngine(t)
	childIn := &bytes.Buffer{}
	parentOut := &bytes.Buffer{}
	sink := &mockSink{}

	p := NewProxy(eng, sink, nopWriteCloser{childIn}, strings.NewReader(""),
		WithMode("enforce"), WithLogger(silentLogger()))
	p.parentOut = parentOut

	// Extra fields in params shouldn't bypass policy
	line := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec_command","arguments":{"command":"whoami"},"extra":"field"}}` + "\n"
	err := p.handleClientLine([]byte(line))
	if err != nil {
		t.Fatalf("handleClientLine: %v", err)
	}

	if childIn.Len() != 0 {
		t.Error("extra fields should not bypass deny policy")
	}
}

func TestSecurityBypass_DuplicateID(t *testing.T) {
	eng := buildAllowAllEngine(t)
	childIn := &bytes.Buffer{}
	parentOut := &bytes.Buffer{}
	sink := &mockSink{}

	p := NewProxy(eng, sink, nopWriteCloser{childIn}, strings.NewReader(""),
		WithLogger(silentLogger()))
	p.parentOut = parentOut

	// Two calls with the same outstanding ID are invalid JSON-RPC. The second
	// must not overwrite response-policy correlation for the first.
	line1 := []byte(makeToolsCallJSON(1, "read_file", map[string]any{"path": "/a"}) + "\n")
	line2 := []byte(makeToolsCallJSON(1, "write_file", map[string]any{"path": "/b"}) + "\n")

	if err := p.handleClientLine(line1); err != nil {
		t.Fatal(err)
	}
	if err := p.handleClientLine(line2); err != nil {
		t.Fatal(err)
	}

	p.pendingMu.Lock()
	pending, ok := p.pendingCalls[NormalizedID(json.RawMessage(`1`))]
	p.pendingMu.Unlock()

	if !ok {
		t.Fatal("expected pending call")
	}
	if pending.request["mcp_tool"] != "read_file" {
		t.Errorf("first pending call was overwritten; got tool=%v", pending.request["mcp_tool"])
	}
	if strings.Count(childIn.String(), "\n") != 1 {
		t.Fatalf("duplicate request reached child: %q", childIn.String())
	}
	if !strings.Contains(parentOut.String(), "already pending") {
		t.Fatalf("duplicate request did not receive protocol error: %s", parentOut.String())
	}
}

func TestPendingToolListCapacityFailsClosed(t *testing.T) {
	eng := buildAllowAllEngine(t)
	childIn := &bytes.Buffer{}
	parentOut := &bytes.Buffer{}
	p := NewProxy(eng, &mockSink{}, nopWriteCloser{childIn}, strings.NewReader(""),
		WithFilterTools(true), WithMode("enforce"), WithLogger(silentLogger()))
	p.parentOut = parentOut

	for index := 0; index < maxPendingRequests; index++ {
		p.pendingToolList[fmt.Sprintf("%d", index)] = struct{}{}
	}
	line := []byte(`{"jsonrpc":"2.0","id":"overflow","method":"tools/list","params":{}}` + "\n")
	if err := p.handleClientLine(line); err != nil {
		t.Fatal(err)
	}
	if childIn.Len() != 0 {
		t.Fatal("untracked tools/list request reached child at capacity")
	}
	if !strings.Contains(parentOut.String(), "pending tools/list capacity reached") {
		t.Fatalf("unexpected client response: %s", parentOut.String())
	}
}

func TestPendingToolCallCapacityNeverAgeEvictsSecurityCorrelation(t *testing.T) {
	eng := buildAllowAllEngine(t)
	childIn := &bytes.Buffer{}
	parentOut := &bytes.Buffer{}
	p := NewProxy(eng, &mockSink{}, nopWriteCloser{childIn}, strings.NewReader(""),
		WithMode("enforce"), WithLogger(silentLogger()))
	p.parentOut = parentOut

	// Zero-valued pending entries are older than any TTL. They model child
	// calls whose responses are delayed indefinitely; bounded correlation must
	// remain fail-closed instead of being silently forgotten.
	for index := 0; index < maxPendingRequests; index++ {
		p.pendingCalls[fmt.Sprintf("old-%d", index)] = pendingCall{state: pendingCallResponseActive}
	}
	line := []byte(makeToolsCallJSON("overflow", "read_file", map[string]any{"path": "/tmp/x"}) + "\n")
	require.NoError(t, p.handleClientLine(line))
	assert.Empty(t, childIn.String())
	assert.Contains(t, parentOut.String(), "pending tools/call capacity reached")
	assert.Len(t, p.pendingCalls, maxPendingRequests)
}

// ---------------------------------------------------------------------------
// Test: Options
// ---------------------------------------------------------------------------

func TestWithToolMapping(t *testing.T) {
	eng := buildAllowAllEngine(t)
	sink := &mockSink{}

	p := NewProxy(eng, sink, nopWriteCloser{&bytes.Buffer{}}, strings.NewReader(""),
		WithToolMapping(map[string]string{"my_exec": "shell"}),
		WithLogger(silentLogger()))

	if p.toolMapping["my_exec"] != "shell" {
		t.Errorf("expected mapping my_exec->shell, got %v", p.toolMapping)
	}
}

func TestWithToolMapping_Nil(t *testing.T) {
	eng := buildAllowAllEngine(t)
	sink := &mockSink{}

	p := NewProxy(eng, sink, nopWriteCloser{&bytes.Buffer{}}, strings.NewReader(""),
		WithToolMapping(nil),
		WithLogger(silentLogger()))

	if p.toolMapping != nil {
		t.Error("nil mapping should set toolMapping to nil")
	}
}

func TestWithMode_Default(t *testing.T) {
	eng := buildAllowAllEngine(t)
	p := NewProxy(eng, nil, nopWriteCloser{&bytes.Buffer{}}, strings.NewReader(""))
	if p.mode != "enforce" {
		t.Errorf("expected default mode 'enforce', got %q", p.mode)
	}
}

func TestWithMode_Empty(t *testing.T) {
	eng := buildAllowAllEngine(t)
	p := NewProxy(eng, nil, nopWriteCloser{&bytes.Buffer{}}, strings.NewReader(""),
		WithMode(""))
	if p.mode != "enforce" {
		t.Errorf("expected default mode 'enforce' for empty string, got %q", p.mode)
	}
}

func TestWithMode_NormalizesKnownValuesAndFailsClosedForUnknown(t *testing.T) {
	eng := buildDenyAllEngine(t)
	for _, test := range []struct {
		mode string
		want string
	}{
		{mode: " MONITOR ", want: "monitor"},
		{mode: "ENFORCE", want: "enforce"},
		{mode: "disabled", want: "enforce"},
		{mode: "typo", want: "enforce"},
	} {
		t.Run(test.mode, func(t *testing.T) {
			childIn := &bytes.Buffer{}
			p := NewProxy(eng, &mockSink{}, nopWriteCloser{childIn}, strings.NewReader(""),
				WithMode(test.mode), WithLogger(silentLogger()))
			p.parentOut = &bytes.Buffer{}
			if p.mode != test.want {
				t.Fatalf("mode = %q, want %q", p.mode, test.want)
			}
			if err := p.handleClientLine([]byte(makeToolsCallJSON(1, "execute_command", map[string]any{"command": "whoami"}) + "\n")); err != nil {
				t.Fatal(err)
			}
			if test.want == "enforce" && childIn.Len() != 0 {
				t.Fatal("unknown/enforce mode failed open")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: buildRequestData
// ---------------------------------------------------------------------------

func TestBuildRequestData(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		tool     string
		args     map[string]any
		checkKey string
		checkVal any
	}{
		{
			name:     "basic",
			method:   "tools/call",
			tool:     "read_file",
			args:     map[string]any{"path": "/etc/hosts"},
			checkKey: "mcp_tool",
			checkVal: "read_file",
		},
		{
			name:     "command extraction",
			method:   "tools/call",
			tool:     "exec",
			args:     map[string]any{"cmd": "ls -la"},
			checkKey: "command",
			checkVal: "ls -la",
		},
		{
			name:     "url parsing",
			method:   "tools/call",
			tool:     "fetch",
			args:     map[string]any{"url": "https://example.com/path"},
			checkKey: "domain",
			checkVal: "example.com",
		},
		{
			name:     "url path extraction",
			method:   "tools/call",
			tool:     "fetch",
			args:     map[string]any{"url": "https://example.com/api/v1"},
			checkKey: "path",
			checkVal: "/api/v1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildRequestData(tt.method, tt.tool, tt.args)
			if result[tt.checkKey] != tt.checkVal {
				t.Errorf("%s: expected %v, got %v", tt.checkKey, tt.checkVal, result[tt.checkKey])
			}
		})
	}
}

func TestBuildRequestData_URLWithExistingPath(t *testing.T) {
	// If "path" is already in arguments, URL-derived path shouldn't overwrite
	args := map[string]any{
		"path": "/existing",
		"url":  "https://example.com/from-url",
	}
	result := buildRequestData("tools/call", "fetch", args)
	if result["path"] != "/existing" {
		t.Errorf("existing path should not be overwritten; got %v", result["path"])
	}
}

func TestBuildRequestData_URLOverridesCallerDerivedMetadata(t *testing.T) {
	result := buildRequestData("tools/call", "fetch", map[string]any{
		"url":    "https://webhook.site/collect",
		"domain": "github.com",
		"scheme": "file",
	})
	if result["domain"] != "webhook.site" || result["scheme"] != "https" {
		t.Fatalf("derived metadata = domain %v scheme %v", result["domain"], result["scheme"])
	}
}

// ---------------------------------------------------------------------------
// Test: extractResponseBody
// ---------------------------------------------------------------------------

func TestExtractResponseBody(t *testing.T) {
	tests := []struct {
		name   string
		fields map[string]json.RawMessage
		expect string
	}{
		{
			name:   "with result",
			fields: map[string]json.RawMessage{"result": json.RawMessage(`{"content":"hello"}`)},
			expect: `{"content":"hello"}` + "\n" + `{"content":"hello"}`,
		},
		{
			name:   "with error",
			fields: map[string]json.RawMessage{"error": json.RawMessage(`{"code":-1,"message":"fail","data":"detail"}`)},
			expect: `{"code":-1,"message":"fail","data":"detail"}` + "\n" + `{"code":-1,"data":"detail","message":"fail"}`,
		},
		{
			name:   "empty",
			fields: map[string]json.RawMessage{},
			expect: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractResponseBody(tt.fields)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.expect {
				t.Errorf("expected %q, got %q", tt.expect, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: ensureTrailingNewline
// ---------------------------------------------------------------------------

func TestEnsureTrailingNewline(t *testing.T) {
	tests := []struct {
		input    []byte
		expected []byte
	}{
		{[]byte("hello"), []byte("hello\n")},
		{[]byte("hello\n"), []byte("hello\n")},
		{[]byte(""), []byte("\n")},
		{nil, []byte("\n")},
	}

	for _, tt := range tests {
		got := ensureTrailingNewline(tt.input)
		if !bytes.Equal(got, tt.expected) {
			t.Errorf("ensureTrailingNewline(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: Audit events
// ---------------------------------------------------------------------------

func TestAuditEventsWritten(t *testing.T) {
	eng := buildAllowAllEngine(t)
	childIn := &bytes.Buffer{}
	sink := &mockSink{}

	p := NewProxy(eng, sink, nopWriteCloser{childIn}, strings.NewReader(""),
		WithLogger(silentLogger()))
	p.parentOut = &bytes.Buffer{}

	line := []byte(makeToolsCallJSON(1, "read_file", map[string]any{"path": "/tmp"}) + "\n")
	p.handleClientLine(line)

	events := sink.getEvents()
	if len(events) == 0 {
		t.Fatal("expected audit event for tools/call")
	}
	if events[0].Tool != "file_read" || events[0].Tool != MapToolName("read_file", nil) {
		// Just check it was written with some tool
		if events[0].Tool == "" {
			t.Error("audit event should have tool set")
		}
	}
}

func TestAuditNilSink(t *testing.T) {
	eng := buildAllowAllEngine(t)
	childIn := &bytes.Buffer{}

	// nil sink should not panic
	p := NewProxy(eng, nil, nopWriteCloser{childIn}, strings.NewReader(""),
		WithLogger(silentLogger()))
	p.parentOut = &bytes.Buffer{}

	line := []byte(makeToolsCallJSON(1, "read_file", map[string]any{"path": "/tmp"}) + "\n")
	err := p.handleClientLine(line)
	if err != nil {
		t.Fatalf("unexpected error with nil sink: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Engine builders using real policy YAML
// ---------------------------------------------------------------------------

func buildAllowAllEngine(t *testing.T) *engine.Engine {
	t.Helper()
	return buildTestEngine(t, `
default_action: allow
policies: []
`)
}

func buildDenyAllEngine(t *testing.T) *engine.Engine {
	t.Helper()
	return buildTestEngine(t, `
default_action: deny
policies: []
`)
}

func buildAskEngine(t *testing.T) *engine.Engine {
	t.Helper()
	return buildTestEngine(t, `
default_action: allow
policies:
  - name: require-approval
    match:
      tool: "*"
    rules:
      - action: ask
        when:
          default: true
`)
}

func buildDenyExecEngine(t *testing.T) *engine.Engine {
	t.Helper()
	return buildTestEngine(t, `
default_action: allow
policies:
  - name: deny-exec
    match:
      tool: "exec"
    rules:
      - action: deny
        when:
          default: true
`)
}

func buildResponseDenyEngine(t *testing.T) *engine.Engine {
	t.Helper()
	return buildTestEngine(t, `
default_action: allow
policies:
  - name: block-secrets
    match:
      tool: "*"
    rules:
      - action: deny
        message: "response contains secrets"
        when:
          response_matches:
            - "SECRET_TOKEN"
`)
}
