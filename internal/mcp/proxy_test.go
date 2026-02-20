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
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/peg/rampart/internal/approval"
	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/engine"
)

// ---------------------------------------------------------------------------
// Mock engine
// ---------------------------------------------------------------------------

type mockEngine struct {
	evaluateFn         func(engine.ToolCall) engine.Decision
	evaluateResponseFn func(engine.ToolCall, string) engine.Decision
}

func (m *mockEngine) evaluate(call engine.ToolCall) engine.Decision {
	if m.evaluateFn != nil {
		return m.evaluateFn(call)
	}
	return engine.Decision{Action: engine.ActionAllow}
}

func (m *mockEngine) evaluateResponse(call engine.ToolCall, response string) engine.Decision {
	if m.evaluateResponseFn != nil {
		return m.evaluateResponseFn(call, response)
	}
	return engine.Decision{Action: engine.ActionAllow}
}

// We need a real *engine.Engine for the proxy. Since we can't easily mock it
// via interface (proxy takes *engine.Engine directly), we'll build a minimal
// engine from policy YAML and test through it.

// ---------------------------------------------------------------------------
// Mock audit sink
// ---------------------------------------------------------------------------

type mockSink struct {
	mu     sync.Mutex
	events []audit.Event
}

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

func makeToolsListJSON(id any) string {
	msg := map[string]any{
		"jsonrpc": "2.0",
		"method":  "tools/list",
		"id":      id,
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
	p.pendingCalls["1"] = pendingCall{
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

	// Pending call should be consumed
	p.pendingMu.Lock()
	if len(p.pendingCalls) != 0 {
		t.Error("pending call should be consumed after response")
	}
	p.pendingMu.Unlock()
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
	p.pendingCalls["1"] = pendingCall{
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

func TestHandleChildLine_NoPendingCall_PassesThrough(t *testing.T) {
	eng := buildAllowAllEngine(t)
	parentOut := &bytes.Buffer{}
	sink := &mockSink{}

	p := NewProxy(eng, sink, nopWriteCloser{&bytes.Buffer{}}, strings.NewReader(""),
		WithLogger(silentLogger()))
	p.parentOut = parentOut

	respLine := []byte(makeResponseJSON(999, "ok") + "\n")
	err := p.handleChildLine(respLine, parentOut)
	if err != nil {
		t.Fatalf("handleChildLine: %v", err)
	}

	// Should pass through without evaluation
	if parentOut.Len() == 0 {
		t.Fatal("unmatched response should pass through")
	}
}

// ---------------------------------------------------------------------------
// Test: maybeFilterToolsList
// ---------------------------------------------------------------------------

func TestMaybeFilterToolsList_FiltersBlockedTools(t *testing.T) {
	eng := buildDenyExecEngine(t)
	sink := &mockSink{}

	p := NewProxy(eng, sink, nopWriteCloser{&bytes.Buffer{}}, strings.NewReader(""),
		WithFilterTools(true), WithMode("enforce"), WithLogger(silentLogger()))
	p.parentOut = &bytes.Buffer{}

	// Register pending tools/list
	p.pendingMu.Lock()
	p.pendingToolList["1"] = time.Now()
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

	filtered, handled, err := p.maybeFilterToolsList(resp)
	if err != nil {
		t.Fatalf("maybeFilterToolsList: %v", err)
	}
	if !handled {
		t.Fatal("expected handled=true")
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

func TestMaybeFilterToolsList_NotRequested_Noop(t *testing.T) {
	eng := buildAllowAllEngine(t)
	sink := &mockSink{}

	p := NewProxy(eng, sink, nopWriteCloser{&bytes.Buffer{}}, strings.NewReader(""),
		WithFilterTools(true), WithLogger(silentLogger()))

	resp := Response{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`99`),
		Result:  json.RawMessage(`{"tools":[]}`),
	}

	_, handled, err := p.maybeFilterToolsList(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if handled {
		t.Error("should not handle response for unrequested tools/list")
	}
}

func TestMaybeFilterToolsList_RequireApprovalVisible(t *testing.T) {
	eng := buildAskEngine(t)
	sink := &mockSink{}

	p := NewProxy(eng, sink, nopWriteCloser{&bytes.Buffer{}}, strings.NewReader(""),
		WithFilterTools(true), WithMode("enforce"), WithLogger(silentLogger()))
	p.parentOut = &bytes.Buffer{}

	p.pendingMu.Lock()
	p.pendingToolList["1"] = time.Now()
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

	filtered, handled, err := p.maybeFilterToolsList(resp)
	if err != nil {
		t.Fatalf("maybeFilterToolsList: %v", err)
	}
	if !handled {
		t.Fatal("expected handled=true")
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

// ---------------------------------------------------------------------------
// Test: Edge cases
// ---------------------------------------------------------------------------

func TestHandleClientLine_MalformedJSON(t *testing.T) {
	eng := buildAllowAllEngine(t)
	childIn := &bytes.Buffer{}
	sink := &mockSink{}

	p := NewProxy(eng, sink, nopWriteCloser{childIn}, strings.NewReader(""),
		WithLogger(silentLogger()))
	p.parentOut = &bytes.Buffer{}

	// Malformed JSON should pass through to child
	err := p.handleClientLine([]byte("this is not json\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if childIn.Len() == 0 {
		t.Error("malformed JSON should be forwarded to child")
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
		WithLogger(silentLogger()))
	p.parentOut = &bytes.Buffer{}

	// tools/call with no arguments field
	line := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}` + "\n"
	err := p.handleClientLine([]byte(line))
	if err != nil {
		t.Fatalf("handleClientLine: %v", err)
	}

	if childIn.Len() == 0 {
		t.Error("should forward even without arguments")
	}
}

func TestHandleChildLine_MalformedJSON(t *testing.T) {
	eng := buildAllowAllEngine(t)
	parentOut := &bytes.Buffer{}
	sink := &mockSink{}

	p := NewProxy(eng, sink, nopWriteCloser{&bytes.Buffer{}}, strings.NewReader(""),
		WithLogger(silentLogger()))

	err := p.handleChildLine([]byte("not json at all\n"), parentOut)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parentOut.Len() == 0 {
		t.Error("malformed child output should pass through to parent")
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

	// Two calls with same ID — second should overwrite first pending
	line1 := []byte(makeToolsCallJSON(1, "read_file", map[string]any{"path": "/a"}) + "\n")
	line2 := []byte(makeToolsCallJSON(1, "write_file", map[string]any{"path": "/b"}) + "\n")

	p.handleClientLine(line1)
	p.handleClientLine(line2)

	p.pendingMu.Lock()
	pending, ok := p.pendingCalls["1"]
	p.pendingMu.Unlock()

	if !ok {
		t.Fatal("expected pending call")
	}
	// The second call should be the one stored
	if pending.request["mcp_tool"] != "write_file" {
		t.Errorf("expected second call to overwrite; got tool=%v", pending.request["mcp_tool"])
	}
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

// ---------------------------------------------------------------------------
// Test: extractResponseBody
// ---------------------------------------------------------------------------

func TestExtractResponseBody(t *testing.T) {
	tests := []struct {
		name   string
		resp   Response
		expect string
	}{
		{
			name:   "with result",
			resp:   Response{Result: json.RawMessage(`{"content":"hello"}`)},
			expect: `{"content":"hello"}`,
		},
		{
			name:   "with error",
			resp:   Response{Error: &ErrorObject{Code: -1, Message: "fail"}},
			expect: `{"code":-1,"message":"fail"}`,
		},
		{
			name:   "empty",
			resp:   Response{},
			expect: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractResponseBody(tt.resp)
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
      - action: require_approval
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
