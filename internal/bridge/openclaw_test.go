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

package bridge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockGateway simulates an OpenClaw Gateway WebSocket server.
type mockGateway struct {
	t        *testing.T
	server   *httptest.Server
	upgrader websocket.Upgrader
	conn     *websocket.Conn
	writeMu  sync.Mutex
	ready    chan struct{}
}

func newMockGateway(t *testing.T) *mockGateway {
	mg := &mockGateway{
		t:        t,
		upgrader: websocket.Upgrader{},
		ready:    make(chan struct{}),
	}

	mg.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := mg.upgrader.Upgrade(w, r, nil)
		require.NoError(t, err)
		mg.writeMu.Lock()
		mg.conn = conn
		mg.writeMu.Unlock()
		mg.handleConnection(conn)
	}))

	return mg
}

func (mg *mockGateway) url() string {
	return "ws" + strings.TrimPrefix(mg.server.URL, "http")
}

func (mg *mockGateway) handleConnection(conn *websocket.Conn) {
	// Step 1: send connect.challenge.
	challenge := map[string]any{
		"type":    "event",
		"event":   "connect.challenge",
		"payload": map[string]any{"nonce": "test-nonce-abc123"},
		"seq":     0,
	}
	data, _ := json.Marshal(challenge)
	conn.WriteMessage(websocket.TextMessage, data)

	// Step 2: read connect request.
	_, msg, err := conn.ReadMessage()
	if err != nil {
		return
	}
	var req gatewayRequest
	json.Unmarshal(msg, &req)

	// Step 3: respond with hello-ok.
	resp := map[string]any{
		"type":    "res",
		"id":      req.ID,
		"ok":      true,
		"payload": map[string]any{"type": "hello-ok"},
	}
	data, _ = json.Marshal(resp)
	conn.WriteMessage(websocket.TextMessage, data)

	close(mg.ready)
}

func (mg *mockGateway) sendApprovalRequest(id, command, agent string) {
	<-mg.ready
	type requestInner struct {
		Command    string `json:"command"`
		AgentID    string `json:"agentId"`
		SessionKey string `json:"sessionKey"`
	}
	payload, _ := json.Marshal(struct {
		ID      string       `json:"id"`
		Request requestInner `json:"request"`
	}{
		ID: id,
		Request: requestInner{
			Command:    command,
			AgentID:    agent,
			SessionKey: "test-session",
		},
	})

	mg.sendEvent("exec.approval.requested", json.RawMessage(payload), 1)
}

func (mg *mockGateway) sendApprovalResolved(id, decision string) {
	<-mg.ready
	payload, _ := json.Marshal(struct {
		ID       string `json:"id"`
		Decision string `json:"decision"`
	}{
		ID:       id,
		Decision: decision,
	})
	mg.sendEvent("exec.approval.resolved", json.RawMessage(payload), 2)
}

func (mg *mockGateway) sendEvent(event string, payload json.RawMessage, seq int) {
	msg := map[string]any{
		"type":    "event",
		"event":   event,
		"payload": payload,
		"seq":     seq,
	}
	data, _ := json.Marshal(msg)
	mg.writeMu.Lock()
	mg.conn.WriteMessage(websocket.TextMessage, data)
	mg.writeMu.Unlock()
}

func (mg *mockGateway) readResponse() map[string]any {
	_, msg, err := mg.conn.ReadMessage()
	require.NoError(mg.t, err)

	// Expect a type-frame req: {"type":"req","id":"...","method":"exec.approval.resolve","params":{...}}
	var frame map[string]any
	json.Unmarshal(msg, &frame)
	return frame
}

func (mg *mockGateway) close() {
	mg.writeMu.Lock()
	conn := mg.conn
	mg.writeMu.Unlock()
	if conn != nil {
		conn.Close()
	}
	mg.server.Close()
}

func writeTestPolicy(t *testing.T, dir string) string {
	t.Helper()
	policy := `version: "1"
default_action: allow
policies:
  - name: block-dangerous
    match:
      tool: exec
    rules:
      - action: deny
        when:
          command_matches:
            - "rm -rf /"
            - "rm -rf ~"
        message: "Destructive command blocked"
`
	path := filepath.Join(dir, "policy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(policy), 0o644))
	return path
}

func newTestEngine(t *testing.T, policyPath string) *engine.Engine {
	t.Helper()
	store := engine.NewFileStore(policyPath)
	eng, err := engine.New(store, nil)
	require.NoError(t, err)
	return eng
}

func TestBridgeAutoResolveAllow(t *testing.T) {
	mg := newMockGateway(t)
	defer mg.close()

	tmpDir := t.TempDir()
	policyPath := writeTestPolicy(t, tmpDir)
	eng := newTestEngine(t, policyPath)

	bridge := NewOpenClawBridge(eng, Config{
		GatewayURL:        mg.url(),
		GatewayToken:      "test-token",
		ReconnectInterval: 100 * time.Millisecond,
	})
	defer bridge.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- bridge.Start(ctx)
	}()

	// Wait for connection.
	time.Sleep(500 * time.Millisecond)

	// Send a safe command — should be auto-allowed.
	mg.sendApprovalRequest("approval-safe", "git status", "claude-code")
	time.Sleep(200 * time.Millisecond)

	resp := mg.readResponse()
	params, ok := resp["params"].(map[string]any)
	require.True(t, ok, "expected params in response")
	assert.Equal(t, "approval-safe", params["id"])
	assert.Equal(t, "allow-once", params["decision"])

	cancel()
}

func TestBridgeAutoResolveDeny(t *testing.T) {
	mg := newMockGateway(t)
	defer mg.close()

	tmpDir := t.TempDir()
	policyPath := writeTestPolicy(t, tmpDir)
	eng := newTestEngine(t, policyPath)

	bridge := NewOpenClawBridge(eng, Config{
		GatewayURL:        mg.url(),
		GatewayToken:      "test-token",
		ReconnectInterval: 100 * time.Millisecond,
	})
	defer bridge.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- bridge.Start(ctx)
	}()

	time.Sleep(500 * time.Millisecond)

	// Send a dangerous command — should be auto-denied.
	mg.sendApprovalRequest("approval-danger", "rm -rf /", "claude-code")
	time.Sleep(200 * time.Millisecond)

	resp := mg.readResponse()
	params, ok := resp["params"].(map[string]any)
	require.True(t, ok, "expected params in response")
	assert.Equal(t, "approval-danger", params["id"])
	assert.Equal(t, "deny", params["decision"])

	cancel()
}

func TestBridgeReconnect(t *testing.T) {
	mg := newMockGateway(t)

	tmpDir := t.TempDir()
	policyPath := writeTestPolicy(t, tmpDir)
	eng := newTestEngine(t, policyPath)

	bridge := NewOpenClawBridge(eng, Config{
		GatewayURL:        mg.url(),
		GatewayToken:      "test-token",
		ReconnectInterval: 200 * time.Millisecond,
	})
	defer bridge.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- bridge.Start(ctx)
	}()

	// Wait for initial connection.
	time.Sleep(500 * time.Millisecond)

	// Close the gateway to simulate a disconnect.
	mg.close()

	// Start a new gateway on a different port — we can't reuse the same URL,
	// so instead just verify the bridge doesn't crash and attempts reconnect.
	// Give it time to attempt reconnect.
	time.Sleep(400 * time.Millisecond)

	// The bridge should still be running (reconnecting), not crashed.
	select {
	case err := <-errCh:
		// Context cancel is expected, real errors are not.
		if ctx.Err() == nil {
			t.Fatalf("bridge exited unexpectedly: %v", err)
		}
	default:
		// Still running — good, it's trying to reconnect.
	}

	cancel()
}

func TestDiscoverGatewayConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "openclaw.json")

	config := map[string]any{
		"gateway": map[string]any{
			"url": "ws://127.0.0.1:18789/ws",
			"auth": map[string]any{
				"token": "test-gateway-token-123",
			},
		},
	}
	data, err := json.Marshal(config)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(configPath, data, 0o644))

	url, token, err := ReadGatewayConfig(configPath)
	require.NoError(t, err)
	assert.Equal(t, "ws://127.0.0.1:18789/ws", url)
	assert.Equal(t, "test-gateway-token-123", token)
}

func TestDiscoverGatewayConfigDefaultURL(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "openclaw.json")

	// No URL set — should default to ws://127.0.0.1:18789/ws
	config := map[string]any{
		"gateway": map[string]any{
			"auth": map[string]any{
				"token": "tok",
			},
		},
	}
	data, err := json.Marshal(config)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(configPath, data, 0o644))

	url, token, err := ReadGatewayConfig(configPath)
	require.NoError(t, err)
	assert.Equal(t, "ws://127.0.0.1:18789/ws", url)
	assert.Equal(t, "tok", token)
}

func TestDiscoverGatewayConfigMissingToken(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "openclaw.json")

	config := map[string]any{
		"gateway": map[string]any{
			"auth": map[string]any{},
		},
	}
	data, err := json.Marshal(config)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(configPath, data, 0o644))

	_, _, err = ReadGatewayConfig(configPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no gateway.auth.token")
}

func TestDiscoverGatewayConfigMissingFile(t *testing.T) {
	_, _, err := ReadGatewayConfig("/nonexistent/openclaw.json")
	assert.Error(t, err)
}

// TestWriteAllowAlwaysRule verifies that writeAllowAlwaysRule creates a YAML
// policy file with the correct structure for an allow rule.
func TestWriteAllowAlwaysRule(t *testing.T) {
	tmpDir := t.TempDir()

	// Override HOME (Linux/macOS) and USERPROFILE (Windows) so
	// writeAllowAlwaysRule writes to our temp dir on all platforms.
	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)

	eng := newTestEngine(t, writeTestPolicy(t, tmpDir))
	b := NewOpenClawBridge(eng, Config{
		GatewayURL:   "ws://127.0.0.1:1",
		GatewayToken: "test-token",
	})

	const testCmd = "echo hello-world"
	b.writeAllowAlwaysRule(testCmd)

	overridesPath := filepath.Join(tmpDir, ".rampart", "policies", "user-overrides.yaml")
	data, err := os.ReadFile(overridesPath)
	if err != nil {
		t.Fatalf("user-overrides.yaml not written: %v", err)
	}

	content := string(data)

	// Must contain the tool: exec match.
	if !strings.Contains(content, "tool: exec") {
		t.Errorf("expected 'tool: exec' in overrides, got:\n%s", content)
	}

	// Must contain the command in the command_matches list.
	if !strings.Contains(content, testCmd) {
		t.Errorf("expected command %q in overrides, got:\n%s", testCmd, content)
	}

	// Must contain the allow action.
	if !strings.Contains(content, "action: allow") {
		t.Errorf("expected 'action: allow' in overrides, got:\n%s", content)
	}

	// Must NOT write a duplicate rule on second call.
	b.writeAllowAlwaysRule(testCmd)
	data2, _ := os.ReadFile(overridesPath)
	if strings.Count(string(data2), testCmd) > strings.Count(content, testCmd) {
		t.Error("duplicate rule written on second call to writeAllowAlwaysRule")
	}
}

// TestHandleApprovalRequestedAsk is a regression test for the bug where
// ActionAsk commands were not stored in pendingCommands, breaking allow-always
// writeback when the user clicked "Always Allow" in the Discord approval UI.
func TestHandleApprovalRequestedAskStoresPendingCommand(t *testing.T) {
	tmpDir := t.TempDir()

	// Write a policy that returns ActionAsk for the sudo command.
	askPolicy := `version: "1"
default_action: deny
policies:
  - name: ask-sudo
    match:
      tool: exec
    rules:
      - action: ask
        when:
          command_matches:
            - "sudo *"
        message: "sudo command — approve or deny?"
`
	policyPath := filepath.Join(tmpDir, "ask-policy.yaml")
	if err := os.WriteFile(policyPath, []byte(askPolicy), 0o644); err != nil {
		t.Fatal(err)
	}

	mg := newMockGateway(t)
	defer mg.close()

	eng := newTestEngine(t, policyPath)
	b := NewOpenClawBridge(eng, Config{
		GatewayURL:        mg.url(),
		GatewayToken:      "test-token",
		ReconnectInterval: 100 * time.Millisecond,
	})
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() { b.Start(ctx) }() //nolint:errcheck

	// Wait for connection to establish.
	time.Sleep(500 * time.Millisecond)

	const approvalID = "ask-approval-001"
	const testCmd = "sudo systemctl restart nginx"

	mg.sendApprovalRequest(approvalID, testCmd, "claude-code")

	// Give the bridge time to evaluate and update pendingCommands.
	time.Sleep(300 * time.Millisecond)

	b.pendingMu.Lock()
	cmd, stored := b.pendingCommands[approvalID]
	b.pendingMu.Unlock()

	if !stored {
		t.Errorf("expected command to be stored in pendingCommands for ActionAsk, but it was not")
	} else if cmd != testCmd {
		t.Errorf("expected pendingCommands[%q] = %q, got %q", approvalID, testCmd, cmd)
	}

	cancel()
}

func TestHandleApprovalRequestedAskLeavesApprovalPending(t *testing.T) {
	tmpDir := t.TempDir()

	askPolicy := `version: "1"
default_action: deny
policies:
  - name: ask-sudo
    match:
      tool: exec
    rules:
      - action: ask
        when:
          command_matches:
            - "sudo *"
        message: "sudo command — approve or deny?"
`
	policyPath := filepath.Join(tmpDir, "ask-policy.yaml")
	if err := os.WriteFile(policyPath, []byte(askPolicy), 0o644); err != nil {
		t.Fatal(err)
	}

	mg := newMockGateway(t)
	defer mg.close()

	eng := newTestEngine(t, policyPath)
	b := NewOpenClawBridge(eng, Config{
		GatewayURL:        mg.url(),
		GatewayToken:      "test-token",
		ReconnectInterval: 100 * time.Millisecond,
	})
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { b.Start(ctx) }() //nolint:errcheck

	time.Sleep(500 * time.Millisecond)

	const approvalID = "ask-approval-pending-001"
	mg.sendApprovalRequest(approvalID, "sudo true", "claude-code")
	time.Sleep(300 * time.Millisecond)

	b.pendingMu.Lock()
	_, stillStored := b.pendingCommands[approvalID]
	b.pendingMu.Unlock()
	if !stillStored {
		t.Fatalf("expected ask approval command to remain stored until human resolution")
	}
}

func TestResolvedAllowAlwaysWritesRuleAndCleansPendingCommand(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)

	askPolicy := `version: "1"
default_action: deny
policies:
  - name: ask-sudo
    match:
      tool: exec
    rules:
      - action: ask
        when:
          command_matches:
            - "sudo *"
        message: "sudo command — approve or deny?"
`
	policyPath := filepath.Join(tmpDir, "ask-policy.yaml")
	if err := os.WriteFile(policyPath, []byte(askPolicy), 0o644); err != nil {
		t.Fatal(err)
	}

	mg := newMockGateway(t)
	defer mg.close()

	eng := newTestEngine(t, policyPath)
	b := NewOpenClawBridge(eng, Config{
		GatewayURL:        mg.url(),
		GatewayToken:      "test-token",
		ReconnectInterval: 100 * time.Millisecond,
	})
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { b.Start(ctx) }() //nolint:errcheck

	time.Sleep(500 * time.Millisecond)

	const approvalID = "ask-approval-resolved-001"
	const testCmd = "sudo systemctl restart nginx"
	mg.sendApprovalRequest(approvalID, testCmd, "claude-code")
	time.Sleep(300 * time.Millisecond)
	mg.sendApprovalResolved(approvalID, "allow-always")
	time.Sleep(300 * time.Millisecond)

	overridesPath := filepath.Join(tmpDir, ".rampart", "policies", "user-overrides.yaml")
	data, err := os.ReadFile(overridesPath)
	if err != nil {
		t.Fatalf("user-overrides.yaml not written after allow-always resolution: %v", err)
	}
	if !strings.Contains(string(data), testCmd) {
		t.Fatalf("expected allow-always writeback for %q, got:\n%s", testCmd, string(data))
	}

	b.pendingMu.Lock()
	_, stillStored := b.pendingCommands[approvalID]
	b.pendingMu.Unlock()
	if stillStored {
		t.Fatalf("expected pending command to be cleaned after resolved event")
	}
}

// TestBridgeAuditSinkWrite verifies that bridge-evaluated approvals are written
// to the audit sink, fixing the empty-params audit trail bug.
func TestBridgeAuditSinkWrite(t *testing.T) {
	mg := newMockGateway(t)
	defer mg.close()

	tmpDir := t.TempDir()
	policyPath := writeTestPolicy(t, tmpDir)
	eng := newTestEngine(t, policyPath)

	// Simple in-memory audit sink for testing.
	var mu sync.Mutex
	var written []audit.Event
	sink := &testAuditSink{writeFn: func(ev audit.Event) error {
		mu.Lock()
		written = append(written, ev)
		mu.Unlock()
		return nil
	}}

	b := NewOpenClawBridge(eng, Config{
		GatewayURL:        mg.url(),
		GatewayToken:      "test-token",
		ReconnectInterval: 100 * time.Millisecond,
		AuditSink:         sink,
	})
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() { b.Start(ctx) }() //nolint:errcheck

	time.Sleep(500 * time.Millisecond)

	mg.sendApprovalRequest("audit-test-001", "go test ./...", "test-agent")
	time.Sleep(300 * time.Millisecond)

	// Consume the gateway response to unblock.
	mg.readResponse()

	mu.Lock()
	n := len(written)
	var ev audit.Event
	if n > 0 {
		ev = written[0]
	}
	mu.Unlock()

	if n == 0 {
		t.Fatal("expected audit event to be written, got none")
	}
	if ev.Tool != "exec" {
		t.Errorf("expected Tool=exec, got %q", ev.Tool)
	}
	if ev.Agent != "test-agent" {
		t.Errorf("expected Agent=test-agent, got %q", ev.Agent)
	}
	if ev.Request == nil {
		t.Error("expected non-nil Request params in audit event")
	} else if ev.Request["command"] != "go test ./..." {
		t.Errorf("expected command in audit Request, got %v", ev.Request)
	}
	if ev.ID == "" {
		t.Error("expected non-empty event ID")
	}

	cancel()
}

// testAuditSink is a minimal in-memory AuditSink for tests.
type testAuditSink struct {
	writeFn func(audit.Event) error
}

func (s *testAuditSink) Write(ev audit.Event) error {
	if s.writeFn != nil {
		return s.writeFn(ev)
	}
	return nil
}
func (s *testAuditSink) Flush() error { return nil }
func (s *testAuditSink) Close() error { return nil }

func TestBuildAllowPattern(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// 3+ tokens: replace last arg with *
		{"sudo apt-get install nmap", "sudo apt-get install *"},
		{"kubectl apply -f prod.yaml", "kubectl apply -f prod.yaml"},
		{"docker run nginx", "docker run nginx"},
		{"curl https://example.com/install.sh", "curl https://example.com/install.sh"},
		{"chmod 600 /etc/shadow", "chmod 600 /etc/shadow"},
		{"npm install lodash", "npm install *"},
		// Strip pipes and redirection first
		{"sudo apt-get install nmap --dry-run 2>&1 | head -1", "sudo apt-get install nmap *"},
		{"cat /etc/passwd > /tmp/out", "cat /etc/passwd *"}, // 2 tokens after strip, path-like → append *
		{"ls -la >> log.txt", "ls -la"},                     // 2 tokens after strip, no dot/slash → as-is
		{"some-cmd 2> /dev/null", "some-cmd"},               // 1 token after strip → as-is
		// git commit -m "message" — quoted args become multiple fields
		{"git commit -m fix-bug", "git commit -m *"},
		// Short commands (1-2 tokens)
		{"ls", "ls"},
		{"whoami", "whoami"},
		{"cat /etc/hosts", "cat /etc/hosts *"},       // path-like → append *
		{"python3 script.py", "python3 script.py *"}, // dot → append *
		{"echo hello", "echo hello"},                 // no dot/slash → keep as-is
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := policy.BuildAllowPattern(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}
