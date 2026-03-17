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
	"github.com/peg/rampart/internal/engine"
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
	// Read the connect request (type-frame protocol).
	_, msg, err := conn.ReadMessage()
	if err != nil {
		return
	}

	var req gatewayRequest
	json.Unmarshal(msg, &req)

	// Respond with a type-frame res.
	resp := map[string]any{
		"type":   "res",
		"id":     req.ID,
		"result": map[string]any{"type": "hello-ok"},
	}
	data, _ := json.Marshal(resp)
	conn.WriteMessage(websocket.TextMessage, data)

	close(mg.ready)
}

func (mg *mockGateway) sendApprovalRequest(id, command, agent string) {
	<-mg.ready
	payload, _ := json.Marshal(approvalRequestParams{
		ID:         id,
		Command:    command,
		AgentID:    agent,
		SessionKey: "test-session",
	})

	// Type-frame event format.
	msg := map[string]any{
		"type":    "event",
		"event":   "exec.approval.requested",
		"payload": json.RawMessage(payload),
		"seq":     1,
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
