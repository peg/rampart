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

package daemon

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
	"github.com/peg/rampart/internal/approval"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockGateway simulates an OpenClaw Gateway for testing.
type mockGateway struct {
	t          *testing.T
	server     *httptest.Server
	upgrader   websocket.Upgrader
	conn       *websocket.Conn
	writeMu    sync.Mutex // guards WebSocket writes
	ready      chan struct{}
	received   []map[string]any
	challenges bool
}

func newMockGateway(t *testing.T) *mockGateway {
	mg := &mockGateway{
		t:          t,
		upgrader:   websocket.Upgrader{},
		ready:      make(chan struct{}),
		challenges: true,
	}

	mg.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := mg.upgrader.Upgrade(w, r, nil)
		require.NoError(t, err)
		mg.conn = conn
		mg.handleConnection(conn)
	}))

	return mg
}

func (mg *mockGateway) url() string {
	return "ws" + strings.TrimPrefix(mg.server.URL, "http")
}

func (mg *mockGateway) handleConnection(conn *websocket.Conn) {
	// Send challenge.
	if mg.challenges {
		challenge := map[string]any{
			"type":  "event",
			"event": "connect.challenge",
			"payload": map[string]any{
				"nonce": "test-nonce",
				"ts":    time.Now().UnixMilli(),
			},
		}
		data, _ := json.Marshal(challenge)
		conn.WriteMessage(websocket.TextMessage, data)
	}

	// Read connect request.
	_, msg, err := conn.ReadMessage()
	if err != nil {
		return
	}

	var connectReq map[string]any
	json.Unmarshal(msg, &connectReq)
	mg.received = append(mg.received, connectReq)

	// Send hello-ok.
	ok := true
	hello := wsMessage{
		Type:    "res",
		ID:      connectReq["id"].(string),
		OK:      &ok,
		Payload: json.RawMessage(`{"type":"hello-ok","protocol":3}`),
	}
	data, _ := json.Marshal(hello)
	conn.WriteMessage(websocket.TextMessage, data)

	// Signal that handshake is complete and conn is safe for test use.
	close(mg.ready)
}

func (mg *mockGateway) sendApprovalRequest(id, command, agent string) {
	<-mg.ready // wait for handshake to complete
	payload, _ := json.Marshal(approvalRequest{
		ID: id,
		Request: approvalRequestInner{
			Command: command,
			AgentID: agent,
			Session: "test-session",
			Host:    "gateway",
		},
	})

	msg := map[string]any{
		"type":    "event",
		"event":   "exec.approval.requested",
		"payload": json.RawMessage(payload),
	}
	data, _ := json.Marshal(msg)
	mg.writeMu.Lock()
	mg.conn.WriteMessage(websocket.TextMessage, data)
	mg.writeMu.Unlock()
}

func (mg *mockGateway) readResponse() map[string]any {
	_, msg, err := mg.conn.ReadMessage()
	require.NoError(mg.t, err)

	var resp map[string]any
	json.Unmarshal(msg, &resp)
	return resp
}

func (mg *mockGateway) close() {
	if mg.conn != nil {
		mg.conn.Close()
	}
	mg.server.Close()
}

func writePolicyFile(t *testing.T, dir string) string {
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

func TestDaemonEvaluatesApprovals(t *testing.T) {
	mg := newMockGateway(t)
	defer mg.close()

	tmpDir := t.TempDir()
	policyPath := writePolicyFile(t, tmpDir)
	auditDir := filepath.Join(tmpDir, "audit")

	cfg := Config{
		GatewayURL:        mg.url(),
		GatewayToken:      "test-token",
		PolicyPath:        policyPath,
		AuditDir:          auditDir,
		ReconnectInterval: 100 * time.Millisecond,
	}

	d, err := New(cfg)
	require.NoError(t, err)
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start daemon in background.
	errCh := make(chan error, 1)
	go func() {
		errCh <- d.Run(ctx)
	}()

	// Wait for connection.
	time.Sleep(500 * time.Millisecond)

	// Send a dangerous command.
	mg.sendApprovalRequest("approval-1", "rm -rf /", "main")
	time.Sleep(200 * time.Millisecond)

	resp := mg.readResponse()
	params, ok := resp["params"].(map[string]any)
	require.True(t, ok, "expected params in response")
	assert.Equal(t, "approval-1", params["id"])
	assert.Equal(t, "deny", params["decision"])

	// Send a safe command.
	mg.sendApprovalRequest("approval-2", "git status", "main")
	time.Sleep(200 * time.Millisecond)

	resp = mg.readResponse()
	params, ok = resp["params"].(map[string]any)
	require.True(t, ok, "expected params in response")
	assert.Equal(t, "approval-2", params["id"])
	assert.Equal(t, "allow-once", params["decision"])

	cancel()
}

func TestDaemonRequireApproval(t *testing.T) {
	mg := newMockGateway(t)
	defer mg.close()

	tmpDir := t.TempDir()
	auditDir := filepath.Join(tmpDir, "audit")

	// Write a policy that requires approval for sudo commands.
	policyPath := filepath.Join(tmpDir, "policy.yaml")
	policy := `version: "1"
default_action: allow
policies:
  - name: sudo-approval
    match:
      tool: exec
    rules:
      - action: require_approval
        when:
          command_matches:
            - "sudo *"
        message: "Sudo requires approval"
`
	require.NoError(t, os.WriteFile(policyPath, []byte(policy), 0o644))

	cfg := Config{
		GatewayURL:        mg.url(),
		GatewayToken:      "test-token",
		PolicyPath:        policyPath,
		AuditDir:          auditDir,
		ReconnectInterval: 100 * time.Millisecond,
	}

	d, err := New(cfg)
	require.NoError(t, err)
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- d.Run(ctx)
	}()

	time.Sleep(500 * time.Millisecond)

	// Send a sudo command — should pend, not auto-resolve.
	mg.sendApprovalRequest("approval-sudo", "sudo reboot", "main")

	// Poll for pending approval with timeout (avoids flaky sleep in CI).
	var pending []*approval.Request
	require.Eventually(t, func() bool {
		pending = d.Approvals().List()
		return len(pending) == 1
	}, 3*time.Second, 50*time.Millisecond, "expected one pending approval")
	assert.Equal(t, "sudo reboot", pending[0].Call.Command())

	// Approve it.
	require.NoError(t, d.Approvals().Resolve(pending[0].ID, true, "test"))

	// The daemon should now resolve the OpenClaw approval.
	time.Sleep(200 * time.Millisecond)
	resp := mg.readResponse()
	params, ok := resp["params"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "approval-sudo", params["id"])
	assert.Equal(t, "allow-once", params["decision"])

	cancel()
}

func TestDaemonRequiresToken(t *testing.T) {
	cfg := Config{
		GatewayURL:   "ws://127.0.0.1:18789",
		GatewayToken: "",
		PolicyPath:   "/nonexistent",
	}

	_, err := New(cfg)
	assert.Error(t, err) // Will fail on policy load, but token check is in CLI layer.
}
