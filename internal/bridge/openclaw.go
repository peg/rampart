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

// Package bridge connects Rampart to external approval systems.
//
// The OpenClaw bridge connects to the OpenClaw gateway WebSocket and routes
// exec approval requests through Rampart's policy engine. Approvals that
// the engine auto-resolves (allow/deny) are sent back immediately. Approvals
// that require human review are forwarded to a running Rampart serve instance
// via its HTTP API.
//
// Wire protocol: OpenClaw gateway uses a custom type-discriminated frame format,
// NOT JSON-RPC 2.0:
//
//	Request:  {"type":"req",   "id":"<uuid>", "method":"...", "params":{...}}
//	Response: {"type":"res",   "id":"<uuid>", "result":{...}} or {"type":"err",...}
//	Event:    {"type":"event", "event":"exec.approval.requested", "payload":{...}, "seq":N}
//
// Authentication is via a connect request (first frame after dial):
//
//	method="connect", params={"auth":{"token":"<gateway_token>"},"scopes":["operator.approvals"]}
package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/peg/rampart/internal/engine"
)

// OpenClawBridge connects to the OpenClaw gateway and handles exec approval
// routing through Rampart's policy engine.
type OpenClawBridge struct {
	engine     *engine.Engine
	gatewayURL string
	token      string
	serveURL   string
	logger     *slog.Logger

	reconnectInterval time.Duration

	mu      sync.Mutex   // guards conn
	writeMu sync.Mutex   // guards WebSocket writes
	conn    *websocket.Conn

	pendingMu       sync.Mutex
	pending         map[string]chan struct{} // approval ID → close to signal resolution
	pendingCommands map[string]string       // approval ID → command (for allow-always writeback)
}

// Config holds bridge configuration.
type Config struct {
	// GatewayURL is the OpenClaw Gateway WebSocket URL (e.g., ws://127.0.0.1:18789/ws).
	GatewayURL string

	// GatewayToken is the authentication token for the Gateway.
	GatewayToken string

	// ServeURL is the Rampart serve instance URL for human-review escalation.
	ServeURL string

	// ReconnectInterval is how long to wait before reconnecting after a disconnect.
	ReconnectInterval time.Duration

	// Logger is the structured logger.
	Logger *slog.Logger
}

// NewOpenClawBridge creates a new bridge.
func NewOpenClawBridge(eng *engine.Engine, cfg Config) *OpenClawBridge {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.ReconnectInterval == 0 {
		cfg.ReconnectInterval = 5 * time.Second
	}
	if cfg.ServeURL == "" {
		cfg.ServeURL = discoverServeURL()
	}

	return &OpenClawBridge{
		engine:            eng,
		gatewayURL:        cfg.GatewayURL,
		token:             cfg.GatewayToken,
		serveURL:          cfg.ServeURL,
		logger:            cfg.Logger,
		reconnectInterval: cfg.ReconnectInterval,
		pending:         make(map[string]chan struct{}),
		pendingCommands: make(map[string]string),
	}
}

// Close closes the bridge's active WebSocket connection, unblocking any pending
// reads and causing Start to return.
func (b *OpenClawBridge) Close() {
	b.mu.Lock()
	conn := b.conn
	b.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
}

// Start connects to the gateway and processes approval events until the context
// is cancelled. It automatically reconnects on disconnect with backoff.
func (b *OpenClawBridge) Start(ctx context.Context) error {
	backoff := b.reconnectInterval
	for {
		err := b.connectAndListen(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}

		b.logger.Warn("bridge: disconnected from gateway", "error", err)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
			// Double backoff up to 30s.
			if backoff < 30*time.Second {
				backoff *= 2
			}
		}
	}
}

func (b *OpenClawBridge) connectAndListen(ctx context.Context) error {
	b.logger.Info("bridge: connecting to gateway", "url", b.gatewayURL)

	dialer := websocket.DefaultDialer
	conn, _, err := dialer.DialContext(ctx, b.gatewayURL, nil)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	b.mu.Lock()
	b.conn = conn
	b.mu.Unlock()

	defer func() {
		b.mu.Lock()
		b.conn = nil
		b.mu.Unlock()
	}()

	// Ping/pong for dead connection detection.
	const pongWait = 90 * time.Second
	const pingInterval = 30 * time.Second
	conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	pingCtx, pingCancel := context.WithCancel(ctx)
	defer pingCancel()
	go func() {
		ticker := time.NewTicker(pingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-pingCtx.Done():
				return
			case <-ticker.C:
				b.writeMu.Lock()
				conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second))
				b.writeMu.Unlock()
			}
		}
	}()

	// Authenticate and subscribe via the connect request.
	if err := b.sendConnect(conn); err != nil {
		return fmt.Errorf("connect handshake: %w", err)
	}

	b.logger.Info("bridge: connected to OpenClaw gateway, listening for approval requests")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		_, message, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		conn.SetReadDeadline(time.Now().Add(pongWait))
		b.handleFrame(ctx, conn, message)
	}
}

// sendConnect performs the OpenClaw gateway connect handshake:
//
//  1. Wait for the server's connect.challenge event (contains a nonce).
//  2. Send a connect request with auth token, scopes, and protocol version.
//  3. Wait for the server's res frame confirming hello-ok.
func (b *OpenClawBridge) sendConnect(conn *websocket.Conn) error {
	// Step 1: wait for connect.challenge.
	_, challengeMsg, err := conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("read connect challenge: %w", err)
	}
	var challengeFrame gatewayFrame
	if err := json.Unmarshal(challengeMsg, &challengeFrame); err != nil {
		return fmt.Errorf("parse connect challenge: %w", err)
	}
	if challengeFrame.Type != "event" || challengeFrame.Event != "connect.challenge" {
		return fmt.Errorf("expected connect.challenge, got type=%s event=%s", challengeFrame.Type, challengeFrame.Event)
	}

	// Extract nonce from challenge payload.
	var challengePayload struct {
		Nonce string `json:"nonce"`
	}
	if len(challengeFrame.Payload) > 0 {
		_ = json.Unmarshal(challengeFrame.Payload, &challengePayload)
	}

	// Step 2: send connect request with device identity so the gateway preserves
	// our operator.approvals scope. Without device identity, the gateway silently
	// strips all scopes via clearUnboundScopes(), preventing exec.approval.* events.
	scopes := []string{"operator.approvals"}

	connectParams := map[string]any{
		"minProtocol": 3,
		"maxProtocol": 3,
		"client": map[string]any{
			"id":          "gateway-client",
			"displayName": "Rampart Bridge",
			"version":     "0.0.1",
			"platform":    runtime.GOOS,
			"mode":        "backend",
		},
		"auth": map[string]any{
			"token": b.token,
		},
		"scopes": scopes,
		"role":   "operator",
		"caps":   []string{},
	}

	// Include device identity if available — required to preserve scopes.
	if identity, err := loadOpenClawDeviceIdentity(); err != nil {
		b.logger.Warn("bridge: device identity unavailable — scopes may be stripped by gateway", "error", err)
	} else if devicePayload, err := identity.buildDeviceAuthPayload(challengePayload.Nonce, b.token, scopes); err != nil {
		b.logger.Warn("bridge: device auth payload failed — scopes may be stripped by gateway", "error", err)
	} else {
		connectParams["device"] = devicePayload
		b.logger.Debug("bridge: device identity loaded", "device_id", identity.DeviceID)
	}

	reqID := uuid.New().String()
	frame := gatewayRequest{
		Type:   "req",
		ID:     reqID,
		Method: "connect",
		Params: connectParams,
	}

	data, err := json.Marshal(frame)
	if err != nil {
		return fmt.Errorf("marshal connect: %w", err)
	}

	b.writeMu.Lock()
	err = conn.WriteMessage(websocket.TextMessage, data)
	b.writeMu.Unlock()
	if err != nil {
		return fmt.Errorf("send connect: %w", err)
	}

	// Step 3: read hello-ok response.
	_, resp, err := conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("read connect response: %w", err)
	}

	var resFrame gatewayFrame
	if err := json.Unmarshal(resp, &resFrame); err != nil {
		return fmt.Errorf("parse connect response: %w", err)
	}
	if resFrame.Type == "err" {
		return fmt.Errorf("connect rejected: %s", string(resFrame.Error))
	}
	if resFrame.Type != "res" {
		return fmt.Errorf("unexpected connect response type: %s", resFrame.Type)
	}

	b.logger.Info("bridge: handshake complete", "client_id", "rampart-bridge", "scopes", []string{"operator.approvals"})
	return nil
}

// handleFrame dispatches an incoming gateway frame.
func (b *OpenClawBridge) handleFrame(ctx context.Context, conn *websocket.Conn, data []byte) {
	var frame gatewayFrame
	if err := json.Unmarshal(data, &frame); err != nil {
		b.logger.Debug("bridge: failed to parse frame", "error", err)
		return
	}

	switch frame.Type {
	case "event":
		b.handleEvent(ctx, conn, frame)
	case "res", "err":
		// Responses to our requests — currently fire-and-forget for resolveApproval.
	default:
		b.logger.Debug("bridge: unknown frame type", "type", frame.Type)
	}
}

// handleEvent handles an incoming event frame.
func (b *OpenClawBridge) handleEvent(ctx context.Context, conn *websocket.Conn, frame gatewayFrame) {
	switch frame.Event {
	case "exec.approval.requested":
		var req approvalRequestParams
		if err := json.Unmarshal(frame.Payload, &req); err != nil {
			b.logger.Error("bridge: failed to parse approval request", "error", err)
			return
		}
		go b.handleApprovalRequested(ctx, conn, req)

	case "exec.approval.resolved":
		// Another client resolved this approval — cancel any pending escalation.
		// If decision is "allow-always", write a user override rule.
		var resolved struct {
			ID       string `json:"id"`
			Decision string `json:"decision"`
		}
		if err := json.Unmarshal(frame.Payload, &resolved); err == nil {
			b.pendingMu.Lock()
			if ch, ok := b.pending[resolved.ID]; ok {
				close(ch)
				delete(b.pending, resolved.ID)
			}
			cmd := b.pendingCommands[resolved.ID]
			delete(b.pendingCommands, resolved.ID)
			b.pendingMu.Unlock()

			if resolved.Decision == "allow-always" && cmd != "" {
				go b.writeAllowAlwaysRule(cmd)
			}
		}
	}
}

// handleApprovalRequested evaluates a command against the policy engine and
// resolves the approval accordingly.
func (b *OpenClawBridge) handleApprovalRequested(ctx context.Context, conn *websocket.Conn, req approvalRequestParams) {
	call := engine.ToolCall{
		Tool:    "exec",
		Agent:   req.agentID(),
		Session: req.Request.SessionKey,
		Params: map[string]any{
			"command": req.command(),
		},
		Timestamp: time.Now(),
	}

	start := time.Now()
	decision := b.engine.Evaluate(call)
	evalDuration := time.Since(start)

	b.logger.Info("bridge: evaluated approval request",
		"id", req.ID,
		"command", req.command(),
		"agent", req.agentID(),
		"action", decision.Action.String(),
		"duration", evalDuration,
	)

	switch decision.Action {
	case engine.ActionAllow, engine.ActionWatch:
		b.resolveApproval(conn, req.ID, "allow-once")

	case engine.ActionDeny:
		b.resolveApproval(conn, req.ID, "deny")

	case engine.ActionRequireApproval, engine.ActionAsk:
		// Escalate to Rampart serve for human review.
		b.escalateToServe(ctx, conn, req, decision)

	case engine.ActionWebhook:
		// Webhook actions delegate to an external system.
		// Don't resolve — let OpenClaw's approval flow handle it or time out.
		b.logger.Info("bridge: webhook action — deferring to OpenClaw approval flow",
			"id", req.ID, "command", req.command())

	default:
		// Unknown action — fail open so we don't silently block commands.
		b.logger.Warn("bridge: unknown action, allowing (fail-open)",
			"id", req.ID, "action", decision.Action.String())
		b.resolveApproval(conn, req.ID, "allow-once")
	}
}

// resolveApproval sends exec.approval.resolve to the gateway on the given conn.
// If the write fails (e.g. conn was replaced by a reconnect), it retries on
// the current active connection so in-flight escalations aren't silently lost.
// decision is "allow-once", "allow-always", or "deny".
func (b *OpenClawBridge) resolveApproval(conn *websocket.Conn, approvalID, decision string) {
	if err := b.sendResolve(conn, approvalID, decision); err != nil {
		b.logger.Warn("bridge: resolve on original conn failed, retrying on current conn",
			"id", approvalID, "error", err)
		b.mu.Lock()
		current := b.conn
		b.mu.Unlock()
		if current != nil && current != conn {
			if err2 := b.sendResolve(current, approvalID, decision); err2 != nil {
				b.logger.Error("bridge: resolve failed on both conns, approval lost",
					"id", approvalID, "error", err2)
			}
		}
		return
	}
	b.logger.Info("bridge: resolved approval", "id", approvalID, "decision", decision)
}

// sendResolve writes an exec.approval.resolve frame to a specific connection.
func (b *OpenClawBridge) sendResolve(conn *websocket.Conn, approvalID, decision string) error {
	frame := gatewayRequest{
		Type:   "req",
		ID:     uuid.New().String(),
		Method: "exec.approval.resolve",
		Params: map[string]any{
			"id":       approvalID,
			"decision": decision,
		},
	}

	data, err := json.Marshal(frame)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	b.writeMu.Lock()
	err = conn.WriteMessage(websocket.TextMessage, data)
	b.writeMu.Unlock()
	return err
}

// escalateToServe forwards the approval to Rampart serve for human review.
func (b *OpenClawBridge) escalateToServe(ctx context.Context, conn *websocket.Conn, req approvalRequestParams, decision engine.Decision) {
	b.logger.Warn("bridge: approval requires human review — escalating to serve",
		"id", req.ID, "command", req.command(), "serve_url", b.serveURL)

	// Register cancellation channel and store command for allow-always writeback.
	cancelCh := make(chan struct{})
	b.pendingMu.Lock()
	b.pending[req.ID] = cancelCh
	b.pendingCommands[req.ID] = req.command()
	b.pendingMu.Unlock()

	defer func() {
		b.pendingMu.Lock()
		delete(b.pending, req.ID)
		delete(b.pendingCommands, req.ID)
		b.pendingMu.Unlock()
	}()

	body, _ := json.Marshal(map[string]any{
		"tool":    "exec",
		"command": req.command(),
		"agent":   req.agentID(),
		"session": req.Request.SessionKey,
		"message": decision.Message,
	})

	httpReq, err := http.NewRequestWithContext(ctx, "POST", b.serveURL+"/v1/approvals", bytes.NewReader(body))
	if err != nil {
		b.logger.Error("bridge: failed to create escalation request", "error", err)
		b.resolveApproval(conn, req.ID, "allow-once") // fail-open
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if token := os.Getenv("RAMPART_TOKEN"); token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		b.logger.Warn("bridge: serve escalation failed, failing open", "error", err)
		b.resolveApproval(conn, req.ID, "allow-once")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b.logger.Warn("bridge: serve escalation returned non-2xx, failing open", "status", resp.StatusCode)
		b.resolveApproval(conn, req.ID, "allow-once")
		return
	}

	var result struct {
		ID string `json:"id"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if result.ID == "" {
		b.resolveApproval(conn, req.ID, "allow-once")
		return
	}

	// Poll for the Rampart approval decision.
	const pollInterval = 2 * time.Second
	const pollTimeout = 5 * time.Minute
	deadline := time.Now().Add(pollTimeout)

	for {
		select {
		case <-ctx.Done():
			b.resolveApproval(conn, req.ID, "deny")
			return
		case <-cancelCh:
			// Resolved by another client.
			return
		case <-time.After(pollInterval):
		}

		if time.Now().After(deadline) {
			b.logger.Warn("bridge: escalation timed out", "id", req.ID)
			b.resolveApproval(conn, req.ID, "deny")
			return
		}

		pollReq, _ := http.NewRequestWithContext(ctx, "GET", b.serveURL+"/v1/approvals/"+result.ID, nil)
		if token := os.Getenv("RAMPART_TOKEN"); token != "" {
			pollReq.Header.Set("Authorization", "Bearer "+token)
		}
		pollResp, err := http.DefaultClient.Do(pollReq)
		if err != nil {
			continue
		}

		var status struct {
			Status string `json:"status"`
		}
		json.NewDecoder(pollResp.Body).Decode(&status)
		pollResp.Body.Close()

		switch status.Status {
		case "approved":
			b.resolveApproval(conn, req.ID, "allow-once")
			return
		case "denied", "expired":
			b.resolveApproval(conn, req.ID, "deny")
			return
		}
	}
}

// writeAllowAlwaysRule appends an allow rule for the given command to
// ~/.rampart/policies/user-overrides.yaml and hot-reloads the engine.
// This is called when a human clicks "Always Allow" in the OpenClaw approval UI.
func (b *OpenClawBridge) writeAllowAlwaysRule(command string) {
	home, err := os.UserHomeDir()
	if err != nil {
		b.logger.Error("bridge: allow-always: resolve home dir", "error", err)
		return
	}

	overridesPath := filepath.Join(home, ".rampart", "policies", "user-overrides.yaml")

	// Hash the command for a stable rule name.
	hb := sha256Command(command)
	ruleName := fmt.Sprintf("user-allow-%x", hb)

	// Build the rule block to append.
	rule := fmt.Sprintf("\n- name: %s\n  match:\n    tool: exec\n  rules:\n    - when:\n        command_matches:\n          - %q\n      action: allow\n      message: \"User allowed (always)\"\n",
		ruleName, command)

	// Read existing file or create with header.
	var existing string
	data, err := os.ReadFile(overridesPath)
	if err != nil {
		existing = "# Rampart user override policies\n# Auto-generated entries are added here when you click \"Always Allow\"\n# This file is never overwritten by upgrades or rampart setup\npolicies:\n"
	} else {
		existing = string(data)
		// Don't add a duplicate rule.
		if strings.Contains(existing, ruleName) {
			b.logger.Info("bridge: allow-always rule already exists", "rule", ruleName, "command", command)
			return
		}
	}

	if err := os.WriteFile(overridesPath, []byte(existing+rule), 0o600); err != nil {
		b.logger.Error("bridge: allow-always: write user-overrides.yaml", "error", err)
		return
	}

	b.logger.Info("bridge: allow-always rule written", "rule", ruleName, "command", command, "path", overridesPath)

	// Hot-reload the engine so the new rule takes effect immediately.
	if err := b.engine.Reload(); err != nil {
		b.logger.Warn("bridge: allow-always: engine reload failed", "error", err)
	}
}

// sha256Command returns 4 bytes derived from a djb2 hash of the command string.
func sha256Command(s string) [4]byte {
	var hash uint32 = 5381
	for _, b := range []byte(s) {
		hash = hash*33 + uint32(b)
	}
	return [4]byte{byte(hash >> 24), byte(hash >> 16), byte(hash >> 8), byte(hash)}
}

// --- Wire protocol types ---

// gatewayRequest is an outgoing request frame.
type gatewayRequest struct {
	Type   string `json:"type"`
	ID     string `json:"id"`
	Method string `json:"method"`
	Params any    `json:"params,omitempty"`
}

// gatewayFrame is a generic incoming frame (response or event).
type gatewayFrame struct {
	Type    string          `json:"type"`
	ID      string          `json:"id,omitempty"`
	Event   string          `json:"event,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
	Seq     int             `json:"seq,omitempty"`
}

// approvalRequestParams is the payload of an exec.approval.requested event.
// The gateway broadcasts: {id, request: {command, agentId, sessionKey, cwd, ...}, createdAtMs, expiresAtMs}
type approvalRequestParams struct {
	ID      string `json:"id"`
	Request struct {
		Command    string `json:"command"`
		AgentID    string `json:"agentId"`
		SessionKey string `json:"sessionKey"`
		CWD        string `json:"cwd,omitempty"`
	} `json:"request"`
}

// command returns the command string from the nested request object.
func (p approvalRequestParams) command() string { return p.Request.Command }

// agentID returns the agent ID from the nested request object.
func (p approvalRequestParams) agentID() string { return p.Request.AgentID }

// --- Discovery helpers ---

// DiscoverGatewayConfig reads the OpenClaw gateway URL and token from
// ~/.openclaw/openclaw.json. Returns url, token, error.
func DiscoverGatewayConfig() (string, string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", fmt.Errorf("resolve home directory: %w", err)
	}

	configPath := filepath.Join(home, ".openclaw", "openclaw.json")
	return ReadGatewayConfig(configPath)
}

// ReadGatewayConfig reads gateway URL and token from the specified openclaw.json path.
func ReadGatewayConfig(path string) (string, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", fmt.Errorf("read openclaw config: %w", err)
	}

	var cfg openclawConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return "", "", fmt.Errorf("parse openclaw config: %w", err)
	}

	token := cfg.Gateway.Auth.Token
	if token == "" {
		return "", "", fmt.Errorf("no gateway.auth.token in %s", path)
	}

	url := cfg.Gateway.URL
	if url == "" {
		url = "ws://127.0.0.1:18789/ws"
	}

	return url, token, nil
}

// discoverServeURL finds the Rampart serve URL from serve.state or environment.
func discoverServeURL() string {
	if v := os.Getenv("RAMPART_URL"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "http://127.0.0.1:9090"
	}
	data, err := os.ReadFile(filepath.Join(home, ".rampart", "serve.state"))
	if err != nil {
		return "http://127.0.0.1:9090"
	}
	var state struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(data, &state); err != nil || state.URL == "" {
		return "http://127.0.0.1:9090"
	}
	return state.URL
}

// openclawConfig represents the relevant subset of ~/.openclaw/openclaw.json.
type openclawConfig struct {
	Gateway struct {
		URL  string `json:"url"`
		Auth struct {
			Token string `json:"token"`
		} `json:"auth"`
	} `json:"gateway"`
}
