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
// that require human review remain pending in OpenClaw's native approval
// system so the operator sees exactly one approval object.
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
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/engine"
)

// OpenClawBridge connects to the OpenClaw gateway and handles exec approval
// routing through Rampart's policy engine.
type OpenClawBridge struct {
	engine     *engine.Engine
	gatewayURL string
	token      string
	serveURL   string
	sink       audit.AuditSink
	logger     *slog.Logger

	reconnectInterval time.Duration

	mu      sync.Mutex // guards conn
	writeMu sync.Mutex // guards WebSocket writes
	conn    *websocket.Conn

	pendingMu       sync.Mutex
	pending         map[string]chan struct{} // approval ID → close to signal resolution
	pendingCommands map[string]string        // approval ID → command (for allow-always writeback)
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

	// AuditSink is the audit sink for logging bridge-evaluated tool calls.
	AuditSink audit.AuditSink

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
		sink:              cfg.AuditSink,
		logger:            cfg.Logger,
		reconnectInterval: cfg.ReconnectInterval,
		pending:           make(map[string]chan struct{}),
		pendingCommands:   make(map[string]string),
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

	// Step 2: send connect request.
	reqID := uuid.New().String()
	frame := gatewayRequest{
		Type:   "req",
		ID:     reqID,
		Method: "connect",
		Params: map[string]any{
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
			"scopes": []string{"operator.approvals"},
			"role":   "operator",
			"caps":   []string{},
		},
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
		b.logger.Debug("bridge: received event", "event", frame.Event)
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
		// Store the command immediately so allow-always writeback works
		// regardless of who ultimately resolves the approval (Rampart or OpenClaw native flow).
		if req.ID != "" && req.command() != "" {
			b.pendingMu.Lock()
			b.pendingCommands[req.ID] = req.command()
			b.pendingMu.Unlock()
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
		Session: req.sessionKey(),
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

	// Write audit event so bridge-evaluated commands appear in the JSONL trail.
	if b.sink != nil {
		ev := audit.Event{
			ID:        audit.NewEventID(),
			Timestamp: time.Now().UTC(),
			Agent:     call.Agent,
			Session:   call.Session,
			Tool:      call.Tool,
			Request:   call.Params,
			Decision: audit.EventDecision{
				Action:          decision.Action.String(),
				MatchedPolicies: decision.MatchedPolicies,
				EvalTimeUS:      decision.EvalDuration.Microseconds(),
				Message:         decision.Message,
			},
		}
		if err := b.sink.Write(ev); err != nil {
			b.logger.Warn("bridge: failed to write audit event", "error", err)
		}
	}

	switch decision.Action {
	case engine.ActionAllow, engine.ActionWatch:
		b.resolveApproval(conn, req.ID, "allow-once")
		b.cleanPendingCommand(req.ID)

	case engine.ActionDeny:
		b.resolveApproval(conn, req.ID, "deny")
		b.cleanPendingCommand(req.ID)

	case engine.ActionRequireApproval, engine.ActionAsk:
		b.leavePendingForHumanReview(req, decision)

	case engine.ActionWebhook:
		// Webhook actions delegate to an external system.
		// Don't resolve — let OpenClaw's approval flow handle it or time out.
		b.logger.Info("bridge: webhook action — deferring to OpenClaw approval flow",
			"id", req.ID, "command", req.command())

	default:
		// Unknown action — fail closed. An unrecognized action should never
		// silently allow a command that may require human review.
		b.logger.Warn("bridge: unknown action, denying (fail-closed)",
			"id", req.ID, "action", decision.Action.String())
		b.resolveApproval(conn, req.ID, "deny")
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

// leavePendingForHumanReview keeps the native OpenClaw approval pending so the
// operator sees exactly one approval object for the command.
func (b *OpenClawBridge) leavePendingForHumanReview(req approvalRequestParams, decision engine.Decision) {
	b.logger.Info("bridge: approval requires human review, leaving native OpenClaw approval pending",
		"id", req.ID,
		"command", req.command(),
		"agent", req.agentID(),
		"message", decision.Message,
	)
}

// cleanPendingCommand removes a command from pendingCommands after auto-resolution.
// For escalated commands, cleanup happens in the resolved event handler instead.
func (b *OpenClawBridge) cleanPendingCommand(id string) {
	b.pendingMu.Lock()
	delete(b.pendingCommands, id)
	b.pendingMu.Unlock()
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

	// Hash the command for a stable rule name using SHA-256 (first 8 hex chars).
	hb := commandHash(command)
	ruleName := fmt.Sprintf("user-allow-%s", hb)

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

	if err := os.MkdirAll(filepath.Dir(overridesPath), 0o700); err != nil {
		b.logger.Error("bridge: allow-always: create policies dir", "error", err)
		return
	}
	// Atomic write: write to temp file then rename to avoid partial reads.
	dir := filepath.Dir(overridesPath)
	tmp, err := os.CreateTemp(dir, ".rampart-user-overrides-*.yaml.tmp")
	if err != nil {
		b.logger.Error("bridge: allow-always: create temp file", "error", err)
		return
	}
	tmpPath := tmp.Name()
	if _, werr := tmp.WriteString(existing + rule); werr != nil {
		tmp.Close()
		os.Remove(tmpPath)
		b.logger.Error("bridge: allow-always: write temp file", "error", werr)
		return
	}
	if cerr := tmp.Close(); cerr != nil {
		os.Remove(tmpPath)
		b.logger.Error("bridge: allow-always: close temp file", "error", cerr)
		return
	}
	if rerr := os.Rename(tmpPath, overridesPath); rerr != nil {
		os.Remove(tmpPath)
		b.logger.Error("bridge: allow-always: rename to final path", "error", rerr)
		return
	}

	b.logger.Info("bridge: allow-always rule written", "rule", ruleName, "command", command, "path", overridesPath)

	// Hot-reload the engine so the new rule takes effect immediately.
	if err := b.engine.Reload(); err != nil {
		b.logger.Warn("bridge: allow-always: engine reload failed", "error", err)
	}
}

// commandHash returns the first 8 hex characters of the SHA-256 hash of s.
// Used to generate stable, collision-resistant rule names for allow-always entries.
func commandHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum[:4])
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
type approvalRequestParams struct {
	ID      string `json:"id"`
	Request struct {
		Command    string `json:"command"`
		AgentID    string `json:"agentId"`
		SessionKey string `json:"sessionKey"`
		CWD        string `json:"cwd,omitempty"`
	} `json:"request"`
}

func (r approvalRequestParams) command() string    { return r.Request.Command }
func (r approvalRequestParams) agentID() string    { return r.Request.AgentID }
func (r approvalRequestParams) sessionKey() string { return r.Request.SessionKey }

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
