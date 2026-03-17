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
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/peg/rampart/internal/engine"
)

// OpenClawBridge connects to the OpenClaw gateway and handles exec approval
// routing through Rampart's policy engine.
type OpenClawBridge struct {
	engine     *engine.Engine
	gatewayURL string
	token      string
	serveURL   string // Rampart serve URL for human-review escalation
	logger     *slog.Logger

	reconnectInterval time.Duration

	mu      sync.Mutex
	writeMu sync.Mutex // guards WebSocket writes
	conn    *websocket.Conn
	seq     atomic.Int64
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
		cfg.ServeURL = "http://127.0.0.1:19090"
	}

	return &OpenClawBridge{
		engine:            eng,
		gatewayURL:        cfg.GatewayURL,
		token:             cfg.GatewayToken,
		serveURL:          cfg.ServeURL,
		logger:            cfg.Logger,
		reconnectInterval: cfg.ReconnectInterval,
	}
}

// Start connects to the gateway, subscribes to approval events, and processes
// them until the context is cancelled. It automatically reconnects on disconnect.
func (b *OpenClawBridge) Start(ctx context.Context) error {
	for {
		err := b.connectAndListen(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}

		b.logger.Warn("bridge: disconnected from gateway", "error", err)
		b.logger.Info("bridge: reconnecting", "interval", b.reconnectInterval)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(b.reconnectInterval):
		}
	}
}

func (b *OpenClawBridge) connectAndListen(ctx context.Context) error {
	b.logger.Info("bridge: connecting to gateway", "url", b.gatewayURL)

	header := http.Header{}
	header.Set("Authorization", "Bearer "+b.token)

	conn, _, err := websocket.DefaultDialer.DialContext(ctx, b.gatewayURL, header)
	if err != nil {
		return fmt.Errorf("bridge: connect: %w", err)
	}
	defer conn.Close()

	b.mu.Lock()
	b.conn = conn
	b.seq.Store(0)
	b.mu.Unlock()

	// Set up ping/pong to detect dead connections.
	const pongWait = 90 * time.Second
	const pingInterval = 30 * time.Second
	conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	// Start ping ticker in background.
	pingDone := make(chan struct{})
	go func() {
		defer close(pingDone)
		ticker := time.NewTicker(pingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				b.writeMu.Lock()
				err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second))
				b.writeMu.Unlock()
				if err != nil {
					return
				}
			}
		}
	}()
	defer func() { <-pingDone }()

	// Subscribe to approval events via JSON-RPC.
	if err := b.subscribe(); err != nil {
		return fmt.Errorf("bridge: subscribe: %w", err)
	}

	b.logger.Info("bridge: connected to OpenClaw gateway, listening for approval requests")

	// Listen for messages.
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		_, message, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("bridge: read: %w", err)
		}

		conn.SetReadDeadline(time.Now().Add(pongWait))
		b.handleMessage(ctx, message)
	}
}

// subscribe sends the scope.subscribe JSON-RPC request.
func (b *OpenClawBridge) subscribe() error {
	msg := map[string]any{
		"jsonrpc": "2.0",
		"method":  "scope.subscribe",
		"params": map[string]any{
			"scope": "operator.approvals",
		},
		"id": b.nextID(),
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal subscribe: %w", err)
	}

	b.writeMu.Lock()
	err = b.conn.WriteMessage(websocket.TextMessage, data)
	b.writeMu.Unlock()

	if err != nil {
		return fmt.Errorf("send subscribe: %w", err)
	}

	// Read subscribe response.
	_, respMsg, err := b.conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("read subscribe response: %w", err)
	}

	var resp jsonRPCResponse
	if err := json.Unmarshal(respMsg, &resp); err != nil {
		return fmt.Errorf("parse subscribe response: %w", err)
	}

	if resp.Error != nil {
		return fmt.Errorf("subscribe rejected: %s", string(resp.Error.Message))
	}

	return nil
}

// jsonRPCMessage is a generic JSON-RPC 2.0 message (notification or request).
type jsonRPCMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      any             `json:"id,omitempty"`
}

// jsonRPCResponse is a JSON-RPC 2.0 response.
type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
	ID      any             `json:"id,omitempty"`
}

// jsonRPCError is a JSON-RPC error object.
type jsonRPCError struct {
	Code    int             `json:"code"`
	Message json.RawMessage `json:"message"`
}

// approvalRequestParams is the params of an exec.approval.requested notification.
type approvalRequestParams struct {
	ID         string `json:"id"`
	Command    string `json:"command"`
	CWD        string `json:"cwd"`
	AgentID    string `json:"agentId"`
	SessionKey string `json:"sessionKey"`
}

func (b *OpenClawBridge) handleMessage(ctx context.Context, raw []byte) {
	var msg jsonRPCMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		b.logger.Warn("bridge: unparseable message", "error", err)
		return
	}

	// Skip responses to our own requests.
	if msg.Method == "" {
		// This is likely a response — check for errors.
		var resp jsonRPCResponse
		if err := json.Unmarshal(raw, &resp); err == nil && resp.Error != nil {
			b.logger.Error("bridge: gateway rejected request",
				"id", resp.ID,
				"error", string(resp.Error.Message),
			)
		}
		return
	}

	if msg.Method != "exec.approval.requested" {
		return
	}

	var req approvalRequestParams
	if err := json.Unmarshal(msg.Params, &req); err != nil {
		b.logger.Warn("bridge: unparseable approval request", "error", err)
		return
	}

	go b.handleApprovalRequested(ctx, req)
}

func (b *OpenClawBridge) handleApprovalRequested(ctx context.Context, req approvalRequestParams) {
	start := time.Now()

	call := engine.ToolCall{
		ID:        req.ID,
		Agent:     req.AgentID,
		Session:   req.SessionKey,
		Tool:      "exec",
		Params:    map[string]any{"command": req.Command, "cwd": req.CWD},
		Timestamp: time.Now(),
	}

	decision := b.engine.Evaluate(call)
	evalDuration := time.Since(start)

	b.logger.Info("bridge: evaluated approval request",
		"id", req.ID,
		"command", req.Command,
		"agent", req.AgentID,
		"action", decision.Action.String(),
		"duration", evalDuration,
	)

	switch decision.Action {
	case engine.ActionAllow, engine.ActionWatch:
		b.resolveApproval(req.ID, "allow-once")
	case engine.ActionDeny:
		b.resolveApproval(req.ID, "deny")
	case engine.ActionRequireApproval:
		b.escalateToServe(ctx, req, decision)
	default:
		// Fail closed for unknown actions.
		b.resolveApproval(req.ID, "deny")
	}
}

// escalateToServe forwards the approval to a running Rampart serve instance
// and polls for resolution.
func (b *OpenClawBridge) escalateToServe(ctx context.Context, req approvalRequestParams, decision engine.Decision) {
	b.logger.Warn("bridge: approval requires human review — escalating to serve",
		"id", req.ID,
		"command", req.Command,
		"serve_url", b.serveURL,
	)

	// POST to Rampart serve's eval endpoint to create a pending approval.
	evalReq := map[string]any{
		"tool":    "exec",
		"command": req.Command,
		"cwd":     req.CWD,
		"agent":   req.AgentID,
		"session": req.SessionKey,
	}
	body, _ := json.Marshal(evalReq)

	httpReq, err := http.NewRequestWithContext(ctx, "POST", b.serveURL+"/v1/eval", bytes.NewReader(body))
	if err != nil {
		b.logger.Error("bridge: failed to create escalation request", "error", err)
		b.resolveApproval(req.ID, "deny")
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		b.logger.Error("bridge: failed to escalate to serve", "error", err)
		b.resolveApproval(req.ID, "deny")
		return
	}
	resp.Body.Close()

	// For now, if the serve endpoint requires approval, deny the OpenClaw request.
	// The human will see the pending approval in the Rampart dashboard.
	// Future: poll the approval status and relay resolution back.
	b.logger.Warn("bridge: escalated to serve — denying until human resolves via dashboard",
		"id", req.ID,
	)
	b.resolveApproval(req.ID, "deny")
}

func (b *OpenClawBridge) resolveApproval(approvalID, decision string) {
	b.mu.Lock()
	conn := b.conn
	b.mu.Unlock()

	if conn == nil {
		b.logger.Error("bridge: cannot resolve approval, not connected")
		return
	}

	msg := map[string]any{
		"jsonrpc": "2.0",
		"method":  "exec.approval.resolve",
		"params": map[string]any{
			"id":       approvalID,
			"decision": decision,
		},
		"id": b.nextID(),
	}

	data, err := json.Marshal(msg)
	if err != nil {
		b.logger.Error("bridge: failed to marshal resolve message", "error", err, "approvalId", approvalID)
		return
	}

	b.writeMu.Lock()
	err = conn.WriteMessage(websocket.TextMessage, data)
	b.writeMu.Unlock()

	if err != nil {
		b.logger.Error("bridge: failed to resolve approval", "error", err, "approvalId", approvalID)
	} else {
		b.logger.Info("bridge: resolved approval", "id", approvalID, "decision", decision)
	}
}

func (b *OpenClawBridge) nextID() int64 {
	return b.seq.Add(1)
}

// Close gracefully shuts down the bridge.
func (b *OpenClawBridge) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.conn != nil {
		return b.conn.Close()
	}
	return nil
}

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

// openclawConfig represents the relevant subset of ~/.openclaw/openclaw.json.
type openclawConfig struct {
	Gateway struct {
		URL  string `json:"url"`
		Auth struct {
			Token string `json:"token"`
		} `json:"auth"`
	} `json:"gateway"`
}
