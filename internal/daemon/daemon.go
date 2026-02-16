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

// Package daemon implements the Rampart daemon that connects to an OpenClaw
// Gateway WebSocket and auto-resolves exec approval requests based on policies.
//
// The daemon acts as an operator client with `operator.approvals` scope.
// When an exec approval request arrives, it evaluates the command against
// loaded policies and responds with allow/deny. Every decision is recorded
// in the audit trail.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/peg/rampart/internal/approval"
	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/engine"
)

// Config holds the daemon configuration.
type Config struct {
	// GatewayURL is the OpenClaw Gateway WebSocket URL (e.g., ws://127.0.0.1:18789).
	GatewayURL string

	// GatewayToken is the authentication token for the Gateway.
	GatewayToken string

	// PolicyPath is the path to the Rampart policy YAML file.
	PolicyPath string

	// AuditDir is the directory for audit log files.
	AuditDir string

	// Logger is the structured logger.
	Logger *slog.Logger

	// ReconnectInterval is how long to wait before reconnecting after a disconnect.
	ReconnectInterval time.Duration
}

// Daemon connects to an OpenClaw Gateway and auto-resolves exec approvals.
type Daemon struct {
	cfg       Config
	engine    *engine.Engine
	sink      *audit.JSONLSink
	approvals *approval.Store
	logger    *slog.Logger

	mu      sync.Mutex
	writeMu sync.Mutex // guards WebSocket writes (not goroutine-safe)
	conn    *websocket.Conn
	seq     atomic.Int64
}

// New creates a new daemon with the given configuration.
func New(cfg Config) (*Daemon, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.ReconnectInterval == 0 {
		cfg.ReconnectInterval = 5 * time.Second
	}

	store := engine.NewFileStore(cfg.PolicyPath)
	eng, err := engine.New(store, cfg.Logger)
	if err != nil {
		return nil, fmt.Errorf("daemon: load policies: %w", err)
	}

	sink, err := audit.NewJSONLSink(cfg.AuditDir)
	if err != nil {
		return nil, fmt.Errorf("daemon: create audit sink: %w", err)
	}

	approvalStore := approval.NewStore(
		approval.WithExpireCallback(func(r *approval.Request) {
			cfg.Logger.Warn("approval expired, denying",
				"id", r.ID,
				"command", r.Call.Command(),
			)
		}),
	)

	return &Daemon{
		cfg:       cfg,
		engine:    eng,
		sink:      sink,
		approvals: approvalStore,
		logger:    cfg.Logger,
	}, nil
}

// Run starts the daemon and blocks until the context is cancelled.
// It automatically reconnects on disconnect.
func (d *Daemon) Run(ctx context.Context) error {
	for {
		err := d.connectAndListen(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}

		d.logger.Warn("disconnected from gateway", "error", err)
		d.logger.Info("reconnecting", "interval", d.cfg.ReconnectInterval)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d.cfg.ReconnectInterval):
		}
	}
}

func (d *Daemon) connectAndListen(ctx context.Context) error {
	d.logger.Info("connecting to gateway", "url", d.cfg.GatewayURL)

	conn, _, err := websocket.DefaultDialer.DialContext(ctx, d.cfg.GatewayURL, nil)
	if err != nil {
		return fmt.Errorf("daemon: connect: %w", err)
	}
	defer conn.Close()

	d.mu.Lock()
	d.conn = conn
	d.seq.Store(0)
	d.mu.Unlock()

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
				d.writeMu.Lock()
				err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second))
				d.writeMu.Unlock()
				if err != nil {
					return
				}
			}
		}
	}()
	defer func() { <-pingDone }()

	// Perform handshake.
	if err := d.handshake(ctx); err != nil {
		return fmt.Errorf("daemon: handshake: %w", err)
	}

	d.logger.Info("connected to gateway, listening for approval requests")

	// Listen for messages.
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		_, message, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("daemon: read: %w", err)
		}

		// Reset deadline on every successful read.
		conn.SetReadDeadline(time.Now().Add(pongWait))
		d.handleMessage(ctx, message)
	}
}

// wsMessage is the generic Gateway WebSocket frame.
type wsMessage struct {
	Type    string          `json:"type"`
	ID      string          `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Event   string          `json:"event,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
	OK      *bool           `json:"ok,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// approvalRequest is the payload of an exec.approval.requested event.
type approvalRequest struct {
	ID      string                `json:"id"`
	Request approvalRequestInner  `json:"request"`
}

// approvalRequestInner contains the nested request fields from OpenClaw.
type approvalRequestInner struct {
	Command string `json:"command"`
	CWD     string `json:"cwd"`
	Host    string `json:"host"`
	AgentID string `json:"agentId"`
	Session string `json:"sessionKey"`
}

func (d *Daemon) handshake(ctx context.Context) error {
	// Wait for challenge.
	_, challengeMsg, err := d.conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("read challenge: %w", err)
	}

	var challenge wsMessage
	if err := json.Unmarshal(challengeMsg, &challenge); err != nil {
		return fmt.Errorf("parse challenge: %w", err)
	}

	if challenge.Event != "connect.challenge" {
		return fmt.Errorf("expected connect.challenge, got %s", challenge.Event)
	}

	// Send connect request.
	connectReq := map[string]any{
		"type":   "req",
		"id":     d.nextID(),
		"method": "connect",
		"params": map[string]any{
			"minProtocol": 3,
			"maxProtocol": 3,
			"client": map[string]any{
				"id":       "gateway-client",
				"version":  "0.1.0",
				"platform": "linux",
				"mode":     "backend",
			},
			"role":   "operator",
			"scopes": []string{"operator.read", "operator.approvals"},
			"caps":   []string{},
			"auth": map[string]any{
				"token": d.cfg.GatewayToken,
			},
		},
	}

	data, _ := json.Marshal(connectReq)

	d.writeMu.Lock()
	err = d.conn.WriteMessage(websocket.TextMessage, data)
	d.writeMu.Unlock()

	if err != nil {
		return fmt.Errorf("send connect: %w", err)
	}

	// Wait for hello-ok.
	_, helloMsg, err := d.conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("read hello: %w", err)
	}

	var hello wsMessage
	if err := json.Unmarshal(helloMsg, &hello); err != nil {
		return fmt.Errorf("parse hello: %w", err)
	}

	if hello.OK == nil || !*hello.OK {
		return fmt.Errorf("handshake rejected: %s", string(hello.Error))
	}

	return nil
}

func (d *Daemon) handleMessage(ctx context.Context, raw []byte) {
	var msg wsMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		d.logger.Warn("unparseable message", "error", err)
		return
	}

	// Log non-event messages for debugging (e.g., responses to our resolve requests).
	if msg.Type == "res" {
		if msg.OK != nil && !*msg.OK {
			d.logger.Error("gateway rejected request",
				"id", msg.ID,
				"error", string(msg.Error),
			)
		} else {
			d.logger.Debug("gateway response",
				"id", msg.ID,
				"ok", msg.OK != nil && *msg.OK,
			)
		}
		return
	}

	if msg.Type != "event" {
		return
	}

	if msg.Event != "exec.approval.requested" {
		return
	}

	var req approvalRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		d.logger.Warn("unparseable approval request", "error", err)
		return
	}

	go d.handleApproval(ctx, req)
}

func (d *Daemon) handleApproval(ctx context.Context, req approvalRequest) {
	start := time.Now()

	// Evaluate against policies.
	call := engine.ToolCall{
		ID:        req.ID,
		Agent:     req.Request.AgentID,
		Session:   req.Request.Session,
		Tool:      "exec",
		Params:    map[string]any{"command": req.Request.Command, "cwd": req.Request.CWD},
		Timestamp: time.Now(),
	}

	decision := d.engine.Evaluate(call)
	evalDuration := time.Since(start)

	d.logger.Info("evaluated approval request",
		"id", req.ID,
		"command", req.Request.Command,
		"agent", req.Request.AgentID,
		"action", decision.Action.String(),
		"duration", evalDuration,
	)

	// Record audit event.
	event := audit.Event{
		Timestamp: time.Now(),
		Agent:     req.Request.AgentID,
		Session:   req.Request.Session,
		Tool:      "exec",
		Request:   map[string]any{"command": req.Request.Command, "cwd": req.Request.CWD, "host": req.Request.Host},
		Decision: audit.EventDecision{
			Action:          decision.Action.String(),
			MatchedPolicies: decision.MatchedPolicies,
			EvalTimeUS:      evalDuration.Microseconds(),
			Message:         decision.Message,
		},
	}
	d.sink.Write(event)

	// Resolve the approval.
	switch decision.Action {
	case engine.ActionAllow:
		d.resolveApproval(req.ID, "allow-once")
	case engine.ActionDeny:
		d.resolveApproval(req.ID, "deny")
	case engine.ActionLog:
		d.resolveApproval(req.ID, "allow-once")
	case engine.ActionRequireApproval:
		d.handleHumanApproval(ctx, req, call, decision)
	default:
		d.resolveApproval(req.ID, "deny")
	}
}

// handleHumanApproval creates a pending approval and waits for resolution.
// The OpenClaw approval stays pending until a human resolves via CLI/API.
func (d *Daemon) handleHumanApproval(
	ctx context.Context,
	req approvalRequest,
	call engine.ToolCall,
	decision engine.Decision,
) {
	pending, err := d.approvals.Create(call, decision)
	if err != nil {
		d.logger.Error("daemon: approval store full", "error", err)
		d.resolveApproval(req.ID, "deny")
		return
	}
	d.logger.Warn("approval required — waiting for human",
		"rampart_id", pending.ID,
		"openclaw_id", req.ID,
		"command", req.Request.Command,
		"expires", pending.ExpiresAt.Format(time.RFC3339),
	)

	// Block until the human resolves, the approval expires, or context is cancelled.
	select {
	case <-pending.Done():
		switch pending.Status {
		case approval.StatusApproved:
			d.resolveApproval(req.ID, "allow-once")
		default:
			d.resolveApproval(req.ID, "deny")
		}
	case <-ctx.Done():
		d.logger.Warn("context cancelled, denying pending approval",
			"rampart_id", pending.ID,
			"openclaw_id", req.ID,
		)
		d.resolveApproval(req.ID, "deny")
	}
}

func (d *Daemon) resolveApproval(approvalID, resolution string) {
	d.mu.Lock()
	conn := d.conn
	id := d.nextID()
	d.mu.Unlock()

	if conn == nil {
		d.logger.Error("cannot resolve approval, not connected")
		return
	}

	msg := map[string]any{
		"type":   "req",
		"id":     id,
		"method": "exec.approval.resolve",
		"params": map[string]any{
			"id":       approvalID,
			"decision": resolution,
		},
	}

	data, err := json.Marshal(msg)
	if err != nil {
		d.logger.Error("failed to marshal resolve message", "error", err, "approvalId", approvalID)
		return
	}

	d.writeMu.Lock()
	err = conn.WriteMessage(websocket.TextMessage, data)
	d.writeMu.Unlock()

	if err != nil {
		d.logger.Error("failed to resolve approval", "error", err, "approvalId", approvalID)
	} else {
		d.logger.Info("resolved approval", "id", approvalID, "resolution", resolution)
	}
}

func (d *Daemon) nextID() string {
	n := d.seq.Add(1)
	return fmt.Sprintf("rampart-%d", n)
}

// Approvals returns the daemon's approval store for external access.
func (d *Daemon) Approvals() *approval.Store {
	return d.approvals
}

// Close gracefully shuts down the daemon.
func (d *Daemon) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	var connErr, sinkErr error
	if d.conn != nil {
		connErr = d.conn.Close()
	}
	if d.sink != nil {
		sinkErr = d.sink.Close()
	}
	if d.approvals != nil {
		d.approvals.Close()
	}
	return errors.Join(connErr, sinkErr)
}
