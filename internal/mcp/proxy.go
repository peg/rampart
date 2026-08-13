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
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/peg/rampart/internal/approval"
	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/internal/webhookaction"
)

const (
	defaultMode             = "enforce"
	jsonRPCDenyCode         = -32600
	jsonRPCResponseDenyCode = -32603
	maxPendingRequests      = 1000
)

// Option configures MCP proxy behavior.
type Option func(*Proxy)

// WithMode sets proxy mode: enforce or monitor.
func WithMode(mode string) Option {
	return func(p *Proxy) {
		p.mode = normalizeProxyMode(mode)
	}
}

// normalizeProxyMode recognizes documented values case-insensitively and
// fails closed for empty or unknown values. NewProxy cannot return an option
// validation error, so an invalid mode must never silently disable enforcement.
func normalizeProxyMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "monitor":
		return "monitor"
	case "", "enforce":
		return defaultMode
	default:
		return defaultMode
	}
}

// WithLogger sets proxy logger.
func WithLogger(logger *slog.Logger) Option {
	return func(p *Proxy) {
		if logger != nil {
			p.logger = logger
		}
	}
}

// WithToolMapping sets custom MCP tool-to-type mappings.
func WithToolMapping(mapping map[string]string) Option {
	return func(p *Proxy) {
		if mapping == nil {
			p.toolMapping = nil
			return
		}
		p.toolMapping = make(map[string]string, len(mapping))
		for k, v := range mapping {
			p.toolMapping[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
}

// WithFilterTools enables tools/list response filtering.
func WithFilterTools(enabled bool) Option {
	return func(p *Proxy) {
		p.filterTools = enabled
	}
}

// WithApprovalStore sets an approval store used for require_approval decisions.
// The embedding caller must expose a real resolver for this exact store; an
// inaccessible private store would only make tool calls wait until expiry.
func WithApprovalStore(store *approval.Store) Option {
	return func(p *Proxy) {
		p.approvals = store
	}
}

// WithAgentID sets the agent identity used in policy evaluation and audit events.
// Defaults to "mcp-client" if not set.
func WithAgentID(id string) Option {
	return func(p *Proxy) {
		if strings.TrimSpace(id) != "" {
			p.agentID = strings.TrimSpace(id)
		}
	}
}

// WithSessionID sets the session identity used in policy evaluation and audit events.
// Defaults to "mcp-proxy" if not set.
func WithSessionID(id string) Option {
	return func(p *Proxy) {
		if strings.TrimSpace(id) != "" {
			p.sessionID = strings.TrimSpace(id)
		}
	}
}

// Proxy evaluates MCP tools/call requests before forwarding to child MCP server.
type Proxy struct {
	engine *engine.Engine
	sink   audit.AuditSink

	mode        string
	logger      *slog.Logger
	filterTools bool
	toolMapping map[string]string
	approvals   *approval.Store
	agentID     string
	sessionID   string

	childIn   io.WriteCloser
	childOut  io.Reader
	parentOut io.Writer

	outMu sync.Mutex

	stopCh   chan struct{}
	stopOnce sync.Once

	pendingMu       sync.Mutex
	pendingCond     *sync.Cond
	pendingOwner    uint64
	pendingCalls    map[string]pendingCall
	pendingToolList map[string]struct{}
	pendingGeneric  map[string]struct{}
}

type pendingCallState uint8

const (
	pendingCallReserved pendingCallState = iota + 1
	pendingCallWriting
	pendingCallResponseActive
	pendingCallRejected
)

type pendingCall struct {
	state   pendingCallState
	owner   uint64
	call    engine.ToolCall
	request map[string]any
}

type pendingCallReservation struct {
	key   string
	owner uint64
}

func (r pendingCallReservation) valid() bool {
	return r.key != "" && r.owner != 0
}

type pendingResponseKind uint8

const (
	pendingResponseGeneric pendingResponseKind = iota + 1
	pendingResponseToolList
	pendingResponseToolCall
)

type pendingResponse struct {
	kind     pendingResponseKind
	toolCall pendingCall
}

// NewProxy creates a new MCP stdio proxy.
func NewProxy(eng *engine.Engine, sink audit.AuditSink, childIn io.WriteCloser, childOut io.Reader, opts ...Option) *Proxy {
	p := &Proxy{
		engine:          eng,
		sink:            sink,
		mode:            defaultMode,
		logger:          slog.Default(),
		childIn:         childIn,
		childOut:        childOut,
		stopCh:          make(chan struct{}),
		pendingCalls:    make(map[string]pendingCall),
		pendingToolList: make(map[string]struct{}),
		pendingGeneric:  make(map[string]struct{}),
	}
	p.pendingCond = sync.NewCond(&p.pendingMu)
	for _, opt := range opts {
		if opt != nil {
			opt(p)
		}
	}
	p.mode = normalizeProxyMode(p.mode)
	if p.agentID == "" {
		p.agentID = "mcp-client"
	}
	if p.sessionID == "" {
		p.sessionID = "mcp-proxy"
	}
	return p
}

// Run starts bidirectional proxying between parent stdio and child MCP stdio.
func (p *Proxy) Run(ctx context.Context, parentIn io.Reader, parentOut io.Writer) error {
	defer p.closeStop()

	if parentIn == nil || parentOut == nil {
		return fmt.Errorf("mcp: parent streams must be non-nil")
	}
	if p.childIn == nil || p.childOut == nil {
		return fmt.Errorf("mcp: child streams must be non-nil")
	}
	if p.engine == nil {
		return fmt.Errorf("mcp: engine must be non-nil")
	}
	p.parentOut = parentOut

	clientErrCh := make(chan error, 1)
	childErrCh := make(chan error, 1)

	go func() {
		clientErrCh <- p.proxyClientToChild(ctx, parentIn)
	}()
	go func() {
		childErrCh <- p.proxyChildToClient(parentOut)
	}()

	select {
	case <-ctx.Done():
		_ = p.childIn.Close()
		return nil
	case err := <-clientErrCh:
		_ = p.childIn.Close()
		childErr := <-childErrCh
		return joinProxyErrors(err, childErr)
	case err := <-childErrCh:
		_ = p.childIn.Close()
		return err
	}
}

func (p *Proxy) closeStop() {
	p.stopOnce.Do(func() {
		close(p.stopCh)
	})
}

func joinProxyErrors(a, b error) error {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return fmt.Errorf("%w; %v", a, b)
}

func (p *Proxy) proxyClientToChild(ctx context.Context, parentIn io.Reader) error {
	reader := bufio.NewReaderSize(parentIn, maxLineBytes)
	for {
		line, err := readLine(reader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("mcp: read parent stdin: %w", err)
		}
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if handleErr := p.handleClientLineWithContext(ctx, line); handleErr != nil {
			return handleErr
		}
	}
}

func (p *Proxy) proxyChildToClient(parentOut io.Writer) error {
	reader := bufio.NewReaderSize(p.childOut, maxLineBytes)
	for {
		line, err := readLine(reader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("mcp: read child stdout: %w", err)
		}
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if handleErr := p.handleChildLine(line, parentOut); handleErr != nil {
			return handleErr
		}
	}
}

// maxLineBytes is the maximum number of bytes allowed in a single JSON-RPC line.
// Lines exceeding this limit are rejected to prevent OOM from malicious peers.
const maxLineBytes = 4 * 1024 * 1024 // 4 MB

// readLine reads a newline-terminated line from reader, enforcing maxLineBytes.
// It uses ReadSlice to read in buffer-sized chunks so we can detect an
// oversized line before the full allocation occurs.
func readLine(reader *bufio.Reader) ([]byte, error) {
	var result []byte
	for {
		chunk, err := reader.ReadSlice('\n')
		result = append(result, chunk...)
		if len(result) > maxLineBytes {
			return nil, fmt.Errorf("mcp: line exceeds %d-byte limit", maxLineBytes)
		}
		if err == nil {
			// Delimiter found — full line is in result.
			return result, nil
		}
		if err == bufio.ErrBufferFull {
			// Buffer full but no delimiter yet; keep accumulating.
			continue
		}
		if err == io.EOF {
			if len(result) > 0 {
				return result, nil
			}
			return nil, err
		}
		return nil, err
	}
}

func (p *Proxy) handleClientLine(line []byte) error {
	return p.handleClientLineWithContext(context.Background(), line)
}

func (p *Proxy) handleClientLineWithContext(ctx context.Context, line []byte) error {
	trimmed := bytes.TrimSpace(line)
	if p.mode == "enforce" {
		if err := validateUniqueJSONKeys(trimmed); err != nil {
			p.logger.Warn("mcp: rejecting ambiguous JSON-RPC envelope", "error", err)
			return p.writeErrorToClient(json.RawMessage("null"), jsonRPCDenyCode, "Rampart: invalid JSON-RPC request envelope")
		}
		if _, err := decodeCanonicalJSONObject(trimmed, "jsonrpc", "id", "method", "params"); err != nil {
			p.logger.Warn("mcp: rejecting case-shadowed JSON-RPC envelope", "error", err)
			return p.writeErrorToClient(json.RawMessage("null"), jsonRPCDenyCode, "Rampart: invalid JSON-RPC request envelope")
		}
	}

	var req Request
	if err := json.Unmarshal(trimmed, &req); err != nil {
		if p.mode == "enforce" {
			p.logger.Warn("mcp: rejecting invalid JSON-RPC envelope", "error", err)
			return p.writeErrorToClient(json.RawMessage("null"), jsonRPCDenyCode, "Rampart: invalid JSON-RPC request envelope")
		}
		p.logger.Debug("mcp: pass through non-json line in monitor mode", "error", err)
		return p.writeToChild(line)
	}

	if req.Method == "tools/call" {
		if p.mode == "enforce" {
			if req.JSONRPC != "2.0" {
				return p.writeErrorToClient(responseID(req.ID), jsonRPCDenyCode, "Rampart: invalid tools/call JSON-RPC envelope")
			}
			if !validRequestID(req.ID) {
				// tools/call is an MCP request, not a notification. A missing ID
				// cannot receive an error response, so silently drop it rather than
				// forwarding an untrackable execution boundary.
				if !HasID(req.ID) {
					p.logger.Warn("mcp: dropping tools/call without a request id")
					return nil
				}
				return p.writeErrorToClient(json.RawMessage("null"), jsonRPCDenyCode, "Rampart: invalid tools/call request id")
			}
		}
		return p.handleToolsCall(ctx, req, line)
	}

	pendingToolListID := ""
	pendingGenericID := ""
	if p.filterTools && req.Method == "tools/list" && HasID(req.ID) {
		var err error
		pendingToolListID, err = p.trackPendingToolList(req.ID)
		if err != nil {
			if p.mode == "enforce" {
				return p.writeErrorToClient(responseID(req.ID), jsonRPCDenyCode, "Rampart: "+err.Error())
			}
			p.logger.Debug("mcp: untrackable tools/list id in monitor mode; passing through", "error", err)
			pendingToolListID = ""
		}
	} else if req.Method != "" && HasID(req.ID) {
		var err error
		pendingGenericID, err = p.reservePendingGeneric(req.ID)
		if err != nil {
			if p.mode == "enforce" {
				return p.writeErrorToClient(responseID(req.ID), jsonRPCDenyCode, "Rampart: "+err.Error())
			}
			p.logger.Debug("mcp: untrackable request id in monitor mode; passing through", "method", req.Method, "error", err)
			pendingGenericID = ""
		}
	}

	if err := p.writeToChild(line); err != nil {
		p.releasePendingToolList(pendingToolListID)
		p.releasePendingGeneric(pendingGenericID)
		return err
	}
	return nil
}

func (p *Proxy) handleToolsCall(ctx context.Context, req Request, rawLine []byte) error {
	if p.mode == "enforce" {
		paramsFields, err := decodeCanonicalJSONObject(req.Params, "name", "arguments")
		if err != nil {
			return p.writeErrorToClient(responseID(req.ID), jsonRPCDenyCode, "Rampart: invalid tools/call params")
		}
		if arguments, ok := paramsFields["arguments"]; ok && !bytes.Equal(bytes.TrimSpace(arguments), []byte("null")) {
			if _, err := decodeCanonicalJSONObject(arguments, securitySensitiveArgumentKeys...); err != nil {
				return p.writeErrorToClient(responseID(req.ID), jsonRPCDenyCode, "Rampart: invalid tools/call arguments")
			}
		}
	}
	var params ToolsCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		if p.mode == "enforce" && HasID(req.ID) {
			return p.writeErrorToClient(req.ID, jsonRPCDenyCode, "Rampart: invalid tools/call params")
		}
		p.logger.Debug("mcp: tools/call params parse failed; passing through", "error", err)
		return p.writeToChild(rawLine)
	}
	if strings.TrimSpace(params.Name) == "" {
		if p.mode == "enforce" {
			if HasID(req.ID) {
				return p.writeErrorToClient(responseID(req.ID), jsonRPCDenyCode, "Rampart: invalid tools/call params: tool name is required")
			}
			return nil
		}
		return p.writeToChild(rawLine)
	}

	if params.Arguments == nil {
		params.Arguments = map[string]any{}
	}

	var reservation pendingCallReservation
	if HasID(req.ID) {
		var reserveErr error
		reservation, reserveErr = p.reservePendingCall(req.ID)
		if reserveErr != nil {
			if p.mode == "enforce" {
				return p.writeErrorToClient(responseID(req.ID), jsonRPCDenyCode, "Rampart: "+reserveErr.Error())
			}
			p.logger.Debug("mcp: untrackable tools/call id in monitor mode; passing through", "error", reserveErr)
		}
		defer p.releasePendingCall(reservation)
	}

	requestData := buildRequestData(req.Method, params.Name, params.Arguments)
	mappedTool := MapToolName(params.Name, p.toolMapping)

	call := engine.ToolCall{
		ID:        audit.NewEventID(),
		Agent:     p.agentID,
		Session:   p.sessionID,
		Tool:      mappedTool,
		Params:    requestData,
		Input:     params.Arguments,
		Timestamp: time.Now().UTC(),
	}

	var decision engine.Decision
	if p.mode == "enforce" {
		decision = p.engine.Enforce(call, engine.EvalOptions{})
	} else {
		decision = p.engine.EvaluateWith(call, engine.EvalOptions{})
	}
	if err := p.writeAudit(call, decision, requestData, nil); err != nil {
		p.logger.Error("mcp: audit write failed", "error", err)
		if p.mode == "enforce" {
			if HasID(req.ID) {
				return p.writeErrorToClient(req.ID, jsonRPCDenyCode, "Rampart: audit storage is unavailable; refusing tool call")
			}
			return nil
		}
	}

	if p.mode == "enforce" && decision.Action == engine.ActionDeny {
		message := strings.TrimSpace(decision.Message)
		if message == "" {
			message = "request denied by policy"
		}
		if HasID(req.ID) {
			return p.writeErrorToClient(req.ID, jsonRPCDenyCode, "Rampart: "+message)
		}
		return nil
	}

	if p.mode == "enforce" && (decision.Action == engine.ActionRequireApproval || decision.Action == engine.ActionAsk) {
		message := strings.TrimSpace(decision.Message)
		if message == "" {
			message = "request requires approval"
		}
		if p.approvals == nil {
			if HasID(req.ID) {
				return p.writeErrorToClient(req.ID, jsonRPCDenyCode, "Rampart: approval required, but this MCP proxy has no approval resolver; refusing request")
			}
			return nil
		}

		pending, err := p.approvals.Create(call, decision)
		if err != nil {
			p.logger.Error("mcp: approval store full", "error", err)
			return p.writeErrorToClient(req.ID, jsonRPCDenyCode, "Rampart: "+err.Error())
		}
		p.logger.Info("mcp: approval required",
			"id", pending.ID,
			"tool", mappedTool,
			"command", call.Command(),
			"message", decision.Message,
			"expires", pending.ExpiresAt.Format(time.RFC3339),
		)

		select {
		case <-pending.Done():
			if pending.Status != approval.StatusApproved {
				denyMessage := message
				if pending.Status == approval.StatusExpired {
					denyMessage = "request approval expired"
				}
				if HasID(req.ID) {
					return p.writeErrorToClient(req.ID, jsonRPCDenyCode, "Rampart: "+denyMessage)
				}
				return nil
			}
		case <-ctx.Done():
			return nil
		case <-p.stopCh:
			return nil
		}
	}

	if p.mode == "enforce" && decision.Action == engine.ActionWebhook {
		webhookDecision := webhookaction.Execute(p.logger, call, decision)
		webhookRequest := cloneMap(requestData)
		webhookRequest["mcp_phase"] = "webhook_result"
		if err := p.writeAudit(call, webhookDecision, webhookRequest, nil); err != nil {
			p.logger.Error("mcp: webhook-result audit write failed", "error", err)
			if HasID(req.ID) {
				return p.writeErrorToClient(req.ID, jsonRPCDenyCode, "Rampart: audit storage is unavailable; refusing tool call")
			}
			return nil
		}
		if webhookDecision.Action == engine.ActionDeny {
			denyMsg := strings.TrimSpace(webhookDecision.Message)
			if denyMsg == "" {
				denyMsg = "request denied by webhook"
			}
			if HasID(req.ID) {
				return p.writeErrorToClient(req.ID, jsonRPCDenyCode, "Rampart: "+denyMsg)
			}
			return nil
		}
		// Webhook allowed — fall through to forward the call.
	}

	if reservation.valid() {
		forwarded, err := p.forwardReservedCall(reservation, pendingCall{call: call, request: requestData}, rawLine)
		if err != nil {
			return err
		}
		if forwarded {
			return nil
		}
		if p.mode == "enforce" {
			return p.writeErrorToClient(responseID(req.ID), jsonRPCDenyCode, "Rampart: tools/call correlation was invalidated before forwarding")
		}
		p.logger.Debug("mcp: tools/call correlation invalidated in monitor mode; passing through untracked")
	}
	return p.writeToChild(rawLine)
}

func responseID(id json.RawMessage) json.RawMessage {
	if validRequestID(id) {
		return id
	}
	return json.RawMessage("null")
}

// validRequestID accepts the MCP/JSON-RPC request ID forms Rampart can track.
// JSON-RPC discourages fractional numeric IDs, and MCP requires a request ID to
// be a string or integer that is not null.
func validRequestID(id json.RawMessage) bool {
	_, err := normalizedID(id)
	return err == nil
}

func (p *Proxy) reservePendingCall(id json.RawMessage) (pendingCallReservation, error) {
	key, err := normalizedID(id)
	if err != nil {
		return pendingCallReservation{}, fmt.Errorf("invalid request id: %w", err)
	}
	p.pendingMu.Lock()
	defer p.pendingMu.Unlock()
	if p.pendingIDExistsLocked(key) {
		return pendingCallReservation{}, fmt.Errorf("request id %s is already pending", key)
	}
	if p.pendingCountLocked() >= maxPendingRequests {
		return pendingCallReservation{}, fmt.Errorf("pending tools/call capacity reached")
	}
	p.pendingOwner++
	if p.pendingOwner == 0 {
		p.pendingOwner++
	}
	reservation := pendingCallReservation{key: key, owner: p.pendingOwner}
	// Reservation blocks duplicate IDs during evaluation and approval, but is
	// deliberately not eligible to correlate a child response.
	p.pendingCalls[key] = pendingCall{state: pendingCallReserved, owner: reservation.owner}
	return reservation, nil
}

func (p *Proxy) releasePendingCall(reservation pendingCallReservation) {
	if !reservation.valid() {
		return
	}
	p.pendingMu.Lock()
	if pending, ok := p.pendingCalls[reservation.key]; ok && pending.owner == reservation.owner {
		delete(p.pendingCalls, reservation.key)
	}
	p.pendingMu.Unlock()
}

// forwardReservedCall moves an owned reservation through a non-correlatable
// writing state and makes it response-active only after the child write
// succeeds. Responses that arrive while the write is in progress wait for the
// outcome, so an immediate legitimate response cannot outrun activation.
func (p *Proxy) forwardReservedCall(reservation pendingCallReservation, call pendingCall, line []byte) (bool, error) {
	p.pendingMu.Lock()
	pending, owned := p.pendingCalls[reservation.key]
	if !owned || pending.owner != reservation.owner || pending.state != pendingCallReserved {
		p.pendingMu.Unlock()
		return false, nil
	}
	call.state = pendingCallWriting
	call.owner = reservation.owner
	p.pendingCalls[reservation.key] = call
	p.pendingMu.Unlock()

	writeErr := p.writeToChild(line)

	p.pendingMu.Lock()
	pending, owned = p.pendingCalls[reservation.key]
	owned = owned && pending.owner == reservation.owner && pending.state == pendingCallWriting
	if owned {
		if writeErr != nil {
			delete(p.pendingCalls, reservation.key)
		} else {
			pending.state = pendingCallResponseActive
			pending.owner = 0
			p.pendingCalls[reservation.key] = pending
		}
	}
	p.pendingCond.Broadcast()
	p.pendingMu.Unlock()

	if writeErr != nil {
		return false, writeErr
	}
	if !owned {
		return false, fmt.Errorf("mcp: tools/call correlation lost while forwarding")
	}
	return true, nil
}

func (p *Proxy) trackPendingToolList(id json.RawMessage) (string, error) {
	key, err := normalizedID(id)
	if err != nil {
		return "", fmt.Errorf("invalid request id: %w", err)
	}
	p.pendingMu.Lock()
	defer p.pendingMu.Unlock()
	if p.pendingIDExistsLocked(key) {
		return "", fmt.Errorf("request id %s is already pending", key)
	}
	if p.pendingCountLocked() >= maxPendingRequests {
		return "", fmt.Errorf("pending tools/list capacity reached")
	}
	p.pendingToolList[key] = struct{}{}
	return key, nil
}

func (p *Proxy) releasePendingToolList(key string) {
	if key == "" {
		return
	}
	p.pendingMu.Lock()
	delete(p.pendingToolList, key)
	p.pendingMu.Unlock()
}

func (p *Proxy) reservePendingGeneric(id json.RawMessage) (string, error) {
	key, err := normalizedID(id)
	if err != nil {
		return "", fmt.Errorf("invalid request id: %w", err)
	}
	p.pendingMu.Lock()
	defer p.pendingMu.Unlock()
	if p.pendingIDExistsLocked(key) {
		return "", fmt.Errorf("request id %s is already pending", key)
	}
	if p.pendingCountLocked() >= maxPendingRequests {
		return "", fmt.Errorf("pending request capacity reached")
	}
	p.pendingGeneric[key] = struct{}{}
	return key, nil
}

func (p *Proxy) releasePendingGeneric(key string) {
	if key == "" {
		return
	}
	p.pendingMu.Lock()
	delete(p.pendingGeneric, key)
	p.pendingMu.Unlock()
}

func (p *Proxy) pendingIDExistsLocked(key string) bool {
	if _, exists := p.pendingCalls[key]; exists {
		return true
	}
	if _, exists := p.pendingToolList[key]; exists {
		return true
	}
	_, exists := p.pendingGeneric[key]
	return exists
}

func (p *Proxy) pendingCountLocked() int {
	return len(p.pendingCalls) + len(p.pendingToolList) + len(p.pendingGeneric)
}

func (p *Proxy) handleChildLine(line []byte, parentOut io.Writer) error {
	trimmed := bytes.TrimSpace(line)
	var responseFields map[string]json.RawMessage
	if p.mode == "enforce" {
		if err := validateUniqueJSONKeys(trimmed); err != nil {
			p.logger.Warn("mcp: rejecting invalid or ambiguous child JSON-RPC envelope", "error", err)
			return fmt.Errorf("mcp: reject child JSON-RPC response: %w", err)
		}
		var err error
		responseFields, err = decodeCanonicalJSONObject(trimmed, "jsonrpc", "id", "method", "params", "result", "error")
		if err != nil {
			p.logger.Warn("mcp: rejecting case-shadowed child JSON-RPC envelope", "error", err)
			return fmt.Errorf("mcp: reject child JSON-RPC response: %w", err)
		}
	}

	var resp Response
	if err := json.Unmarshal(trimmed, &resp); err != nil {
		if p.mode == "enforce" {
			return fmt.Errorf("mcp: reject child JSON-RPC response: %w", err)
		}
		p.logger.Debug("mcp: child line is not JSON-RPC response; pass through", "error", err)
		return p.writeToClient(parentOut, line)
	}
	if responseFields == nil {
		responseFields, _ = decodeCanonicalJSONObject(trimmed, "jsonrpc", "id", "method", "params", "result", "error")
	}

	var responseIDKey string
	if HasID(resp.ID) {
		var err error
		responseIDKey, err = normalizedID(resp.ID)
		if err != nil {
			if p.mode == "enforce" {
				return fmt.Errorf("mcp: reject child JSON-RPC response: invalid response id: %w", err)
			}
			return p.writeToClient(parentOut, line)
		}
	}

	_, hasMethod := responseFields["method"]
	_, hasResult := responseFields["result"]
	_, hasError := responseFields["error"]
	if hasMethod {
		if p.mode == "enforce" && (hasResult || hasError) {
			return fmt.Errorf("mcp: reject ambiguous child JSON-RPC request/response envelope")
		}
		// MCP is bidirectional: a child server request or notification is not a
		// response to a client request, even when their ID values happen to match.
		return p.writeToClient(parentOut, line)
	}

	if responseIDKey == "" {
		if p.mode == "enforce" {
			return fmt.Errorf("mcp: reject child JSON-RPC response: uncorrelated response")
		}
		return p.writeToClient(parentOut, line)
	}

	if !p.preparePendingResponse(responseIDKey) {
		if p.mode == "enforce" {
			return fmt.Errorf("mcp: reject child JSON-RPC response: uncorrelated response")
		}
		return p.writeToClient(parentOut, line)
	}
	if p.mode == "enforce" {
		if err := validateCorrelatedResponse(resp, responseFields); err != nil {
			return fmt.Errorf("mcp: reject child JSON-RPC response: %w", err)
		}
	}

	pending, correlated := p.consumePendingResponse(responseIDKey)
	if !correlated {
		if p.mode == "enforce" {
			return fmt.Errorf("mcp: reject child JSON-RPC response: uncorrelated response")
		}
		return p.writeToClient(parentOut, line)
	}
	if pending.kind == pendingResponseToolList && p.filterTools {
		filtered, err := p.filterToolsListResponse(resp)
		if err != nil {
			return err
		}
		return p.writeToClient(parentOut, filtered)
	}
	if pending.kind != pendingResponseToolCall {
		return p.writeToClient(parentOut, line)
	}

	responseBody, responseErr := extractResponseBody(responseFields)
	if responseErr != nil {
		if p.mode == "enforce" {
			return p.writeErrorToClient(resp.ID, jsonRPCResponseDenyCode, "Rampart: invalid tool response; refusing output")
		}
		p.logger.Debug("mcp: response canonicalization failed in monitor mode", "error", responseErr)
	}
	if responseBody != "" {
		result := p.engine.EvaluateResponse(pending.toolCall.call, responseBody)
		responseRequest := cloneMap(pending.toolCall.request)
		responseRequest["mcp_phase"] = "response"
		if err := p.writeAudit(pending.toolCall.call, result, responseRequest, &audit.ToolResponse{DurationMS: result.EvalDuration.Milliseconds()}); err != nil {
			p.logger.Error("mcp: response audit write failed", "error", err)
			if p.mode == "enforce" {
				return p.writeErrorToClient(resp.ID, jsonRPCResponseDenyCode, "Rampart: audit storage is unavailable; refusing tool response")
			}
		}

		if p.mode == "enforce" && result.Action == engine.ActionDeny {
			message := strings.TrimSpace(result.Message)
			if message == "" {
				message = "response blocked by policy"
			}
			return p.writeErrorToClient(resp.ID, jsonRPCResponseDenyCode, "Rampart: "+message)
		}
	}

	return p.writeToClient(parentOut, line)
}

// preparePendingResponse waits for an in-progress child write to commit before
// allowing correlation. A response that arrives while a tools/call is merely
// reserved invalidates that reservation; it must never consume empty metadata
// or allow the request to be forwarded later.
func (p *Proxy) preparePendingResponse(normalized string) bool {
	p.pendingMu.Lock()
	defer p.pendingMu.Unlock()
	for {
		if call, ok := p.pendingCalls[normalized]; ok {
			switch call.state {
			case pendingCallReserved:
				call.state = pendingCallRejected
				p.pendingCalls[normalized] = call
				return false
			case pendingCallWriting:
				p.pendingCond.Wait()
				continue
			case pendingCallResponseActive:
				return true
			default:
				return false
			}
		}
		if _, ok := p.pendingToolList[normalized]; ok {
			return true
		}
		_, ok := p.pendingGeneric[normalized]
		return ok
	}
}

func (p *Proxy) consumePendingResponse(normalized string) (pendingResponse, bool) {
	p.pendingMu.Lock()
	defer p.pendingMu.Unlock()
	if call, ok := p.pendingCalls[normalized]; ok {
		if call.state != pendingCallResponseActive {
			return pendingResponse{}, false
		}
		delete(p.pendingCalls, normalized)
		return pendingResponse{kind: pendingResponseToolCall, toolCall: call}, true
	}
	if _, ok := p.pendingToolList[normalized]; ok {
		delete(p.pendingToolList, normalized)
		return pendingResponse{kind: pendingResponseToolList}, true
	}
	if _, ok := p.pendingGeneric[normalized]; ok {
		delete(p.pendingGeneric, normalized)
		return pendingResponse{kind: pendingResponseGeneric}, true
	}
	return pendingResponse{}, false
}

func validateCorrelatedResponse(resp Response, fields map[string]json.RawMessage) error {
	if resp.JSONRPC != "2.0" {
		return fmt.Errorf("correlated response must use jsonrpc 2.0")
	}
	_, hasResult := fields["result"]
	_, hasError := fields["error"]
	if hasResult == hasError {
		return fmt.Errorf("correlated response must contain exactly one of result or error")
	}
	return nil
}

func (p *Proxy) filterToolsListResponse(resp Response) ([]byte, error) {
	var result map[string]any
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		p.logger.Debug("mcp: tools/list result parse failed; skipping filter", "error", err)
		return ensureTrailingNewline(mustJSONMarshal(resp)), nil
	}

	toolsAny, ok := result["tools"].([]any)
	if !ok {
		return ensureTrailingNewline(mustJSONMarshal(resp)), nil
	}

	filtered := make([]any, 0, len(toolsAny))
	for _, item := range toolsAny {
		toolObj, ok := item.(map[string]any)
		if !ok {
			filtered = append(filtered, item)
			continue
		}
		name, _ := toolObj["name"].(string)
		toolType := MapToolName(name, p.toolMapping)
		requestData := map[string]any{
			"mcp_method": "tools/list",
			"mcp_tool":   name,
		}
		call := engine.ToolCall{
			ID:        audit.NewEventID(),
			Agent:     p.agentID,
			Session:   p.sessionID,
			Tool:      toolType,
			Params:    requestData,
			Timestamp: time.Now().UTC(),
		}
		decision := p.engine.Evaluate(call)
		if err := p.writeAudit(call, decision, requestData, nil); err != nil {
			p.logger.Error("mcp: tool-list audit write failed", "tool", name, "error", err)
			if p.mode == "enforce" {
				// If the enforcement record cannot be persisted, do not advertise the
				// tool as available to the client.
				continue
			}
		}

		if p.mode == "enforce" && decision.Action == engine.ActionDeny {
			continue
		}
		filtered = append(filtered, item)
	}

	result["tools"] = filtered
	resp.Result = mustJSONMarshal(result)
	return ensureTrailingNewline(mustJSONMarshal(resp)), nil
}

var securitySensitiveArgumentKeys = []string{
	"command", "cmd", "input",
	"path", "file_path", "file", "filepath", "target",
	"url", "uri", "href",
	"workdir", "cwd",
	"domain", "scheme",
}

func buildRequestData(method, toolName string, arguments map[string]any) map[string]any {
	params := make(map[string]any, len(arguments)+4)
	for k, v := range arguments {
		params[k] = v
	}
	params["mcp_method"] = method
	params["mcp_tool"] = toolName

	if cmd, ok := firstString(arguments, "command", "cmd", "input"); ok {
		if _, exists := params["command"]; !exists {
			params["command"] = cmd
		}
	}

	if path, ok := firstString(arguments, "path", "file", "filepath", "target"); ok {
		if _, exists := params["path"]; !exists {
			params["path"] = path
		}
	}

	if rawURL, ok := firstString(arguments, "url", "uri", "href"); ok {
		params["url"] = rawURL
		if parsed, err := url.Parse(rawURL); err == nil && parsed.Host != "" {
			// Domain and scheme are derived from the URL. Caller-supplied
			// decoys must never override the destination policy evaluates.
			params["domain"] = parsed.Hostname()
			params["scheme"] = parsed.Scheme
			if _, exists := params["path"]; !exists && parsed.Path != "" {
				params["path"] = parsed.Path
			}
		}
	}

	return params
}

func firstString(arguments map[string]any, keys ...string) (string, bool) {
	for _, key := range keys {
		value, ok := arguments[key].(string)
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		return value, true
	}
	return "", false
}

func extractResponseBody(fields map[string]json.RawMessage) (string, error) {
	var raw json.RawMessage
	if result, ok := fields["result"]; ok {
		raw = result
	} else if responseError, ok := fields["error"]; ok {
		raw = responseError
	} else {
		return "", nil
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return "", err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return "", fmt.Errorf("multiple response JSON values")
		}
		return "", err
	}
	var canonical bytes.Buffer
	encoder := json.NewEncoder(&canonical)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(decoded); err != nil {
		return "", err
	}
	// Scan both representations. The decoded form exposes Unicode and escaped
	// delimiters; the raw form retains any policy patterns intentionally written
	// against serialized JSON.
	return string(raw) + "\n" + strings.TrimSpace(canonical.String()), nil
}

func (p *Proxy) writeAudit(call engine.ToolCall, decision engine.Decision, request map[string]any, response *audit.ToolResponse) error {
	if p.sink == nil {
		return nil
	}
	if request == nil {
		request = cloneMap(call.Params)
	}

	event := audit.Event{
		ID:         audit.NewEventID(),
		Timestamp:  time.Now().UTC(),
		Agent:      call.Agent,
		Session:    call.Session,
		ToolCallID: call.ID,
		Tool:       call.Tool,
		Request:    request,
		Decision: audit.EventDecision{
			Action:          decision.Action.String(),
			MatchedPolicies: decision.MatchedPolicies,
			EvalTimeUS:      decision.EvalDuration.Microseconds(),
			Message:         decision.Message,
		},
		Response: response,
	}

	return p.sink.Write(event)
}

func (p *Proxy) writeErrorToClient(id json.RawMessage, code int, message string) error {
	payload, err := MarshalErrorResponse(id, code, message)
	if err != nil {
		return fmt.Errorf("mcp: marshal error response: %w", err)
	}
	return p.writeToClient(p.parentOut, payload)
}

func (p *Proxy) writeToChild(line []byte) error {
	if _, err := p.childIn.Write(ensureTrailingNewline(line)); err != nil {
		return fmt.Errorf("mcp: write to child stdin: %w", err)
	}
	return nil
}

func (p *Proxy) writeToClient(parentOut io.Writer, line []byte) error {
	if parentOut == nil {
		return nil
	}
	p.outMu.Lock()
	defer p.outMu.Unlock()
	if _, err := parentOut.Write(ensureTrailingNewline(line)); err != nil {
		return fmt.Errorf("mcp: write to parent stdout: %w", err)
	}
	return nil
}

func ensureTrailingNewline(line []byte) []byte {
	if len(line) == 0 {
		return []byte("\n")
	}
	if line[len(line)-1] == '\n' {
		return line
	}
	withNL := make([]byte, 0, len(line)+1)
	withNL = append(withNL, line...)
	withNL = append(withNL, '\n')
	return withNL
}

func cloneMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func mustJSONMarshal(v any) []byte {
	encoded, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return encoded
}
