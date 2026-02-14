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

package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/peg/rampart/internal/approval"
	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/internal/notify"
)

const defaultMode = "enforce"
const redactedResponse = "[REDACTED: sensitive content removed by Rampart]"

// Server is Rampart's HTTP proxy runtime for policy-aware tool calls.
type Server struct {
	engine       *engine.Engine
	sink         audit.AuditSink
	approvals    *approval.Store
	token        string
	mode         string
	logger       *slog.Logger
	mu           sync.Mutex
	server       *http.Server
	startedAt    time.Time
	notifyConfig *engine.NotifyConfig
}

// Option configures a proxy server.
type Option func(*Server)

// WithToken sets the bearer auth token used by the proxy.
func WithToken(token string) Option {
	return func(s *Server) {
		s.token = token
	}
}

// WithMode sets proxy operation mode: enforce, monitor, or disabled.
func WithMode(mode string) Option {
	return func(s *Server) {
		s.mode = mode
	}
}

// WithLogger sets the logger used by the proxy.
// WithNotify configures webhook notifications for policy decisions.
func WithNotify(cfg *engine.NotifyConfig) Option {
	return func(s *Server) {
		s.notifyConfig = cfg
	}
}

func WithLogger(logger *slog.Logger) Option {
	return func(s *Server) {
		if logger != nil {
			s.logger = logger
		}
	}
}

// New creates a new proxy server.
func New(eng *engine.Engine, sink audit.AuditSink, opts ...Option) *Server {
	s := &Server{
		engine:    eng,
		sink:      sink,
		approvals: approval.NewStore(),
		mode:      defaultMode,
		logger:    slog.Default(),
		startedAt: time.Now().UTC(),
	}

	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}

	if s.mode == "" {
		s.mode = defaultMode
	}
	if s.token == "" {
		s.token = generateToken(s.logger)
	}

	if len(s.token) > 4 {
		s.logger.Info("proxy: auth token", "prefix", s.token[:4]+"…")
	}
	return s
}

// Token returns the proxy's bearer token.
func (s *Server) Token() string {
	return s.token
}

// ListenAndServe starts serving HTTP requests at addr.
func (s *Server) ListenAndServe(addr string) error {
	srv := &http.Server{
		Addr:         addr,
		Handler:      s.handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	s.mu.Lock()
	s.server = srv
	s.mu.Unlock()

	if err := srv.ListenAndServe(); err != nil {
		return fmt.Errorf("proxy: listen and serve: %w", err)
	}
	return nil
}

// Serve starts serving HTTP requests on an existing listener.
func (s *Server) Serve(listener net.Listener) error {
	srv := &http.Server{
		Addr:         listener.Addr().String(),
		Handler:      s.handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	s.mu.Lock()
	s.server = srv
	s.mu.Unlock()

	if err := srv.Serve(listener); err != nil {
		return fmt.Errorf("proxy: serve: %w", err)
	}
	return nil
}

// Shutdown gracefully stops the proxy server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	srv := s.server
	s.mu.Unlock()

	if srv == nil {
		return nil
	}
	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("proxy: shutdown: %w", err)
	}
	return nil
}

// maxRequestBody is the maximum allowed request body size (1MB).
const maxRequestBody = 1 << 20

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/tool/{toolName}", s.handleToolCall)
	mux.HandleFunc("POST /v1/preflight/{toolName}", s.handlePreflight)
	mux.HandleFunc("GET /v1/approvals", s.handleListApprovals)
	mux.HandleFunc("POST /v1/approvals/{id}/resolve", s.handleResolveApproval)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})
	return http.MaxBytesHandler(mux, maxRequestBody)
}

type toolRequest struct {
	Agent   string         `json:"agent"`
	Session string         `json:"session"`
	Params  map[string]any `json:"params"`

	// Response is the tool's output for response-side policy evaluation.
	// The caller executes the tool and submits the output here for scanning
	// before returning it to the agent. If empty, response-side evaluation
	// is skipped.
	Response string `json:"response,omitempty"`
}

func (s *Server) handleToolCall(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	var req toolRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}
	if req.Params == nil {
		req.Params = map[string]any{}
	}

	toolName := r.PathValue("toolName")
	decision := engine.Decision{}

	// Enrich params with derived fields for policy matching.
	enrichParams(toolName, req.Params)

	call := engine.ToolCall{
		ID:        audit.NewEventID(),
		Agent:     req.Agent,
		Session:   req.Session,
		Tool:      toolName,
		Params:    req.Params,
		Timestamp: time.Now().UTC(),
	}

	if s.mode == "disabled" {
		decision = engine.Decision{
			Action:       engine.ActionAllow,
			Message:      "policy evaluation disabled",
			EvalDuration: 0,
		}
	} else {
		decision = s.engine.Evaluate(call)
	}

	s.writeAudit(req, toolName, decision)

	resp := map[string]any{
		"decision":         decision.Action.String(),
		"message":          decision.Message,
		"eval_duration_us": decision.EvalDuration.Microseconds(),
	}

	if len(decision.MatchedPolicies) > 0 {
		resp["policy"] = decision.MatchedPolicies[0]
	}

	if s.mode == "enforce" && decision.Action == engine.ActionDeny {
		writeJSON(w, http.StatusForbidden, resp)
		return
	}

	if s.mode == "enforce" && decision.Action == engine.ActionWebhook {
		webhookDecision := s.executeWebhookAction(call, decision)
		resp["decision"] = webhookDecision.Action.String()
		resp["message"] = webhookDecision.Message

		s.writeAudit(req, toolName, webhookDecision)

		if webhookDecision.Action == engine.ActionDeny {
			writeJSON(w, http.StatusForbidden, resp)
			return
		}

		if blocked := s.applyResponseEvaluation(call, req.Response, resp); blocked {
			writeJSON(w, http.StatusOK, resp)
			return
		}

		writeJSON(w, http.StatusOK, resp)
		return
	}

	if s.mode == "enforce" && decision.Action == engine.ActionRequireApproval {
		pending := s.approvals.Create(call, decision)

		s.logger.Info("proxy: approval required",
			"id", pending.ID,
			"tool", toolName,
			"command", call.Command(),
			"message", decision.Message,
		)

		if s.shouldNotify(decision.Action.String()) {
			go s.sendApprovalWebhook(call, decision, pending)
		}

		resp["approval_id"] = pending.ID
		resp["approval_status"] = "pending"
		resp["expires_at"] = pending.ExpiresAt.Format(time.RFC3339)
		writeJSON(w, http.StatusAccepted, resp)
		return
	}

	if blocked := s.applyResponseEvaluation(call, req.Response, resp); blocked {
		writeJSON(w, http.StatusOK, resp)
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) applyResponseEvaluation(
	call engine.ToolCall,
	output string,
	resp map[string]any,
) bool {
	if output == "" || s.mode == "disabled" {
		return false
	}

	resp["response"] = output
	result := s.engine.EvaluateResponse(call, output)
	if result.Action != engine.ActionDeny {
		return false
	}

	resp["decision"] = result.Action.String()
	resp["message"] = result.Message
	resp["eval_duration_us"] = result.EvalDuration.Microseconds()
	resp["response"] = redactedResponse
	if len(result.MatchedPolicies) > 0 {
		resp["policy"] = result.MatchedPolicies[0]
	}

	return true
}

func (s *Server) writeAudit(req toolRequest, toolName string, decision engine.Decision) {
	if s.sink == nil {
		return
	}

	event := audit.Event{
		ID:        audit.NewEventID(),
		Timestamp: time.Now().UTC(),
		Agent:     req.Agent,
		Session:   req.Session,
		Tool:      toolName,
		Request:   req.Params,
		Decision: audit.EventDecision{
			Action:          decision.Action.String(),
			MatchedPolicies: decision.MatchedPolicies,
			EvalTimeUS:      decision.EvalDuration.Microseconds(),
			Message:         decision.Message,
		},
	}

	if err := s.sink.Write(event); err != nil {
		s.logger.Error("proxy: audit write failed", "error", err)
	}

	// Fire webhook notification if configured
	if s.notifyConfig != nil && s.notifyConfig.URL != "" {
		actionStr := decision.Action.String()
		// require_approval notifications are sent after pending approval
		// creation so they can include approval metadata.
		if actionStr != engine.ActionRequireApproval.String() && s.shouldNotify(actionStr) {
			call := engine.ToolCall{
				Tool:      toolName,
				Params:    req.Params,
				Agent:     req.Agent,
				Timestamp: time.Now().UTC(),
			}
			go s.sendWebhook(call, decision)
		}
	}
}

func (s *Server) shouldNotify(actionStr string) bool {
	if s.notifyConfig == nil || s.notifyConfig.URL == "" {
		return false
	}
	if len(s.notifyConfig.On) == 0 {
		// Default: notify on deny
		return actionStr == "deny"
	}
	for _, on := range s.notifyConfig.On {
		if on == actionStr {
			return true
		}
	}
	return false
}

// handlePreflight evaluates a tool call against policies without executing it.
// Returns the decision that would be made — agents use this to plan around
// policy restrictions before attempting blocked actions.
func (s *Server) handlePreflight(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	var req toolRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}
	if req.Params == nil {
		req.Params = map[string]any{}
	}

	toolName := r.PathValue("toolName")
	enrichParams(toolName, req.Params)

	call := engine.ToolCall{
		ID:        audit.NewEventID(),
		Agent:     req.Agent,
		Session:   req.Session,
		Tool:      toolName,
		Params:    req.Params,
		Timestamp: time.Now().UTC(),
	}

	decision := s.engine.Evaluate(call)
	allowed := decision.Action == engine.ActionAllow || decision.Action == engine.ActionLog
	s.writeAudit(req, toolName, decision)

	writeJSON(w, http.StatusOK, map[string]any{
		"allowed":          allowed,
		"decision":         decision.Action.String(),
		"message":          decision.Message,
		"matched_policies": decision.MatchedPolicies,
		"eval_duration_us": decision.EvalDuration.Microseconds(),
	})
}

func (s *Server) handleListApprovals(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	pending := s.approvals.List()
	items := make([]map[string]any, 0, len(pending))

	for _, req := range pending {
		items = append(items, map[string]any{
			"id":         req.ID,
			"tool":       req.Call.Tool,
			"command":    req.Call.Command(),
			"agent":      req.Call.Agent,
			"session":    req.Call.Session,
			"message":    req.Decision.Message,
			"status":     req.Status.String(),
			"created_at": req.CreatedAt.Format(time.RFC3339),
			"expires_at": req.ExpiresAt.Format(time.RFC3339),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"approvals": items})
}

type resolveRequest struct {
	Approved   bool   `json:"approved"`
	ResolvedBy string `json:"resolved_by"`
}

func (s *Server) handleResolveApproval(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	id := r.PathValue("id")
	var req resolveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid body: %v", err))
		return
	}

	if req.ResolvedBy == "" {
		req.ResolvedBy = "api"
	}

	if err := s.approvals.Resolve(id, req.Approved, req.ResolvedBy); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	resolved, _ := s.approvals.Get(id)
	s.logger.Info("proxy: approval resolved",
		"id", id,
		"approved", req.Approved,
		"resolved_by", req.ResolvedBy,
	)

	writeJSON(w, http.StatusOK, map[string]any{
		"id":       id,
		"status":   resolved.Status.String(),
		"approved": req.Approved,
	})
}

// checkAuth validates the bearer token. Returns false if auth fails (error already written).
func (s *Server) checkAuth(w http.ResponseWriter, r *http.Request) bool {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		writeError(w, http.StatusUnauthorized, "missing authorization header")
		return false
	}

	token := strings.TrimPrefix(auth, "Bearer ")
	if token == auth || subtle.ConstantTimeCompare([]byte(token), []byte(s.token)) != 1 {
		writeError(w, http.StatusUnauthorized, "invalid authorization token")
		return false
	}
	return true
}

// Approvals returns the approval store for external access (CLI, daemon).
func (s *Server) Approvals() *approval.Store {
	return s.approvals
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	uptime := int(time.Since(s.startedAt).Seconds())
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"mode":           s.mode,
		"uptime_seconds": uptime,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// webhookActionRequest is the payload POSTed to a webhook action endpoint.
type webhookActionRequest struct {
	Tool      string         `json:"tool"`
	Params    map[string]any `json:"params"`
	Agent     string         `json:"agent"`
	Session   string         `json:"session"`
	Policy    string         `json:"policy"`
	Timestamp string         `json:"timestamp"`
}

// webhookActionResponse is the expected response from a webhook action endpoint.
type webhookActionResponse struct {
	Decision string `json:"decision"` // "allow" or "deny"
	Reason   string `json:"reason"`
}

// executeWebhookAction calls the configured webhook URL and returns an
// allow or deny decision based on the response. On error/timeout, behavior
// is determined by the fail_open setting (default: fail open).
func (s *Server) executeWebhookAction(call engine.ToolCall, decision engine.Decision) engine.Decision {
	cfg := decision.WebhookConfig
	if cfg == nil || cfg.URL == "" {
		s.logger.Error("proxy: webhook action missing config")
		return engine.Decision{
			Action:  engine.ActionAllow,
			Message: "webhook action misconfigured; failing open",
		}
	}

	policyName := "unknown"
	if len(decision.MatchedPolicies) > 0 {
		policyName = decision.MatchedPolicies[0]
	}

	payload := webhookActionRequest{
		Tool:      call.Tool,
		Params:    call.Params,
		Agent:     call.Agent,
		Session:   call.Session,
		Policy:    policyName,
		Timestamp: call.Timestamp.Format(time.RFC3339),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		s.logger.Error("proxy: webhook marshal failed", "error", err)
		return s.webhookFallback(cfg, "marshal error")
	}

	client := &http.Client{Timeout: cfg.EffectiveTimeout()}
	resp, err := client.Post(cfg.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		s.logger.Error("proxy: webhook call failed", "url", cfg.URL, "error", err)
		return s.webhookFallback(cfg, fmt.Sprintf("webhook error: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s.logger.Error("proxy: webhook returned non-2xx", "url", cfg.URL, "status", resp.StatusCode)
		return s.webhookFallback(cfg, fmt.Sprintf("webhook returned HTTP %d", resp.StatusCode))
	}

	var whResp webhookActionResponse
	if err := json.NewDecoder(resp.Body).Decode(&whResp); err != nil {
		s.logger.Error("proxy: webhook response parse failed", "error", err)
		return s.webhookFallback(cfg, "invalid webhook response")
	}

	switch strings.ToLower(whResp.Decision) {
	case "allow":
		s.logger.Info("proxy: webhook allowed", "url", cfg.URL, "tool", call.Tool)
		return engine.Decision{
			Action:          engine.ActionAllow,
			MatchedPolicies: decision.MatchedPolicies,
			Message:         "allowed by webhook",
		}
	case "deny":
		reason := whResp.Reason
		if reason == "" {
			reason = "denied by webhook"
		}
		s.logger.Info("proxy: webhook denied", "url", cfg.URL, "tool", call.Tool, "reason", reason)
		return engine.Decision{
			Action:          engine.ActionDeny,
			MatchedPolicies: decision.MatchedPolicies,
			Message:         reason,
		}
	default:
		s.logger.Error("proxy: webhook returned unknown decision", "decision", whResp.Decision)
		return s.webhookFallback(cfg, fmt.Sprintf("unknown webhook decision: %q", whResp.Decision))
	}
}

// webhookFallback returns the appropriate decision when a webhook call fails.
func (s *Server) webhookFallback(cfg *engine.WebhookActionConfig, reason string) engine.Decision {
	if cfg.EffectiveFailOpen() {
		s.logger.Warn("proxy: webhook fail-open", "reason", reason)
		return engine.Decision{
			Action:  engine.ActionAllow,
			Message: fmt.Sprintf("webhook unavailable, failing open: %s", reason),
		}
	}
	s.logger.Warn("proxy: webhook fail-closed", "reason", reason)
	return engine.Decision{
		Action:  engine.ActionDeny,
		Message: fmt.Sprintf("webhook unavailable, failing closed: %s", reason),
	}
}

func (s *Server) sendWebhook(call engine.ToolCall, decision engine.Decision) {
	command := call.Command()
	if command == "" {
		command = call.Path()
	}
	policyName := "unknown"
	if len(decision.MatchedPolicies) > 0 {
		policyName = decision.MatchedPolicies[0]
	}

	event := notify.NotifyEvent{
		Action:    decision.Action.String(),
		Tool:      call.Tool,
		Command:   command,
		Policy:    policyName,
		Message:   decision.Message,
		Agent:     call.Agent,
		Timestamp: call.Timestamp.Format(time.RFC3339),
	}

	notifier := notify.NewNotifier(s.notifyConfig.URL, s.notifyConfig.Platform)
	if err := notifier.Send(event); err != nil {
		s.logger.Error("proxy: webhook notification failed", "error", err)
	} else {
		s.logger.Debug("proxy: webhook notification sent", "action", decision.Action.String())
	}
}

func (s *Server) sendApprovalWebhook(call engine.ToolCall, decision engine.Decision, pending *approval.Request) {
	command := call.Command()
	if command == "" {
		command = call.Path()
	}
	policyName := "unknown"
	if len(decision.MatchedPolicies) > 0 {
		policyName = decision.MatchedPolicies[0]
	}

	event := notify.NotifyEvent{
		Action:     decision.Action.String(),
		Tool:       call.Tool,
		Command:    command,
		Policy:     policyName,
		Message:    decision.Message,
		Agent:      call.Agent,
		Timestamp:  pending.CreatedAt.UTC().Format(time.RFC3339),
		ApprovalID: pending.ID,
		ExpiresAt:  pending.ExpiresAt.UTC().Format(time.RFC3339),
		ResolveURL: s.approvalResolveURL(pending.ID),
	}

	notifier := notify.NewNotifier(s.notifyConfig.URL, s.notifyConfig.Platform)
	if err := notifier.Send(event); err != nil {
		s.logger.Error("proxy: approval webhook notification failed", "error", err)
	} else {
		s.logger.Debug("proxy: webhook notification sent", "action", decision.Action.String(), "approval_id", pending.ID)
	}
}

func (s *Server) approvalResolveURL(id string) string {
	addr := ""
	s.mu.Lock()
	if s.server != nil {
		addr = strings.TrimSpace(s.server.Addr)
	}
	s.mu.Unlock()

	if addr == "" {
		addr = "localhost:9090"
	}
	if strings.HasPrefix(addr, ":") {
		addr = "localhost" + addr
	}
	if !strings.Contains(addr, "://") {
		addr = "http://" + addr
	}

	base := strings.TrimRight(addr, "/")
	return fmt.Sprintf("%s/v1/approvals/%s/resolve", base, url.PathEscape(id))
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func generateToken(logger *slog.Logger) string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failure is a critical system issue. Fail hard rather
		// than starting with a predictable token.
		logger.Error("proxy: crypto/rand unavailable, cannot generate secure token", "error", err)
		panic("rampart: crypto/rand failed; refusing to start with insecure token")
	}
	return hex.EncodeToString(buf)
}

// enrichParams adds derived fields to params for richer policy matching.
// For fetch/HTTP tools, it parses the URL to extract domain, scheme, and path.
func enrichParams(toolName string, params map[string]any) {
	if toolName == "exec" {
		if cmd, ok := decodeBase64Command(params); ok {
			params["command"] = cmd
		}
		// Strip leading shell comment lines (e.g. "# description\nactual command")
		// so that command_matches patterns work against the real command.
		if cmd, ok := params["command"].(string); ok {
			params["command"] = stripLeadingComments(cmd)
		}
	}

	if toolName == "fetch" || toolName == "http" || toolName == "web_fetch" {
		rawURL, _ := params["url"].(string)
		if rawURL == "" {
			return
		}
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Host == "" {
			return
		}
		if _, ok := params["domain"]; !ok {
			params["domain"] = parsed.Hostname()
		}
		if _, ok := params["scheme"]; !ok {
			params["scheme"] = parsed.Scheme
		}
		if _, ok := params["path"]; !ok {
			params["path"] = parsed.Path
		}
	}
}

// stripLeadingComments removes leading lines that start with # (shell comments)
// from multi-line command strings. Agent frameworks often prepend descriptive
// comments (e.g. "# Check disk space\ndf -h") which break command_matches
// patterns that expect the actual command at the start of the string.
func stripLeadingComments(cmd string) string {
	lines := strings.Split(cmd, "\n")
	start := 0
	for start < len(lines) {
		trimmed := strings.TrimSpace(lines[start])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			start++
			continue
		}
		break
	}
	if start == 0 {
		return cmd
	}
	if start >= len(lines) {
		return cmd // all comments — return original
	}
	return strings.Join(lines[start:], "\n")
}

func decodeBase64Command(params map[string]any) (string, bool) {
	encoded, _ := params["command_b64"].(string)
	if strings.TrimSpace(encoded) == "" {
		return "", false
	}

	// Cap encoded input at 1MB to prevent memory exhaustion.
	const maxBase64Len = 1 << 20
	if len(encoded) > maxBase64Len {
		return "", false
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", false
	}

	return string(decoded), true
}
