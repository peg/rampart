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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/peg/rampart/internal/approval"
	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/build"
	"github.com/peg/rampart/internal/dashboard"
	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/internal/notify"
	"github.com/peg/rampart/internal/signing"
)

const defaultMode = "enforce"
const redactedResponse = "[REDACTED: sensitive content removed by Rampart]"

// Server is Rampart's HTTP proxy runtime for policy-aware tool calls.
type Server struct {
	engine         *engine.Engine
	sink           audit.AuditSink
	approvals        *approval.Store
	approvalTimeout  time.Duration
	token          string
	mode           string
	configPath     string
	logger         *slog.Logger
	resolveBaseURL string
	listenAddr     string
	signer         *signing.Signer
	mu             sync.Mutex
	server         *http.Server
	startedAt      time.Time
	notifyConfig   *engine.NotifyConfig
	metricsEnabled bool
	auditDir       string
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

// WithResolveBaseURL sets the base URL used for approval resolve links.
func WithResolveBaseURL(url string) Option {
	return func(s *Server) {
		s.resolveBaseURL = strings.TrimSpace(url)
	}
}

// WithMetrics enables the /metrics Prometheus endpoint.
func WithMetrics(enabled bool) Option {
	return func(s *Server) {
		s.metricsEnabled = enabled
	}
}

// WithSigner enables HMAC-signed approval resolve URLs.
func WithSigner(signer *signing.Signer) Option {
	return func(s *Server) {
		s.signer = signer
	}
}

// WithApprovalTimeout sets the approval expiration duration.
func WithApprovalTimeout(d time.Duration) Option {
	return func(s *Server) {
		s.approvalTimeout = d
	}
}

// WithConfigPath sets the config path string shown in the /v1/policy endpoint.
// Use "embedded:standard" when the embedded default policy is active.
func WithConfigPath(path string) Option {
	return func(s *Server) {
		s.configPath = path
	}
}

// New creates a new proxy server.
func New(eng *engine.Engine, sink audit.AuditSink, opts ...Option) *Server {
	s := &Server{
		engine:    eng,
		sink:      sink,
		approvals: nil, // initialized after options
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

	// Initialize approval store with timeout.
	var storeOpts []approval.Option
	if s.approvalTimeout > 0 {
		storeOpts = append(storeOpts, approval.WithTimeout(s.approvalTimeout))
	}
	s.approvals = approval.NewStore(storeOpts...)
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
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("proxy: listen: %w", err)
	}
	s.listenAddr = listener.Addr().String()

	srv := s.newHTTPServer(s.listenAddr, s.handler())

	s.mu.Lock()
	s.server = srv
	s.mu.Unlock()

	if err := srv.Serve(listener); err != nil {
		return fmt.Errorf("proxy: listen and serve: %w", err)
	}
	return nil
}

// Serve starts serving HTTP requests on an existing listener.
func (s *Server) Serve(listener net.Listener) error {
	s.listenAddr = listener.Addr().String()
	srv := s.newHTTPServer(s.listenAddr, s.handler())

	s.mu.Lock()
	s.server = srv
	s.mu.Unlock()

	if err := srv.Serve(listener); err != nil {
		return fmt.Errorf("proxy: serve: %w", err)
	}
	return nil
}

// newHTTPServer creates an *http.Server with standard timeouts.
func (s *Server) newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
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
	mux.HandleFunc("POST /v1/approvals", s.handleCreateApproval)
	mux.HandleFunc("GET /v1/approvals", s.handleListApprovals)
	mux.HandleFunc("GET /v1/approvals/{id}", s.handleGetApproval)
	mux.HandleFunc("POST /v1/approvals/{id}/resolve", s.handleResolveApproval)
	mux.HandleFunc("GET /v1/rules/auto-allowed", s.handleGetAutoAllowed)
	mux.HandleFunc("DELETE /v1/rules/auto-allowed/{index}", s.handleDeleteAutoAllowed)
	mux.HandleFunc("GET /v1/audit/events", s.handleAuditEvents)
	mux.HandleFunc("GET /v1/audit/dates", s.handleAuditDates)
	mux.HandleFunc("GET /v1/audit/export", s.handleAuditExport)
	mux.HandleFunc("GET /v1/audit/stats", s.handleAuditStats)
	mux.HandleFunc("GET /v1/policy", s.handlePolicy)
	mux.HandleFunc("POST /v1/test", s.handleTest)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	if s.metricsEnabled {
		mux.Handle("GET /metrics", MetricsHandler())
	}
	mux.Handle("/dashboard", http.RedirectHandler("/dashboard/", http.StatusMovedPermanently))
	mux.Handle("/dashboard/", http.StripPrefix("/dashboard/", dashboard.Handler()))
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

	if s.metricsEnabled {
		policy := ""
		if len(decision.MatchedPolicies) > 0 {
			policy = decision.MatchedPolicies[0]
		}
		RecordDecision(decision.Action.String(), policy, decision.EvalDuration)
		SetPendingApprovals(len(s.approvals.List()))
		SetPolicyCount(s.engine.PolicyCount())
		SetUptime(time.Since(s.startedAt))
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
		// Check if the user has previously "Always Allowed" this pattern.
		// Auto-allow decisions override require_approval from global policies.
		if engine.MatchesAutoAllowFile(engine.DefaultAutoAllowedPath(), call) {
			s.logger.Debug("proxy: auto-allow matched, bypassing approval queue", "tool", toolName)
			decision.Action = engine.ActionAllow
			decision.Message = "auto-allowed by user rule"
			decision.MatchedPolicies = []string{"auto-allowed"}
			resp["decision"] = decision.Action.String()
			resp["message"] = decision.Message
			resp["policy"] = "auto-allowed"
			s.writeAudit(req, toolName, decision)
			writeJSON(w, http.StatusOK, resp)
			return
		}

		pending, err := s.approvals.Create(call, decision)
		if err != nil {
			s.logger.Error("proxy: approval store full", "error", err)
			writeError(w, http.StatusServiceUnavailable, err.Error())
			return
		}

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
		// Default to deny + require_approval so operators get alerted for
		// blocked calls and pending human-approval decisions out of the box.
		return actionStr == "deny" || actionStr == "require_approval"
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
	allowed := decision.Action == engine.ActionAllow || decision.Action == engine.ActionWatch
	s.writeAudit(req, toolName, decision)

	writeJSON(w, http.StatusOK, map[string]any{
		"allowed":          allowed,
		"decision":         decision.Action.String(),
		"message":          decision.Message,
		"matched_policies": decision.MatchedPolicies,
		"eval_duration_us": decision.EvalDuration.Microseconds(),
	})
}

// createApprovalRequest is the JSON body for POST /v1/approvals.
type createApprovalRequest struct {
	Tool    string `json:"tool"`
	Command string `json:"command,omitempty"`
	Agent   string `json:"agent"`
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
	RunID   string `json:"run_id,omitempty"`
}

func (s *Server) handleCreateApproval(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	var req createApprovalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	params := map[string]any{}
	if req.Command != "" {
		params["command"] = req.Command
	}
	if req.Path != "" {
		params["path"] = req.Path
	}

	call := engine.ToolCall{
		ID:        audit.NewEventID(),
		Agent:     req.Agent,
		Session:   "hook",
		RunID:     req.RunID,
		Tool:      req.Tool,
		Params:    params,
		Timestamp: time.Now().UTC(),
	}

	decision := engine.Decision{
		Action:  engine.ActionRequireApproval,
		Message: req.Message,
	}

	pending, err := s.approvals.Create(call, decision)
	if err != nil {
		s.logger.Error("proxy: approval store full", "error", err)
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	s.logger.Info("proxy: external approval created",
		"id", pending.ID,
		"tool", req.Tool,
		"command", req.Command,
		"agent", req.Agent,
		"message", req.Message,
	)

	if s.shouldNotify(decision.Action.String()) {
		go s.sendApprovalWebhook(call, decision, pending)
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         pending.ID,
		"status":     pending.Status.String(),
		"expires_at": pending.ExpiresAt.Format(time.RFC3339),
	})
}

func (s *Server) handleListApprovals(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	pending := s.approvals.List()
	items := make([]map[string]any, 0, len(pending))

	for _, req := range pending {
		item := map[string]any{
			"id":         req.ID,
			"tool":       req.Call.Tool,
			"command":    req.Call.Command(),
			"agent":      req.Call.Agent,
			"session":    req.Call.Session,
			"message":    req.Decision.Message,
			"status":     req.Status.String(),
			"created_at": req.CreatedAt.Format(time.RFC3339),
			"expires_at": req.ExpiresAt.Format(time.RFC3339),
		}
		if req.Call.RunID != "" {
			item["run_id"] = req.Call.RunID
		}
		items = append(items, item)
	}

	writeJSON(w, http.StatusOK, map[string]any{"approvals": items})
}

func (s *Server) handleGetApproval(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	id := r.PathValue("id")
	req, ok := s.approvals.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "approval not found")
		return
	}

	item := map[string]any{
		"id":         req.ID,
		"tool":       req.Call.Tool,
		"command":    req.Call.Command(),
		"agent":      req.Call.Agent,
		"session":    req.Call.Session,
		"message":    req.Decision.Message,
		"status":     req.Status.String(),
		"created_at": req.CreatedAt.Format(time.RFC3339),
		"expires_at": req.ExpiresAt.Format(time.RFC3339),
	}
	if !req.ResolvedAt.IsZero() {
		item["resolved_at"] = req.ResolvedAt.Format(time.RFC3339)
		item["resolved_by"] = req.ResolvedBy
	}

	writeJSON(w, http.StatusOK, item)
}

type resolveRequest struct {
	Approved   bool   `json:"approved"`
	ResolvedBy string `json:"resolved_by"`
	Persist    bool   `json:"persist"`
}

func (s *Server) handleResolveApproval(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// Allow access via either Bearer token or valid HMAC signature.
	if s.signer != nil {
		sig := r.URL.Query().Get("sig")
		expRaw := r.URL.Query().Get("exp")
		if sig != "" && expRaw != "" {
			exp, err := strconv.ParseInt(expRaw, 10, 64)
			if err != nil || !s.signer.ValidateSignature(id, sig, exp) {
				writeError(w, http.StatusUnauthorized, "invalid or expired signature")
				return
			}
			// Signature valid — skip Bearer auth.
			goto authorized
		}
	}
	if !s.checkAuth(w, r) {
		return
	}
authorized:
	var req resolveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid body: %v", err))
		return
	}

	if req.ResolvedBy == "" {
		req.ResolvedBy = "api"
	}

	if err := s.approvals.Resolve(id, req.Approved, req.ResolvedBy); err != nil {
		// Distinguish "already resolved" (replay) from "unknown id".
		if existing, ok := s.approvals.Get(id); ok && existing.Status != approval.StatusPending {
			writeError(w, http.StatusGone, "approval already resolved; URL cannot be reused")
			return
		}
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	resolved, _ := s.approvals.Get(id)
	s.logger.Info("proxy: approval resolved",
		"id", id,
		"approved", req.Approved,
		"resolved_by", req.ResolvedBy,
	)

	// Write audit event for the resolution.
	if s.sink != nil {
		resolution := "denied"
		if req.Approved && req.Persist {
			resolution = "always_allowed"
		} else if req.Approved {
			resolution = "approved"
		}

		auditEvent := audit.Event{
			ID:        audit.NewEventID(),
			Timestamp: time.Now().UTC(),
			Agent:     resolved.Call.Agent,
			Session:   resolved.Call.Session,
			Tool:      resolved.Call.Tool,
			Request: map[string]any{
				"action":      "approval_resolved",
				"tool":        resolved.Call.Tool,
				"command":     resolved.Call.Command(),
				"resolution":  resolution,
				"resolved_by": req.ResolvedBy,
				"approval_id": id,
				"persist":     req.Approved && req.Persist,
			},
			Decision: audit.EventDecision{
				Action:  resolution,
				Message: fmt.Sprintf("approval %s by %s", resolution, req.ResolvedBy),
			},
		}

		if err := s.sink.Write(auditEvent); err != nil {
			s.logger.Error("proxy: audit write for approval resolution failed", "error", err)
		}
	}

	// Persist as auto-allow rule if requested.
	var persisted bool
	if req.Approved && req.Persist {
		policyPath := engine.DefaultAutoAllowedPath()
		if err := engine.AppendAllowRule(policyPath, resolved.Call); err != nil {
			s.logger.Error("proxy: failed to persist allow rule", "error", err)
		} else {
			persisted = true
			s.logger.Info("proxy: allow rule persisted", "path", policyPath, "tool", resolved.Call.Tool)
			// Force immediate reload so the new rule takes effect without waiting for hot-reload.
			if s.engine != nil {
				_ = s.engine.Reload()
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":        id,
		"status":    resolved.Status.String(),
		"approved":  req.Approved,
		"persisted": persisted,
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

// handlePolicy returns a summary of the current active policy configuration.
func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	configPath := s.configPath
	if configPath == "" {
		configPath = "rampart.yaml"
	}

	defaultAction := "allow"
	policyCount := 0
	ruleCount := 0
	if s.engine != nil {
		defaultAction = s.engine.GetDefaultAction()
		policyCount = s.engine.PolicyCount()
		ruleCount = s.engine.RuleCount()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"config_path":    configPath,
		"mode":           s.mode,
		"default_action": defaultAction,
		"policy_count":   policyCount,
		"rule_count":     ruleCount,
	})
}

// handleTest evaluates a command against the loaded policy engine and returns
// the decision. This powers the "Try a command" REPL in the dashboard Policy tab.
func (s *Server) handleTest(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	if s.engine == nil {
		writeError(w, http.StatusServiceUnavailable, "policy engine not initialized")
		return
	}

	var req struct {
		Command string `json:"command"`
		Tool    string `json:"tool"`    // optional, defaults to "exec"
		Agent   string `json:"agent"`   // optional
		Session string `json:"session,omitempty"` // optional; used for session_matches evaluation
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Command == "" {
		writeError(w, http.StatusBadRequest, "command is required")
		return
	}
	if req.Tool == "" {
		req.Tool = "exec"
	}

	params := map[string]any{"command": req.Command}
	if req.Tool == "write" || req.Tool == "read" {
		params = map[string]any{"path": req.Command}
	}
	call := engine.ToolCall{
		ID:        audit.NewEventID(),
		Tool:      req.Tool,
		Agent:     req.Agent,
		Session:   req.Session,
		Params:    params,
		Timestamp: time.Now(),
	}

	decision := s.engine.Evaluate(call)

	writeJSON(w, http.StatusOK, map[string]any{
		"command":          req.Command,
		"tool":             req.Tool,
		"action":           decision.Action.String(),
		"message":          decision.Message,
		"matched_policies": decision.MatchedPolicies,
		"policy_scope":     "global", // project policies are hook-side only
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	uptime := int(time.Since(s.startedAt).Seconds())
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"mode":           s.mode,
		"uptime_seconds": uptime,
		"version":        build.Version,
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
			Action:  engine.ActionDeny,
			Message: "webhook action misconfigured; denying for safety",
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
		ResolveURL: s.approvalResolveURL(pending.ID, pending.ExpiresAt.UTC()),
	}

	notifier := notify.NewNotifier(s.notifyConfig.URL, s.notifyConfig.Platform)
	if err := notifier.Send(event); err != nil {
		s.logger.Error("proxy: approval webhook notification failed", "error", err)
	} else {
		s.logger.Debug("proxy: webhook notification sent", "action", decision.Action.String(), "approval_id", pending.ID)
	}
}

func (s *Server) approvalResolveURL(id string, expiresAt time.Time) string {
	base := s.resolveURLBase()
	if base == "" {
		s.logger.Warn("proxy: cannot generate resolve URL; listen address not configured")
		return ""
	}
	if s.signer != nil {
		return s.signer.SignURL(base, id, expiresAt)
	}
	return fmt.Sprintf("%s/v1/approvals/%s/resolve", base, url.PathEscape(id))
}

func (s *Server) resolveURLBase() string {
	if base := strings.TrimSpace(s.resolveBaseURL); base != "" {
		return strings.TrimRight(base, "/")
	}

	addr := strings.TrimSpace(s.listenAddr)
	if addr == "" {
		return ""
	}

	if strings.Contains(addr, "://") {
		return strings.TrimRight(addr, "/")
	}

	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		if strings.HasPrefix(addr, ":") {
			port = strings.TrimPrefix(addr, ":")
		}
	}
	if strings.TrimSpace(port) == "" {
		return ""
	}
	return "http://localhost:" + port
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
		return "" // all comments/blank lines — return empty
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
