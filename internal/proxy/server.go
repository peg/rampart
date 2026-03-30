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
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/peg/rampart/internal/approval"
	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/dashboard"
	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/internal/signing"
	"github.com/peg/rampart/internal/token"
)

const defaultMode = "enforce"
const redactedResponse = "[REDACTED: sensitive content removed by Rampart]"
const statusCallCountWindow = time.Hour

// Server is Rampart's HTTP proxy runtime for policy-aware tool calls.
type Server struct {
	engine              *engine.Engine
	sink                audit.AuditSink
	approvals           *approval.Store
	approvalTimeout     time.Duration
	token               string
	tokenStore          *token.Store
	mode                string
	configPath          string
	logger              *slog.Logger
	resolveBaseURL      string
	listenAddr          string
	signer              *signing.Signer
	mu                  sync.Mutex
	policyWriteMu       sync.Mutex
	server              *http.Server
	startedAt           time.Time
	notifyConfig        *engine.NotifyConfig
	metricsEnabled      bool
	auditDir            string
	sse                 *sseHub
	lastReloadAPI       time.Time // Rate limiting for /v1/policy/reload
	stopCleanup         chan struct{}
	approvalPersistFile string
}

// Option configures a proxy server.
type Option func(*Server)

// WithToken sets the bearer auth token used by the proxy.
func WithToken(token string) Option {
	return func(s *Server) {
		s.token = token
	}
}

// WithTokenStore sets the per-agent token store for scoped authentication.
func WithTokenStore(store *token.Store) Option {
	return func(s *Server) {
		s.tokenStore = store
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

// WithApprovalPersistenceFile sets the path for the JSONL file used to persist
// pending approvals across server restarts. If empty, persistence is disabled.
func WithApprovalPersistenceFile(path string) Option {
	return func(s *Server) {
		s.approvalPersistFile = path
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
		engine:      eng,
		sink:        sink,
		approvals:   nil, // initialized after options
		mode:        defaultMode,
		logger:      slog.Default(),
		startedAt:   time.Now().UTC(),
		sse:         newSSEHub(),
		stopCleanup: make(chan struct{}),
	}

	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}

	if s.mode == "" {
		s.mode = defaultMode
	}

	// Initialize approval store with timeout and optional persistence.
	var storeOpts []approval.Option
	if s.approvalTimeout > 0 {
		storeOpts = append(storeOpts, approval.WithTimeout(s.approvalTimeout))
	}
	if s.approvalPersistFile != "" {
		storeOpts = append(storeOpts, approval.WithPersistenceFile(s.approvalPersistFile))
	}
	storeOpts = append(storeOpts, approval.WithLogger(s.logger))
	storeOpts = append(storeOpts, approval.WithExpireCallback(func(req *approval.Request) {
		s.broadcastSSE(map[string]any{"type": "approvals"})
		// Write audit event so expired approvals appear in History as denied.
		if s.sink != nil {
			ev := audit.Event{
				ID:        audit.NewEventID(),
				Timestamp: time.Now().UTC(),
				Agent:     req.Call.Agent,
				Session:   req.Call.Session,
				Tool:      req.Call.Tool,
				Request: map[string]any{
					"action":  "approval_expired",
					"tool":    req.Call.Tool,
					"command": req.Call.Command(),
				},
				Decision: audit.EventDecision{
					Action:  "deny",
					Message: "approval timed out — command blocked",
				},
			}
			if err := s.sink.Write(ev); err != nil {
				s.logger.Error("proxy: audit write for approval expiry failed", "error", err)
			}
			s.broadcastSSE(map[string]any{"type": "audit", "event": ev})
		}
	}))
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
// startExpiredRuleCleanup runs a background goroutine that periodically removes
// expired temporal rules (--for) from policy files. Runs every 60 seconds.
func (s *Server) startExpiredRuleCleanup() {
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				removed, err := s.engine.CleanExpired()
				if err != nil {
					s.logger.Error("proxy: expired rule cleanup failed", "error", err)
				} else if removed > 0 {
					s.logger.Info("proxy: expired rules cleaned", "removed", removed)
				}
			case <-s.stopCleanup:
				return
			}
		}
	}()
}

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

// ListenAndServeTLS starts serving HTTPS requests at addr with the given TLS config.
func (s *Server) ListenAndServeTLS(addr string, tlsCfg *tls.Config) error {
	listener, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("proxy: tls listen: %w", err)
	}
	s.listenAddr = listener.Addr().String()

	srv := s.newHTTPServer(s.listenAddr, s.handler())

	s.mu.Lock()
	s.server = srv
	s.mu.Unlock()

	if err := srv.Serve(listener); err != nil {
		return fmt.Errorf("proxy: tls serve: %w", err)
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

	s.startExpiredRuleCleanup()

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

// Shutdown gracefully stops the proxy server and releases all resources.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	srv := s.server
	s.mu.Unlock()

	if srv == nil {
		return nil
	}

	// Stop the expired rule cleanup goroutine.
	select {
	case <-s.stopCleanup:
		// Already closed.
	default:
		close(s.stopCleanup)
	}

	// Close SSE connections first so they don't block server shutdown.
	// Without this, long-lived SSE clients keep the server alive past the deadline.
	s.sse.Close()

	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("proxy: shutdown: %w", err)
	}
	// Stop the approval store's background cleanup goroutine and
	// unblock any watchExpiry goroutines waiting on pending approvals.
	s.approvals.Close()
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
	mux.HandleFunc("POST /v1/approvals/bulk-resolve", s.handleBulkResolve)
	mux.HandleFunc("GET /v1/rules/auto-allowed", s.handleGetAutoAllowed)
	mux.HandleFunc("DELETE /v1/rules/auto-allowed/{name}", s.handleDeleteAutoAllowed)
	mux.HandleFunc("POST /v1/rules/learn", s.handleLearnRule)
	mux.HandleFunc("GET /v1/audit/events", s.handleAuditEvents)
	mux.HandleFunc("GET /v1/audit/dates", s.handleAuditDates)
	mux.HandleFunc("GET /v1/audit/export", s.handleAuditExport)
	mux.HandleFunc("GET /v1/audit/stats", s.handleAuditStats)
	mux.HandleFunc("GET /v1/events/stream", s.handleEventStream)
	mux.HandleFunc("GET /v1/policy/summary", s.handlePolicySummary)
	mux.HandleFunc("GET /v1/policies", s.handlePoliciesSnapshot)
	mux.HandleFunc("POST /v1/policy/reload", s.handlePolicyReload)
	mux.HandleFunc("GET /v1/status", s.handleStatus)
	mux.HandleFunc("POST /v1/test", s.handleTest)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	if s.metricsEnabled {
		metricsHandler := MetricsHandler()
		mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
			if !s.checkAuth(w, r) {
				return
			}
			metricsHandler.ServeHTTP(w, r)
		})
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
	RunID   string         `json:"run_id,omitempty"`
	Params  map[string]any `json:"params"`
	Input   map[string]any `json:"input,omitempty"`

	// Convenience fields: callers can pass "command" or "path" at the top level
	// instead of nesting inside "params". These are promoted into Params by
	// promoteTopLevelParams if Params doesn't already contain them.
	Command string `json:"command,omitempty"`
	Path    string `json:"path,omitempty"`

	// Response is the tool's output for response-side policy evaluation.
	// The caller executes the tool and submits the output here for scanning
	// before returning it to the agent. If empty, response-side evaluation
	// is skipped.
	Response string `json:"response,omitempty"`
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

type resolveRequest struct {
	Approved   bool   `json:"approved"`
	ResolvedBy string `json:"resolved_by"`
	Persist    bool   `json:"persist"`
}

// bulkResolveRequest is the JSON body for POST /v1/approvals/bulk-resolve.
type bulkResolveRequest struct {
	RunID      string `json:"run_id"`
	Action     string `json:"action"`      // "approve" or "deny"
	ResolvedBy string `json:"resolved_by"` // e.g. "api", "cli"
}

func (s *Server) checkAuthOrTokenParam(r *http.Request) bool {
	id, _ := s.identify(r)
	return id != nil
}

// checkAuth validates the bearer token (admin or agent). Returns false if auth fails.
// Used for read-only endpoints accessible to both admin and agent tokens.
// For mutation endpoints, use checkAdminAuth instead.
func (s *Server) checkAuth(w http.ResponseWriter, r *http.Request) bool {
	id, errMsg := s.identify(r)
	if id == nil {
		writeError(w, http.StatusUnauthorized, errMsg)
		return false
	}
	return true
}

// Approvals returns the approval store for external access (CLI, daemon).
func (s *Server) Approvals() *approval.Store {
	return s.approvals
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
