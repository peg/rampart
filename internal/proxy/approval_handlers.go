// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package proxy

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/peg/rampart/internal/approval"
	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/engine"
)

func (s *Server) handleCreateApproval(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(w, r) {
		return
	}

	var req createApprovalRequest
	if err := decodeJSONBody(r.Body, &req); err != nil {
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

	// Check run-scoped authorization and enqueue atomically. A bulk cache
	// publication can never slip between a stale check and Create, leaving an
	// orphan pending request for a call that should have been auto-approved.
	pending, autoApproved, err := s.approvals.CreateOrAutoApproved(call, decision, "")
	if err != nil {
		s.logger.Error("proxy: approval store full", "error", err)
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if autoApproved {
		s.logger.Debug("proxy: run auto-approved (hook), bypassing approval queue", "tool", req.Tool, "run_id", call.RunID)
		ttl := s.approvalTimeout
		if ttl <= 0 {
			ttl = time.Hour
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"id":         audit.NewEventID(),
			"status":     "approved",
			"message":    "auto-approved by bulk-resolve",
			"expires_at": time.Now().Add(ttl).Format(time.RFC3339),
		})
		return
	}
	s.broadcastSSE(map[string]any{"type": "approvals"})

	s.logger.Info("proxy: external approval created",
		"id", pending.ID,
		"tool", req.Tool,
		"command", req.Command,
		"agent", req.Agent,
		"message", req.Message,
	)

	if s.shouldNotify(decision.Action.String()) {
		s.enqueueNotification("approval", func() { s.sendApprovalWebhook(call, decision, pending) })
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         pending.ID,
		"status":     pending.Status.String(),
		"expires_at": pending.ExpiresAt.Format(time.RFC3339),
	})
}

func (s *Server) handleListApprovals(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(w, r) {
		return
	}

	pending := s.approvals.List()
	items := make([]map[string]any, 0, len(pending))

	// A run ID is caller-selected and not globally unique. Group approvals by
	// the complete identity used by bulk authorization.
	type runScope struct {
		agent   string
		session string
		runID   string
	}
	type runGroupEntry struct {
		minCreatedAt time.Time
		items        []map[string]any
	}
	runGroupMap := make(map[runScope]*runGroupEntry)

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
			scope := runScope{
				agent:   strings.TrimSpace(req.Call.Agent),
				session: strings.TrimSpace(req.Call.Session),
				runID:   strings.TrimSpace(req.Call.RunID),
			}
			// Incomplete identity cannot safely support a bulk authorization
			// operation, so leave that approval in the flat/solo view.
			if scope.agent == "" || scope.session == "" || scope.runID == "" {
				items = append(items, item)
				continue
			}
			g, exists := runGroupMap[scope]
			if !exists {
				g = &runGroupEntry{minCreatedAt: req.CreatedAt}
				runGroupMap[scope] = g
			} else if req.CreatedAt.Before(g.minCreatedAt) {
				g.minCreatedAt = req.CreatedAt
			}
			g.items = append(g.items, item)
		}
		items = append(items, item)
	}

	// Build run_groups: only groups with 2+ items, sorted by MIN(created_at).
	type runGroup struct {
		scope        runScope
		minCreatedAt time.Time
		items        []map[string]any
	}
	var groups []runGroup
	for scope, g := range runGroupMap {
		if len(g.items) >= 2 {
			groups = append(groups, runGroup{
				scope:        scope,
				minCreatedAt: g.minCreatedAt,
				items:        g.items,
			})
		}
	}
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].minCreatedAt.Before(groups[j].minCreatedAt)
	})

	// Serialize run_groups for JSON output.
	runGroupsJSON := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		runGroupsJSON = append(runGroupsJSON, map[string]any{
			"agent":               g.scope.agent,
			"session":             g.scope.session,
			"run_id":              g.scope.runID,
			"count":               len(g.items),
			"earliest_created_at": g.minCreatedAt.Format(time.RFC3339),
			"items":               g.items,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"approvals":  items,
		"run_groups": runGroupsJSON,
	})
}

func (s *Server) handleGetApproval(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(w, r) {
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
		// persisted indicates this was an allow-always decision that wrote a persistent rule.
		item["persisted"] = req.Persisted
	}

	writeJSON(w, http.StatusOK, item)
}

// approvalResolutionEvent describes the operator decision itself. For an
// allow-always request this event deliberately records an approved one-shot
// resolution plus persist_requested=true; it does not claim the durable rule
// exists before that separate transaction succeeds.
func approvalResolutionEvent(resolved *approval.Request, approved, persistRequested bool, resolvedBy string) audit.Event {
	resolution := "denied"
	if approved {
		resolution = "approved"
	}
	return audit.Event{
		// Reusing the approval ULID makes a retry after an ambiguous sink error
		// identifiable without creating a second logical resolution identity.
		ID:         resolved.ID,
		Timestamp:  time.Now().UTC(),
		Agent:      resolved.Call.Agent,
		Session:    resolved.Call.Session,
		RunID:      resolved.Call.RunID,
		ToolCallID: resolved.Call.ToolCallID,
		Tool:       resolved.Call.Tool,
		Request: map[string]any{
			"action":            "approval_resolved",
			"tool":              resolved.Call.Tool,
			"command":           resolved.Call.Command(),
			"resolution":        resolution,
			"resolved_by":       resolvedBy,
			"approval_id":       resolved.ID,
			"persist_requested": approved && persistRequested,
			"persist":           false,
		},
		Decision: audit.EventDecision{
			Action:  resolution,
			Message: fmt.Sprintf("approval %s by %s", resolution, resolvedBy),
		},
	}
}

// approvalPersistenceAuthorizationEvent records that the operator-authorized
// durable policy write is about to be attempted. It is persisted before the
// policy file is changed, so the durable authorization is never installed
// without a preceding audit record. It intentionally does not claim success.
func approvalPersistenceAuthorizationEvent(resolved *approval.Request, resolvedBy, policyPath string) audit.Event {
	return audit.Event{
		ID:         audit.NewEventID(),
		Timestamp:  time.Now().UTC(),
		Agent:      resolved.Call.Agent,
		Session:    resolved.Call.Session,
		RunID:      resolved.Call.RunID,
		ToolCallID: resolved.Call.ToolCallID,
		Tool:       resolved.Call.Tool,
		Request: map[string]any{
			"action":      "approval_persistence_authorized",
			"tool":        resolved.Call.Tool,
			"command":     resolved.Call.Command(),
			"resolved_by": resolvedBy,
			"approval_id": resolved.ID,
			"policy_path": policyPath,
			"persist":     false,
		},
		Decision: audit.EventDecision{
			Action:  "authorized",
			Message: fmt.Sprintf("durable allow persistence authorized by %s", resolvedBy),
		},
	}
}

func (s *Server) handleResolveApproval(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// Allow access via either HMAC signature (dashboard) or admin bearer token.
	// HMAC signatures bypass scope checks — they are generated by the server
	// for dashboard approval links and are inherently scoped.
	hmacAuthed := false
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
			hmacAuthed = true
			goto authorized
		}
	}
	// Bearer auth requires admin scope — agent tokens cannot self-approve.
	if !s.checkAdminAuth(w, r) {
		return
	}
authorized:
	var req resolveRequest
	if err := decodeJSONBody(r.Body, &req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid body: %v", err))
		return
	}

	if req.ResolvedBy == "" {
		req.ResolvedBy = "api"
	}
	if hmacAuthed {
		// A signed link authenticates the server-issued capability, not the
		// identity claimed in its caller-controlled JSON body. Record an honest,
		// server-owned principal so audit consumers cannot be misled.
		req.ResolvedBy = "signed-link"
	}

	// HMAC-signed URLs are scoped to a single approval action — they must not
	// be able to make permanent policy changes. Check before resolving so the
	// approval is never committed with Persist=true via a signed URL.
	if hmacAuthed && req.Persist {
		writeError(w, http.StatusForbidden, "persist=true requires admin token authentication, not a signed approval URL")
		return
	}
	if req.Approved && req.Persist {
		pending, ok := s.approvals.Get(id)
		if !ok {
			writeError(w, http.StatusNotFound, "approval not found")
			return
		}
		if _, persistErr := engine.GenerateAllowRule(pending.Call); persistErr != nil {
			writeError(w, http.StatusBadRequest, persistErr.Error())
			return
		}
	}

	// The store records Persisted only after the separate durable policy
	// transaction succeeds below. The resolution audit is a required
	// pre-publication step: a failed write leaves the request pending, does not
	// wake its waiter, and does not expose an exact-replay grant.
	var resolutionAudit *audit.Event
	err := s.approvals.ResolveBeforePublish(id, req.Approved, req.ResolvedBy, func(candidate *approval.Request) error {
		if s.sink == nil {
			return nil
		}
		event := approvalResolutionEvent(candidate, req.Approved, req.Persist, req.ResolvedBy)
		if writeErr := s.sink.Write(event); writeErr != nil {
			return fmt.Errorf("write approval resolution audit: %w", writeErr)
		}
		resolutionAudit = &event
		return nil
	})
	if err != nil {
		// Distinguish "already resolved" (replay) from "unknown id".
		if existing, ok := s.approvals.Get(id); ok && existing.Status != approval.StatusPending {
			writeError(w, http.StatusGone, "approval already resolved; URL cannot be reused")
			return
		} else if ok {
			// The request is still pending, so resolution failed before any
			// authorization was committed (for example, durable replay state
			// was unavailable). Keep it retryable and fail closed.
			writeError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	resolved, _ := s.approvals.Get(id)
	s.broadcastSSE(map[string]any{"type": "approvals"})
	if resolutionAudit != nil {
		s.broadcastAuditEvent(*resolutionAudit)
	}
	s.logger.Info("proxy: approval resolved",
		"id", id,
		"approved", req.Approved,
		"resolved_by", req.ResolvedBy,
	)

	var persisted bool
	if req.Approved && req.Persist {
		policyPath := engine.DefaultAutoAllowedPath()
		persistenceAuditOK := true
		if s.sink != nil {
			event := approvalPersistenceAuthorizationEvent(resolved, req.ResolvedBy, policyPath)
			if writeErr := s.sink.Write(event); writeErr != nil {
				persistenceAuditOK = false
				s.logger.Error("proxy: audit write for durable approval authorization failed; policy not installed", "error", writeErr)
			} else {
				s.broadcastAuditEvent(event)
			}
		}
		if !persistenceAuditOK {
			s.logger.Warn("proxy: skipped durable allow rule because its required audit record was unavailable", "approval_id", id)
		} else if err := engine.AppendAllowRule(policyPath, resolved.Call); err != nil {
			s.logger.Error("proxy: failed to persist allow rule", "error", err)
		} else {
			persisted = true
			if markErr := s.approvals.MarkPersisted(id); markErr != nil {
				s.logger.Error("proxy: failed to record persisted approval state", "id", id, "error", markErr)
			}
			s.logger.Info("proxy: allow rule persisted", "path", policyPath, "tool", resolved.Call.Tool)
			// Force immediate reload so the new rule takes effect without waiting for hot-reload.
			if s.engine != nil {
				if reloadErr := s.engine.Reload(); reloadErr != nil {
					s.logger.Error("proxy: post-change reload failed", "error", reloadErr)
				}
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

// handleBulkResolve resolves all pending approvals for an exact
// agent/session/run scope. Incomplete scopes are rejected to prevent
// inadvertent cross-agent authorization.
func (s *Server) handleBulkResolve(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(w, r) {
		return
	}

	var req bulkResolveRequest
	if err := decodeJSONBody(r.Body, &req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	req.Agent = strings.TrimSpace(req.Agent)
	req.Session = strings.TrimSpace(req.Session)
	req.RunID = strings.TrimSpace(req.RunID)
	if req.Agent == "" || req.Session == "" || req.RunID == "" {
		writeError(w, http.StatusBadRequest, "agent, session, and run_id are required; refusing incomplete bulk-approval scope")
		return
	}

	// Validate action explicitly — default-to-approve on typos/empty is a security gap.
	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action != "approve" && action != "deny" {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("action must be \"approve\" or \"deny\", got %q", req.Action))
		return
	}
	approved := action == "approve"

	resolvedBy := req.ResolvedBy
	if resolvedBy == "" {
		resolvedBy = "api"
	}

	// Collect all pending approvals that belong to this run.
	pending := s.approvals.List()
	matching := make([]*approval.Request, 0)
	for _, ap := range pending {
		if strings.TrimSpace(ap.Call.Agent) == req.Agent &&
			strings.TrimSpace(ap.Call.Session) == req.Session &&
			strings.TrimSpace(ap.Call.RunID) == req.RunID {
			matching = append(matching, ap)
		}
	}

	var resolved int
	var ids []string
	var resolveErr error
	autoApproveTTL := s.approvalTimeout
	if autoApproveTTL <= 0 {
		autoApproveTTL = time.Hour
	}

	resolveBatch := func(batch []*approval.Request) {
		for _, ap := range batch {
			err := s.approvals.ResolveBeforePublish(ap.ID, approved, resolvedBy, func(candidate *approval.Request) error {
				if s.sink == nil {
					return nil
				}
				event := approvalResolutionEvent(candidate, approved, false, resolvedBy)
				event.Request["bulk"] = true
				event.Request["auto_approve"] = approved
				if approved {
					event.Request["auto_approve_ttl_seconds"] = int64(autoApproveTTL / time.Second)
				}
				event.Decision.Message = fmt.Sprintf("bulk %s by %s", event.Decision.Action, resolvedBy)
				if writeErr := s.sink.Write(event); writeErr != nil {
					return fmt.Errorf("write bulk approval resolution audit: %w", writeErr)
				}
				return nil
			})
			if err != nil {
				resolveErr = err
				s.logger.Warn("proxy: bulk-resolve stopped before publishing approval", "id", ap.ID, "error", err)
				return
			}
			resolved++
			ids = append(ids, ap.ID)
			// Individual audit SSE events intentionally remain batched below.
		}
	}
	resolveBatch(matching)

	// The run-scoped cache is authorization state in its own right. Install it
	// only after every approval selected by this bulk request has a durable
	// journal transition and required audit record. Installation and approval
	// creation use the same Store lock. If creation wins their race, this loop
	// receives and resolves that new request before trying publication again;
	// if publication wins, the creator observes auto-approved state atomically.
	if approved && resolveErr == nil && len(matching) > 0 {
		scopeCall := engine.ToolCall{Agent: req.Agent, Session: req.Session, RunID: req.RunID}
		owners := make([]*approval.Request, 0, len(matching))
		seenOwners := make(map[string]struct{}, len(matching))
		for _, ap := range matching {
			if _, seen := seenOwners[ap.OwnerScopeID()]; !seen {
				seenOwners[ap.OwnerScopeID()] = struct{}{}
				owners = append(owners, ap)
			}
		}
		for _, owner := range owners {
			for resolveErr == nil {
				select {
				case <-r.Context().Done():
					resolveErr = fmt.Errorf("bulk approval request cancelled before cache publication: %w", r.Context().Err())
					continue
				default:
				}
				raced, installed := s.approvals.AutoApproveRunIfNoPendingForRequest(scopeCall, owner, autoApproveTTL)
				if installed {
					break
				}
				if len(raced) == 0 {
					resolveErr = fmt.Errorf("bulk approval scope could not be installed")
					break
				}
				resolveBatch(raced)
			}
		}
		if resolveErr != nil {
			s.logger.Error("proxy: bulk-resolve could not install auto-approval scope",
				"agent", req.Agent, "session", req.Session, "run_id", req.RunID, "error", resolveErr)
		}
	}

	if resolved > 0 {
		// Broadcast a single audit_batch event instead of N individual audit
		// events to avoid flooding the SSE channel on large bulk-resolves.
		s.broadcastSSE(map[string]any{"type": "approvals"})
		s.broadcastSSE(map[string]any{
			"type": "audit_batch", "agent": req.Agent, "session": req.Session, "run_id": req.RunID,
		})
	}

	s.logger.Info("proxy: bulk-resolve completed",
		"agent", req.Agent,
		"session", req.Session,
		"run_id", req.RunID,
		"action", req.Action,
		"resolved", resolved,
		"resolved_by", resolvedBy,
	)
	if resolveErr != nil {
		writeError(w, http.StatusServiceUnavailable, "bulk resolution stopped before unaudited authorization could be published")
		return
	}

	if ids == nil {
		ids = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"resolved": resolved,
		"ids":      ids,
	})
}

func (s *Server) handleResolveHostedApproval(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(w, r) {
		return
	}

	auditID := strings.TrimSpace(r.PathValue("auditID"))
	if auditID == "" {
		writeError(w, http.StatusBadRequest, "audit_id is required")
		return
	}

	var req hostedApprovalResolveRequest
	if err := decodeJSONBody(r.Body, &req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	outcome := strings.ToLower(strings.TrimSpace(req.Outcome))
	switch outcome {
	case "approved", "denied", "timeout", "cancelled":
		// valid
	default:
		writeError(w, http.StatusBadRequest, "outcome must be one of: approved, denied, timeout, cancelled")
		return
	}

	scope := strings.ToLower(strings.TrimSpace(req.Scope))
	if scope != "" {
		switch scope {
		case "once", "session", "always":
			// valid
		default:
			writeError(w, http.StatusBadRequest, "scope must be one of: once, session, always")
			return
		}
	}

	resolvedBy := strings.TrimSpace(req.ResolvedBy)
	if resolvedBy == "" {
		resolvedBy = "api"
	}

	resolvedAt := time.Now().UTC()
	if strings.TrimSpace(req.ResolvedAt) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(req.ResolvedAt))
		if err != nil {
			writeError(w, http.StatusBadRequest, "resolved_at must be RFC3339")
			return
		}
		resolvedAt = parsed.UTC()
	}

	if s.sink == nil {
		writeError(w, http.StatusServiceUnavailable, "audit sink is not initialized")
		return
	}

	tool := strings.TrimSpace(req.Tool)
	if tool == "" {
		tool = "hosted_approval"
	}

	request := map[string]any{
		"action":      "hosted_approval_resolved",
		"audit_id":    auditID,
		"outcome":     outcome,
		"resolved_by": resolvedBy,
		"resolved_at": resolvedAt.Format(time.RFC3339),
	}
	if req.ToolCallID != "" {
		request["tool_call_id"] = req.ToolCallID
	}
	if req.HostApprovalID != "" {
		request["host_approval_id"] = req.HostApprovalID
	}
	if scope != "" {
		request["scope"] = scope
	}
	if req.Message != "" {
		request["message"] = req.Message
	}
	if owner := req.ApprovalOwner.toMap(); len(owner) > 0 {
		request["approval_owner"] = owner
	}

	message := req.Message
	if message == "" {
		message = fmt.Sprintf("hosted approval %s by %s", outcome, resolvedBy)
	}

	eventID := audit.NewEventID()
	event := audit.Event{
		ID:            eventID,
		Timestamp:     resolvedAt,
		Agent:         req.Agent,
		Session:       req.Session,
		RunID:         req.RunID,
		ToolCallID:    req.ToolCallID,
		ApprovalOwner: req.ApprovalOwner.toMap(),
		Tool:          tool,
		Request:       request,
		Decision: audit.EventDecision{
			Action:  outcome,
			Message: message,
		},
	}
	if err := s.sink.Write(event); err != nil {
		s.logger.Error("proxy: audit write for hosted approval resolution failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "failed to write hosted approval audit event")
		return
	}
	s.broadcastAuditEvent(event)

	writeJSON(w, http.StatusOK, map[string]any{
		"audit_id":    auditID,
		"event_id":    eventID,
		"status":      "recorded",
		"outcome":     outcome,
		"resolved_at": resolvedAt.Format(time.RFC3339),
	})
}

func (s *Server) approvalResolveURL(id string, expiresAt time.Time) string {
	base := s.resolveURLBase()
	if base == "" {
		s.logger.Warn("proxy: cannot generate resolve URL; listen address not configured")
		return ""
	}
	if s.signer == nil {
		s.logger.Error("proxy: signed approval links are unavailable; suppressing bearerless resolve URL")
		return ""
	}
	return s.signer.SignURL(base, id, expiresAt)
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
	scheme := "http"
	if s.tlsEnabled {
		scheme = "https"
	}
	return scheme + "://localhost:" + port
}
