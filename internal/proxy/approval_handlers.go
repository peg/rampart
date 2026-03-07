// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package proxy

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
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

	// Short-circuit if this run has been bulk-approved.
	if call.RunID != "" && s.approvals.IsAutoApproved(call.RunID) {
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

	pending, err := s.approvals.Create(call, decision)
	if err != nil {
		s.logger.Error("proxy: approval store full", "error", err)
		writeError(w, http.StatusServiceUnavailable, err.Error())
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

	// Track per-run-id grouping data for the run_groups response field.
	type runGroupEntry struct {
		minCreatedAt time.Time
		items        []map[string]any
	}
	runGroupMap := make(map[string]*runGroupEntry)

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
			// Accumulate into run group tracking.
			g, exists := runGroupMap[req.Call.RunID]
			if !exists {
				g = &runGroupEntry{minCreatedAt: req.CreatedAt}
				runGroupMap[req.Call.RunID] = g
			} else if req.CreatedAt.Before(g.minCreatedAt) {
				g.minCreatedAt = req.CreatedAt
			}
			g.items = append(g.items, item)
		}
		items = append(items, item)
	}

	// Build run_groups: only groups with 2+ items, sorted by MIN(created_at).
	type runGroup struct {
		runID        string
		minCreatedAt time.Time
		items        []map[string]any
	}
	var groups []runGroup
	for runID, g := range runGroupMap {
		if len(g.items) >= 2 {
			groups = append(groups, runGroup{
				runID:        runID,
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
			"run_id":              g.runID,
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

func (s *Server) handleResolveApproval(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// Allow access via either HMAC signature (dashboard) or admin bearer token.
	// HMAC signatures bypass scope checks — they are generated by the server
	// for dashboard approval links and are inherently scoped.
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
	// Bearer auth requires admin scope — agent tokens cannot self-approve.
	if !s.checkAdminAuth(w, r) {
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
	s.broadcastSSE(map[string]any{"type": "approvals"})
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
		s.broadcastSSE(map[string]any{"type": "audit", "event": auditEvent})
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

// handleBulkResolve resolves all pending approvals for a given run_id.
// Returns 400 if run_id is empty to prevent inadvertent mass-approval.
func (s *Server) handleBulkResolve(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(w, r) {
		return
	}

	var req bulkResolveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	if strings.TrimSpace(req.RunID) == "" {
		writeError(w, http.StatusBadRequest, "run_id is required; refusing to bulk-resolve without a run_id")
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

	// Set auto-approve BEFORE resolving so any new approvals created from
	// the same run during the loop window are also auto-approved (fixes TOCTOU).
	if approved {
		ttl := s.approvalTimeout
		if ttl <= 0 {
			ttl = time.Hour
		}
		s.approvals.AutoApproveRun(req.RunID, ttl)
	}

	// Collect all pending approvals that belong to this run.
	pending := s.approvals.List()
	var resolved int
	var ids []string

	for _, ap := range pending {
		if ap.Call.RunID != req.RunID {
			continue
		}
		if err := s.approvals.Resolve(ap.ID, approved, resolvedBy); err != nil {
			s.logger.Warn("proxy: bulk-resolve skipped approval", "id", ap.ID, "error", err)
			continue
		}
		resolved++
		ids = append(ids, ap.ID)
		// Write audit event for each resolved approval.
		if s.sink != nil {
			resolution := "denied"
			if approved {
				resolution = "approved"
			}
			ev := audit.Event{
				ID:        audit.NewEventID(),
				Timestamp: time.Now().UTC(),
				Agent:     ap.Call.Agent,
				Session:   ap.Call.Session,
				Tool:      ap.Call.Tool,
				Request: map[string]any{
					"action":      "approval_resolved",
					"tool":        ap.Call.Tool,
					"command":     ap.Call.Command(),
					"resolution":  resolution,
					"resolved_by": resolvedBy,
					"approval_id": ap.ID,
				},
				Decision: audit.EventDecision{
					Action:  resolution,
					Message: fmt.Sprintf("bulk %s by %s", resolution, resolvedBy),
				},
			}
			if err := s.sink.Write(ev); err != nil {
				s.logger.Error("proxy: audit write for bulk-resolve failed", "error", err)
			}
			// Individual audit SSE events intentionally omitted here —
			// a single audit_batch broadcast fires after the loop instead.
		}
	}

	if resolved > 0 {
		// Broadcast a single audit_batch event instead of N individual audit
		// events to avoid flooding the SSE channel on large bulk-resolves.
		s.broadcastSSE(map[string]any{"type": "approvals"})
		s.broadcastSSE(map[string]any{"type": "audit_batch", "run_id": req.RunID})
	}

	s.logger.Info("proxy: bulk-resolve completed",
		"run_id", req.RunID,
		"action", req.Action,
		"resolved", resolved,
		"resolved_by", resolvedBy,
	)

	if ids == nil {
		ids = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"resolved": resolved,
		"ids":      ids,
	})
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
