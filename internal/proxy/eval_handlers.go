// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package proxy

import (
	"fmt"
	"net/http"
	"time"

	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/build"
	"github.com/peg/rampart/internal/engine"
)

func (s *Server) handleToolCall(w http.ResponseWriter, r *http.Request) {
	identity := s.checkAuthIdentity(w, r)
	if identity == nil {
		return
	}

	var req toolRequest
	if err := decodeJSONBody(r.Body, &req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}
	if req.Params == nil {
		req.Params = map[string]any{}
	}
	promoteTopLevelParams(&req)

	toolName := r.PathValue("toolName")
	decision := engine.Decision{}

	// Enrich params with derived fields for policy matching.
	// Also enrich the input map so MCP-style {"input":{"url":"..."}} requests
	// have domain/scheme/path available for domain_matches policies.
	enrichParams(toolName, req.Params)
	if len(req.Input) > 0 {
		enrichParams(toolName, req.Input)
		// Promote enriched fields from input into params so the engine sees them.
		for _, field := range []string{"url", "domain", "scheme", "path", "command"} {
			if v, ok := req.Input[field]; ok {
				if _, exists := req.Params[field]; !exists {
					req.Params[field] = v
				}
			}
		}
	}

	// Per-agent tokens override the agent identity from the request.
	// This prevents an agent from impersonating another agent.
	// Also update req.Agent so audit events reflect the true identity.
	if !identity.IsAdmin && identity.Agent != "" {
		req.Agent = identity.Agent
	}
	if req.Verification {
		writeError(w, http.StatusBadRequest, "verification mode is only available on the preflight endpoint")
		return
	}

	call := engine.ToolCall{
		ID:         audit.NewEventID(),
		Agent:      req.Agent,
		Session:    req.Session,
		RunID:      req.RunID,
		ToolCallID: req.ToolCallID,
		Tool:       toolName,
		Params:     req.Params,
		Input:      extractToolInput(toolName, req.Params, req.Input),
		Timestamp:  time.Now().UTC(),
	}

	if s.mode == "disabled" {
		decision = engine.Decision{
			Action:       engine.ActionAllow,
			Message:      "policy evaluation disabled",
			EvalDuration: 0,
		}
	} else if s.engine == nil {
		decision = engine.Decision{
			Action:  engine.ActionDeny,
			Message: "policy engine unavailable; refusing tool call",
		}
	} else {
		// Per-agent tokens always default to deny for unmatched calls.
		// If a policy filter is set, only that profile's policies are evaluated.
		evalOpts := engine.EvalOptions{}
		if !identity.IsAdmin {
			evalOpts.DefaultDeny = true
			if identity.Policy != "" {
				evalOpts.PolicyFilter = identity.Policy
			}
		}
		decision = s.engine.Enforce(call, evalOpts)
		// Warn when policy filter matched no policies — helps debug silent denies.
		if evalOpts.PolicyFilter != "" && decision.Message == "no matching policy; using default action" {
			s.logger.Warn("proxy: per-agent token policy filter matched no policies — all calls denied",
				"agent", call.Agent, "policy_filter", evalOpts.PolicyFilter, "tool", call.Tool)
		}
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

	auditID, auditErr := s.writeAudit(req, toolName, decision)
	if auditErr != nil && s.mode == "enforce" {
		writeError(w, http.StatusServiceUnavailable, "audit storage is unavailable; refusing tool call")
		return
	}

	allowed := decision.Action == engine.ActionAllow || decision.Action == engine.ActionWatch
	resp := map[string]any{
		"allowed":          allowed,
		"decision":         decision.Action.String(),
		"message":          decision.Message,
		"eval_duration_us": decision.EvalDuration.Microseconds(),
	}
	if auditID != "" {
		resp["audit_id"] = auditID
	}

	if len(decision.MatchedPolicies) > 0 {
		resp["policy"] = decision.MatchedPolicies[0]
	}
	// Always include suggestions so schema is consistent regardless of decision.
	if decision.Suggestions != nil {
		resp["suggestions"] = decision.Suggestions
	} else {
		resp["suggestions"] = []string{}
	}

	if s.mode == "enforce" && decision.Action == engine.ActionDeny {
		writeJSON(w, http.StatusForbidden, resp)
		return
	}

	if s.mode == "enforce" && decision.Action == engine.ActionWebhook {
		webhookDecision := s.executeWebhookAction(call, decision)
		resp["decision"] = webhookDecision.Action.String()
		resp["message"] = webhookDecision.Message

		webhookAuditID, err := s.writeAudit(req, toolName, webhookDecision)
		if err != nil && s.mode == "enforce" {
			writeError(w, http.StatusServiceUnavailable, "audit storage is unavailable; refusing tool call")
			return
		}
		if webhookAuditID != "" {
			auditID = webhookAuditID
		}

		if webhookDecision.Action == engine.ActionDeny {
			writeJSON(w, http.StatusForbidden, resp)
			return
		}

		blocked, responseAuditErr := s.evaluateAndAuditResponse(req, call, toolName, resp, auditID)
		if responseAuditErr != nil && s.mode == "enforce" {
			writeError(w, http.StatusServiceUnavailable, "audit storage is unavailable; refusing tool response")
			return
		}
		if blocked {
			writeJSON(w, http.StatusOK, resp)
			return
		}

		writeJSON(w, http.StatusOK, resp)
		return
	}

	if s.mode == "enforce" && (decision.Action == engine.ActionRequireApproval || decision.Action == engine.ActionAsk) {
		if req.requestsHostedApproval() {
			if identity.IsAdmin {
				if err := req.validateTrustedHostedApproval(); err != nil {
					writeError(w, http.StatusBadRequest, err.Error())
					return
				}
				s.logger.Info("proxy: trusted hosted approval evaluation requested, skipping Rampart pending approval creation",
					"tool", toolName,
					"decision", decision.Action.String(),
					"session", call.Session,
					"approval_owner", req.hostedApprovalOwnerMap(),
				)
				resp["approval_mode"] = "hosted"
				if owner := req.hostedApprovalOwnerMap(); len(owner) > 0 {
					resp["approval_owner"] = owner
				}
				if req.ToolCallID != "" {
					resp["tool_call_id"] = req.ToolCallID
				}
				resp["approval"] = s.hostedApprovalDescriptor(req, decision)
				writeJSON(w, http.StatusOK, resp)
				return
			}
			s.logger.Warn("proxy: ignoring caller-supplied hosted approval bypass flags for untrusted request",
				"tool", toolName,
				"decision", decision.Action.String(),
				"session", call.Session,
				"is_admin", identity.IsAdmin,
				"openclaw_hosted", req.OpenClawHosted,
				"skip_pending_approval", req.SkipPendingApproval,
				"approval_owner", req.hostedApprovalOwnerMap(),
			)
		}

		// Check if this run has been bulk-approved (auto-approve cache).
		if call.RunID != "" && s.approvals.IsAutoApproved(call.RunID) {
			s.logger.Debug("proxy: run auto-approved, bypassing approval queue", "tool", toolName, "run_id", call.RunID)
			decision.Action = engine.ActionAllow
			decision.Message = "auto-approved by bulk-resolve"
			decision.MatchedPolicies = []string{"auto-approved"}
			resp["decision"] = decision.Action.String()
			resp["message"] = decision.Message
			resp["policy"] = "auto-approved"
			finalAuditID, err := s.writeAudit(req, toolName, decision)
			if err != nil && s.mode == "enforce" {
				writeError(w, http.StatusServiceUnavailable, "audit storage is unavailable; refusing tool call")
				return
			}
			blocked, responseAuditErr := s.evaluateAndAuditResponse(req, call, toolName, resp, finalAuditID)
			if responseAuditErr != nil && s.mode == "enforce" {
				writeError(w, http.StatusServiceUnavailable, "audit storage is unavailable; refusing tool response")
				return
			}
			if blocked {
				writeJSON(w, http.StatusOK, resp)
				return
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}

		pending, err := s.approvals.Create(call, decision)
		if err != nil {
			s.logger.Error("proxy: approval store full", "error", err)
			writeError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		s.broadcastSSE(map[string]any{"type": "approvals"})

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

	blocked, responseAuditErr := s.evaluateAndAuditResponse(req, call, toolName, resp, auditID)
	if responseAuditErr != nil && s.mode == "enforce" {
		writeError(w, http.StatusServiceUnavailable, "audit storage is unavailable; refusing tool response")
		return
	}
	if blocked {
		writeJSON(w, http.StatusOK, resp)
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) evaluateAndAuditResponse(
	req toolRequest,
	call engine.ToolCall,
	toolName string,
	resp map[string]any,
	requestAuditID string,
) (bool, error) {
	blocked, decision := s.applyResponseEvaluation(call, req.Response, resp)
	if decision == nil {
		return blocked, nil
	}
	_, err := s.writeResponseAudit(req, toolName, *decision, req.Response, requestAuditID)
	return blocked, err
}

func (s *Server) applyResponseEvaluation(
	call engine.ToolCall,
	output string,
	resp map[string]any,
) (bool, *engine.Decision) {
	if output == "" || s.mode == "disabled" || s.engine == nil {
		return false, nil
	}

	resp["response"] = output
	result := s.engine.EvaluateResponse(call, output)
	if result.Action != engine.ActionDeny {
		return false, &result
	}

	resp["decision"] = result.Action.String()
	resp["message"] = result.Message
	resp["eval_duration_us"] = result.EvalDuration.Microseconds()
	resp["response"] = redactedResponse
	if len(result.MatchedPolicies) > 0 {
		resp["policy"] = result.MatchedPolicies[0]
	}

	return true, &result
}

func (s *Server) writeAudit(req toolRequest, toolName string, decision engine.Decision) (string, error) {
	return s.writeAuditRecord(req, toolName, decision, req.Params, nil)
}

func (s *Server) writeResponseAudit(
	req toolRequest,
	toolName string,
	decision engine.Decision,
	output string,
	requestAuditID string,
) (string, error) {
	request := make(map[string]any, len(req.Params)+3)
	for key, value := range req.Params {
		request[key] = value
	}
	request["rampart_phase"] = "response"
	request["response_bytes"] = len(output)
	if requestAuditID != "" {
		request["request_audit_id"] = requestAuditID
	}

	flags := []string{"response-evaluated"}
	if decision.Action == engine.ActionDeny {
		flags = append(flags, "response-redacted")
	}
	return s.writeAuditRecord(req, toolName, decision, request, &audit.ToolResponse{Flags: flags})
}

func (s *Server) writeAuditRecord(
	req toolRequest,
	toolName string,
	decision engine.Decision,
	request map[string]any,
	response *audit.ToolResponse,
) (string, error) {
	if s.sink == nil {
		return "", nil
	}

	eventID := audit.NewEventID()
	event := audit.Event{
		ID:            eventID,
		Timestamp:     time.Now().UTC(),
		Agent:         req.Agent,
		Session:       req.Session,
		RunID:         req.RunID,
		ToolCallID:    req.ToolCallID,
		ApprovalOwner: req.hostedApprovalOwnerMap(),
		Tool:          toolName,
		Request:       request,
		Decision: audit.EventDecision{
			Action:          decision.Action.String(),
			MatchedPolicies: decision.MatchedPolicies,
			EvalTimeUS:      decision.EvalDuration.Microseconds(),
			Message:         decision.Message,
			Suggestions:     decision.Suggestions,
		},
		Response: response,
	}

	if err := s.sink.Write(event); err != nil {
		s.logger.Error("proxy: audit write failed", "error", err)
		return "", fmt.Errorf("write audit event: %w", err)
	}
	s.broadcastSSE(map[string]any{"type": "audit", "event": event})

	// Fire webhook notification if configured
	if s.notifyConfig != nil && s.notifyConfig.URL != "" {
		actionStr := decision.Action.String()
		// require_approval and ask notifications are sent after pending approval
		// creation so they can include approval metadata (approval_id etc.).
		if actionStr != engine.ActionRequireApproval.String() &&
			actionStr != engine.ActionAsk.String() &&
			s.shouldNotify(actionStr) {
			call := engine.ToolCall{
				Tool:      toolName,
				Params:    request,
				Agent:     req.Agent,
				Timestamp: time.Now().UTC(),
			}
			go s.sendWebhook(call, decision)
		}
	}
	return eventID, nil
}

func (s *Server) hostedApprovalDescriptor(req toolRequest, decision engine.Decision) map[string]any {
	timeout := s.approvalTimeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	scopeOptions := []string{"once", "session"}
	allowAlways := req.ApprovalOwner != nil && req.ApprovalOwner.SupportsAllowAlways
	if allowAlways {
		scopeOptions = append(scopeOptions, "always")
	}
	return map[string]any{
		"reason":                 decision.Message,
		"scope_options":          scopeOptions,
		"allow_always_supported": allowAlways,
		"timeout_ms":             timeout.Milliseconds(),
		"expires_at":             time.Now().UTC().Add(timeout).Format(time.RFC3339),
	}
}

func (s *Server) shouldNotify(actionStr string) bool {
	if s.notifyConfig == nil || s.notifyConfig.URL == "" {
		return false
	}
	if len(s.notifyConfig.On) == 0 {
		// Default to deny + require_approval/ask so operators get alerted for
		// blocked calls and pending human-approval decisions out of the box.
		return actionStr == "deny" || actionStr == "require_approval" || actionStr == "ask"
	}
	for _, on := range s.notifyConfig.On {
		if notificationActionMatches(on, actionStr) {
			return true
		}
	}
	return false
}

func notificationActionMatches(configured, actual string) bool {
	if configured == actual {
		return true
	}
	if (configured == "ask" || configured == "require_approval") &&
		(actual == "ask" || actual == "require_approval") {
		return true
	}
	return (configured == "watch" || configured == "log") &&
		(actual == "watch" || actual == "log")
}

// handlePreflight evaluates a tool call against policies without executing it.
// Returns the decision that would be made — agents use this to plan around
// policy restrictions before attempting blocked actions.
func (s *Server) handlePreflight(w http.ResponseWriter, r *http.Request) {
	identity := s.checkAuthIdentity(w, r)
	if identity == nil {
		return
	}

	var req toolRequest
	if err := decodeJSONBody(r.Body, &req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}
	if req.Params == nil {
		req.Params = map[string]any{}
	}
	promoteTopLevelParams(&req)

	// Override agent from token identity (prevent impersonation via preflight).
	if !identity.IsAdmin && identity.Agent != "" {
		req.Agent = identity.Agent
	}
	if req.Verification && !identity.IsAdmin {
		writeError(w, http.StatusForbidden, "verification mode requires the local admin token")
		return
	}
	if req.Verification && req.Enforce {
		writeError(w, http.StatusBadRequest, "verification and enforce modes cannot be combined")
		return
	}

	toolName := r.PathValue("toolName")
	enrichParams(toolName, req.Params)

	call := engine.ToolCall{
		ID:        audit.NewEventID(),
		Agent:     req.Agent,
		Session:   req.Session,
		Tool:      toolName,
		Params:    req.Params,
		Input:     extractToolInput(toolName, req.Params, req.Input),
		Timestamp: time.Now().UTC(),
	}

	// Apply same policy scoping as handleToolCall.
	evalOpts := engine.EvalOptions{}
	if !identity.IsAdmin {
		evalOpts.DefaultDeny = true
		if identity.Policy != "" {
			evalOpts.PolicyFilter = identity.Policy
		}
	}
	decision := engine.Decision{}
	if s.mode == "disabled" {
		decision = engine.Decision{Action: engine.ActionAllow, Message: "policy evaluation disabled"}
	} else if s.engine == nil {
		decision = engine.Decision{Action: engine.ActionDeny, Message: "policy engine unavailable; refusing tool call"}
	} else if req.Enforce {
		decision = s.engine.Enforce(call, evalOpts)
	} else {
		decision = s.engine.EvaluateWith(call, evalOpts)
	}
	allowed := decision.Action == engine.ActionAllow || decision.Action == engine.ActionWatch
	auditID := ""
	if !req.Verification {
		var auditErr error
		auditID, auditErr = s.writeAudit(req, toolName, decision)
		if auditErr != nil && req.Enforce && s.mode == "enforce" {
			writeError(w, http.StatusServiceUnavailable, "audit storage is unavailable; refusing tool call")
			return
		}
	}

	preflightResp := map[string]any{
		"allowed":          allowed,
		"decision":         decision.Action.String(),
		"message":          decision.Message,
		"matched_policies": decision.MatchedPolicies,
		"eval_duration_us": decision.EvalDuration.Microseconds(),
		"enforced":         req.Enforce,
	}
	if auditID != "" {
		preflightResp["audit_id"] = auditID
	}
	if len(decision.Suggestions) > 0 {
		preflightResp["suggestions"] = decision.Suggestions
	}
	writeJSON(w, http.StatusOK, preflightResp)
}

// handleTest evaluates a command against the loaded policy engine and returns
// the decision. This powers the "Try a command" REPL in the dashboard Policy tab.
// Admin-only: prevents agent tokens from probing the policy engine for bypasses.
func (s *Server) handleTest(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(w, r) {
		return
	}

	if s.engine == nil {
		writeError(w, http.StatusServiceUnavailable, "policy engine not initialized")
		return
	}

	var req struct {
		Command string `json:"command"`
		Tool    string `json:"tool"`              // optional, defaults to "exec"
		Agent   string `json:"agent"`             // optional
		Session string `json:"session,omitempty"` // optional; used for session_matches evaluation
	}
	if err := decodeJSONBody(r.Body, &req); err != nil {
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

	// Admin-only endpoint: evaluate with global scope, no default deny.
	evalOpts := engine.EvalOptions{}
	policyScope := "global"
	decision := s.engine.EvaluateWith(call, evalOpts)

	writeJSON(w, http.StatusOK, map[string]any{
		"command":          req.Command,
		"tool":             req.Tool,
		"action":           decision.Action.String(),
		"message":          decision.Message,
		"matched_policies": decision.MatchedPolicies,
		"policy_scope":     policyScope,
	})
}

// handlePoliciesSnapshot returns all loaded policies with source file info.
// Admin-only — exposes rule names and match conditions.
func (s *Server) handlePoliciesSnapshot(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(w, r) {
		return
	}
	if s.engine == nil {
		writeJSON(w, http.StatusOK, map[string]any{"policies": []any{}, "default_action": "allow"})
		return
	}
	policies, defaultAction := s.engine.Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"policies":       policies,
		"default_action": defaultAction,
		"count":          len(policies),
	})
}

// handlePolicySummary returns a transparency-oriented summary of active rules.
// Admin-only to prevent agent tokens from enumerating policy rules.
func (s *Server) handlePolicySummary(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(w, r) {
		return
	}

	defaultAction := "allow"
	rules := make([]map[string]string, 0)
	if s.engine != nil {
		var summaryRules []engine.PolicySummaryRule
		defaultAction, summaryRules = s.engine.GetPolicySummary()
		rules = make([]map[string]string, 0, len(summaryRules))
		for _, rule := range summaryRules {
			rules = append(rules, map[string]string{
				"name":    rule.Name,
				"action":  rule.Action,
				"summary": rule.Summary,
			})
		}
	}

	summary := fmt.Sprintf("%d active rules loaded; default action: %s", len(rules), defaultAction)
	writeJSON(w, http.StatusOK, map[string]any{
		"default_action": defaultAction,
		"rules":          rules,
		"summary":        summary,
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(w, r) {
		return
	}

	configPath := s.configPath
	if configPath == "" {
		configPath = "rampart.yaml"
	}

	defaultAction := "allow"
	policyCount := 0
	ruleCount := 0
	callCounts := map[string]int{}
	if s.engine != nil {
		defaultAction = s.engine.GetDefaultAction()
		policyCount = s.engine.PolicyCount()
		ruleCount = s.engine.RuleCount()
		callCounts = s.engine.CallCounts(statusCallCountWindow)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"config_path":    configPath,
		"mode":           s.mode,
		"default_action": defaultAction,
		"policy_count":   policyCount,
		"rule_count":     ruleCount,
		"call_counts":    callCounts,
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
