// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package proxy

import (
	"encoding/json"
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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

	call := engine.ToolCall{
		ID:        audit.NewEventID(),
		Agent:     req.Agent,
		Session:   req.Session,
		RunID:     req.RunID,
		Tool:      toolName,
		Params:    req.Params,
		Input:     extractToolInput(toolName, req.Params, req.Input),
		Timestamp: time.Now().UTC(),
	}

	// Count every PreToolUse event regardless of policy outcome.
	if s.engine != nil {
		s.engine.IncrementCallCount(call.Tool, call.Timestamp)
	}

	if s.mode == "disabled" {
		decision = engine.Decision{
			Action:       engine.ActionAllow,
			Message:      "policy evaluation disabled",
			EvalDuration: 0,
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
		decision = s.engine.EvaluateWith(call, evalOpts)
		// Warn when policy filter matched no policies — helps debug silent denies.
		if evalOpts.PolicyFilter != "" && decision.Message == "no matching policy; using default action" {
			s.logger.Warn("proxy: per-agent token policy filter matched no policies — all calls denied",
				"agent", call.Agent, "policy_filter", evalOpts.PolicyFilter, "tool", call.Tool)
		}
	}

	// Consume once:true rules after they fire. This removes the rule from
	// the policy file so it won't match again. Done asynchronously to avoid
	// blocking the response.
	if decision.ConsumedOnce && decision.ConsumedRulePolicy != "" {
		go func(policyName string, ruleIdx int) {
			if err := s.engine.ConsumeOnceRule(policyName, ruleIdx); err != nil {
				s.logger.Error("proxy: failed to consume once rule",
					"policy", policyName,
					"rule_index", ruleIdx,
					"error", err,
				)
			}
		}(decision.ConsumedRulePolicy, decision.ConsumedRuleIndex)
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

	allowed := decision.Action == engine.ActionAllow || decision.Action == engine.ActionWatch
	resp := map[string]any{
		"allowed":          allowed,
		"decision":         decision.Action.String(),
		"message":          decision.Message,
		"eval_duration_us": decision.EvalDuration.Microseconds(),
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

	if s.mode == "enforce" && (decision.Action == engine.ActionRequireApproval || decision.Action == engine.ActionAsk) {
		if req.OpenClawHosted || req.SkipPendingApproval {
			if identity.IsAdmin && req.OpenClawHosted && req.SkipPendingApproval {
				s.logger.Info("proxy: trusted OpenClaw-hosted approval evaluation requested, skipping Rampart pending approval creation",
					"tool", toolName,
					"decision", decision.Action.String(),
					"session", call.Session,
				)
				s.writeAudit(req, toolName, decision)
				writeJSON(w, http.StatusOK, resp)
				return
			}
			s.logger.Warn("proxy: ignoring caller-supplied hosted approval bypass flags for untrusted or incomplete request",
				"tool", toolName,
				"decision", decision.Action.String(),
				"session", call.Session,
				"is_admin", identity.IsAdmin,
				"openclaw_hosted", req.OpenClawHosted,
				"skip_pending_approval", req.SkipPendingApproval,
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
			s.writeAudit(req, toolName, decision)
			writeJSON(w, http.StatusOK, resp)
			return
		}

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
			Suggestions:     decision.Suggestions,
		},
	}

	if err := s.sink.Write(event); err != nil {
		s.logger.Error("proxy: audit write failed", "error", err)
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
		// Default to deny + require_approval/ask so operators get alerted for
		// blocked calls and pending human-approval decisions out of the box.
		return actionStr == "deny" || actionStr == "require_approval" || actionStr == "ask"
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
	identity := s.checkAuthIdentity(w, r)
	if identity == nil {
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
	promoteTopLevelParams(&req)

	// Override agent from token identity (prevent impersonation via preflight).
	if !identity.IsAdmin && identity.Agent != "" {
		req.Agent = identity.Agent
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
	decision := s.engine.EvaluateWith(call, evalOpts)
	allowed := decision.Action == engine.ActionAllow || decision.Action == engine.ActionWatch
	s.writeAudit(req, toolName, decision)

	preflightResp := map[string]any{
		"allowed":          allowed,
		"decision":         decision.Action.String(),
		"message":          decision.Message,
		"matched_policies": decision.MatchedPolicies,
		"eval_duration_us": decision.EvalDuration.Microseconds(),
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
