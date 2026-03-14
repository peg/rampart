// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/peg/rampart/internal/approval"
	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/internal/notify"
)

// executeWebhookAction calls the configured webhook URL and returns an
// allow or deny decision based on the response. On error/timeout, behavior
// is determined by the fail_open setting (default: fail closed).
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
