// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package proxy

import (
	"time"

	"github.com/peg/rampart/internal/approval"
	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/internal/notify"
	"github.com/peg/rampart/internal/webhookaction"
)

// executeWebhookAction calls the configured webhook URL and returns an
// allow or deny decision based on the response. On error/timeout, behavior
// is determined by the fail_open setting (default: fail closed).
func (s *Server) executeWebhookAction(call engine.ToolCall, decision engine.Decision) engine.Decision {
	return webhookaction.Execute(s.logger, call, decision)
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

	resolveURL := s.approvalResolveURL(pending.ID, pending.ExpiresAt.UTC())
	if resolveURL == "" {
		s.logger.Error("proxy: approval notification suppressed because no signed resolve URL is available", "approval_id", pending.ID)
		return
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
		ResolveURL: resolveURL,
	}

	notifier := notify.NewNotifier(s.notifyConfig.URL, s.notifyConfig.Platform)
	if err := notifier.Send(event); err != nil {
		s.logger.Error("proxy: approval webhook notification failed", "error", err)
	} else {
		s.logger.Debug("proxy: webhook notification sent", "action", decision.Action.String(), "approval_id", pending.ID)
	}
}
