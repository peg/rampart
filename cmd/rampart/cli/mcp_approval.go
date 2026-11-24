// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/internal/mcp"
)

// mcpApprovalTimeout matches the hook approval wait. The MCP client owns its
// own request timeout and may give up on the call before this expires.
const mcpApprovalTimeout = 5 * time.Minute

// newMCPServeApprovalResolver routes MCP proxy approvals to the running
// rampart serve queue through the same client the hook integrations use.
// Serve location and credentials are resolved for each approval so a serve
// instance started after the proxy is found. Every failure denies.
//
// Serve notifies reviewers about an approval it queues, with a link to decide
// it, when its own policy is configured to. notifyReviewers (if set) is called
// whenever serve has not done so: the approval never reached the queue, or
// serve queued it without dispatching a notification. The ask is then never
// silent for a proxy whose policy asks for notifications.
func newMCPServeApprovalResolver(timeout time.Duration, errWriter io.Writer, logger *slog.Logger, notifyReviewers func(engine.ToolCall, engine.Decision)) mcp.ApprovalResolver {
	return func(ctx context.Context, call engine.ToolCall, decision engine.Decision) error {
		onQueued := func(serveNotified bool) {
			if !serveNotified && notifyReviewers != nil {
				notifyReviewers(call, decision)
			}
		}
		err := requestMCPServeApproval(ctx, call, decision.Message, timeout, errWriter, logger, onQueued)
		var unqueued approvalNotQueuedError
		if errors.As(err, &unqueued) && notifyReviewers != nil {
			notifyReviewers(call, decision)
		}
		return err
	}
}

// approvalNotQueuedError is a failure before serve returned a queued
// approval, so serve has not notified anyone about it.
type approvalNotQueuedError string

func (e approvalNotQueuedError) Error() string { return string(e) }

func requestMCPServeApproval(ctx context.Context, call engine.ToolCall, message string, timeout time.Duration, errWriter io.Writer, logger *slog.Logger, onQueued func(serveNotified bool)) error {
	serveURL, err := resolveServeURLStrict("", fmt.Sprintf("http://localhost:%d", defaultServePort))
	if err != nil {
		return approvalNotQueuedError("local Rampart configuration is invalid; cannot request approval")
	}
	token, _, err := resolveTokenForEndpoint(serveURL, "")
	if err != nil {
		return approvalNotQueuedError("the Rampart credential endpoint is unsafe; cannot request approval")
	}
	if token == "" {
		return approvalNotQueuedError("no Rampart serve token is available; cannot request approval")
	}
	if !isServeRunning(serveURL) {
		return approvalNotQueuedError("approval requires a running Rampart service (`rampart serve`)")
	}
	client := &hookApprovalClient{
		serveURL:       strings.TrimRight(serveURL, "/"),
		token:          token,
		logger:         logger,
		autoDiscovered: true,
		errWriter:      errWriter,
		onQueued:       onQueued,
	}
	switch client.requestApprovalCtx(ctx, call, message, timeout) {
	case hookAllow:
		return nil
	case hookAsk:
		// hookAsk means serve was unreachable or returned no usable queued
		// approval. A serve that answered 201 with a malformed body may also
		// have notified, so this can rarely duplicate; it is never silent.
		return approvalNotQueuedError("the Rampart approval service was unavailable")
	default:
		return errors.New("approval was denied, expired, or timed out")
	}
}

// newMCPDecisionSink wires the proxy's audit sink and serve approval resolver
// so each ask produces one reviewer notification. In enforce mode serve sends
// it, with its decision link, for an approval it queues and notifies about;
// the proxy sends its own when serve reports no notification or the approval
// never reached the queue. Monitor mode does
// not request approvals, so its ask notifications are unchanged.
func newMCPDecisionSink(sink audit.AuditSink, notifyConfig *engine.NotifyConfig, mode string, errWriter io.Writer, logger *slog.Logger) (*decisionCounterSink, mcp.ApprovalResolver) {
	counted := newDecisionCounterSink(sink, notifyConfig, logger)
	if mode == "enforce" {
		counted.skipNotification = mcpAskAwaitsServeApproval
	}
	return counted, newMCPServeApprovalResolver(mcpApprovalTimeout, errWriter, logger, counted.notify)
}

// mcpAskAwaitsServeApproval reports whether event is the enforce-mode audit
// record of a tools/call ask that the proxy hands to the approval resolver
// next. The resolver notifies for it only when serve does not.
func mcpAskAwaitsServeApproval(event audit.Event) bool {
	if method, _ := event.Request["mcp_method"].(string); method != "tools/call" {
		return false
	}
	if _, phase := event.Request["mcp_phase"]; phase {
		return false
	}
	action, err := engine.ParseAction(event.Decision.Action)
	return err == nil && (action == engine.ActionAsk || action == engine.ActionRequireApproval)
}
