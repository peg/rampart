// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"
)

// hookApprovalClient delegates require_approval decisions to a running
// rampart serve instance. It creates an approval via the API, then polls
// until the approval is resolved or times out.
type hookApprovalClient struct {
	serveURL       string
	token          string
	logger         *slog.Logger
	autoDiscovered bool // true when serve URL was auto-discovered, not explicitly set
}

// createApprovalRequest is the JSON body POSTed to POST /v1/approvals.
type createApprovalRequest struct {
	Tool    string `json:"tool"`
	Command string `json:"command,omitempty"`
	Agent   string `json:"agent"`
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
	RunID   string `json:"run_id,omitempty"`
}

// createApprovalResponse is the JSON returned from POST /v1/approvals.
type createApprovalResponse struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	ExpiresAt string `json:"expires_at"`
}

// pollApprovalResponse is the JSON returned from GET /v1/approvals/{id}.
type pollApprovalResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// requestApproval creates an approval and polls until resolved.
// Returns hookAllow if approved, hookDeny if denied/expired/error.
// Falls back to hookAsk if the serve instance is unreachable.
// The context allows cancellation (e.g., user Ctrl-C).
func (c *hookApprovalClient) requestApproval(tool, command, agent, path, runID, message string, timeout time.Duration) hookDecisionType {
	return c.requestApprovalCtx(context.Background(), tool, command, agent, path, runID, message, timeout)
}

// requestApprovalCtx is like requestApproval but accepts a context for cancellation.
func (c *hookApprovalClient) requestApprovalCtx(ctx context.Context, tool, command, agent, path, runID, message string, timeout time.Duration) hookDecisionType {
	// Create the approval
	body := createApprovalRequest{
		Tool:    tool,
		Command: command,
		Agent:   agent,
		Path:    path,
		Message: message,
		RunID:   runID,
	}

	data, err := json.Marshal(body)
	if err != nil {
		c.logger.Error("hook: marshal approval request", "error", err)
		return hookAsk
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.serveURL+"/v1/approvals", bytes.NewReader(data))
	if err != nil {
		c.logger.Error("hook: create approval request", "error", err)
		return hookAsk
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		// If the context was cancelled (e.g. user Ctrl-C), deny rather than
		// falling back to Claude Code's native prompt — Rampart should fail closed.
		if ctx.Err() != nil {
			c.logger.Debug("hook: context cancelled during approval create, denying", "error", err)
			fmt.Fprintf(os.Stderr, "⚠ Approval cancelled — denying\n")
			return hookDeny
		}
		if c.autoDiscovered {
			c.logger.Debug("hook: auto-discovered serve unreachable, falling back to hookAsk", "url", c.serveURL, "error", err)
		} else {
			fmt.Fprintf(os.Stderr, "⚠ Rampart serve unreachable (%s), falling back to native prompt\n", c.serveURL)
			c.logger.Warn("hook: serve unreachable, falling back to hookAsk", "url", c.serveURL, "error", err)
		}
		return hookAsk
	}
	defer resp.Body.Close()

	// 200 means the approval was already resolved (auto-approve or bulk-resolve).
	// Status field determines the outcome — don't assume approved.
	if resp.StatusCode == http.StatusOK {
		var autoResp struct {
			Status string `json:"status"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&autoResp); err == nil {
			switch autoResp.Status {
			case "approved":
				c.logger.Debug("hook: run auto-approved by bulk-resolve, skipping queue")
				return hookAllow
			case "denied":
				c.logger.Debug("hook: run auto-denied by bulk-resolve, skipping queue")
				fmt.Fprintf(os.Stderr, "❌ Auto-denied (run was bulk-denied)\n")
				return hookDeny
			}
		}
		c.logger.Error("hook: unexpected 200 from approval create", "url", c.serveURL)
		return hookAsk
	}

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		c.logger.Error("hook: create approval failed", "status", resp.StatusCode, "body", string(respBody))
		fmt.Fprintf(os.Stderr, "⚠ Rampart serve returned %d, falling back to native prompt\n", resp.StatusCode)
		return hookAsk
	}

	var created createApprovalResponse
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		c.logger.Error("hook: decode approval response", "error", err)
		return hookAsk
	}

	// Print waiting message
	fmt.Fprintf(os.Stderr, "⏳ Approval required — approve via dashboard (%s/dashboard/) or `rampart watch`\n", c.serveURL)
	fmt.Fprintf(os.Stderr, "   Approval ID: %s\n", created.ID)

	// Poll until resolved
	return c.pollApprovalCtx(ctx, created.ID, timeout)
}

// pollApproval polls GET /v1/approvals/{id} every 500ms until resolved.
func (c *hookApprovalClient) pollApproval(id string, timeout time.Duration) hookDecisionType {
	return c.pollApprovalCtx(context.Background(), id, timeout)
}

// pollApprovalCtx polls with context support for cancellation.
func (c *hookApprovalClient) pollApprovalCtx(ctx context.Context, id string, timeout time.Duration) hookDecisionType {
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.After(timeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintf(os.Stderr, "⚠ Approval cancelled\n")
			return hookDeny
		case <-deadline:
			fmt.Fprintf(os.Stderr, "⏰ Approval timed out — no response received within %s\n", timeout)
			return hookDeny
		case <-ticker.C:
			req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/v1/approvals/%s", c.serveURL, id), nil)
			if err != nil {
				continue
			}
			req.Header.Set("Authorization", "Bearer "+c.token)

			resp, err := client.Do(req)
			if err != nil {
				c.logger.Debug("hook: poll error", "error", err)
				continue
			}

			var status pollApprovalResponse
			err = json.NewDecoder(resp.Body).Decode(&status)
			resp.Body.Close()
			if err != nil {
				continue
			}

			switch status.Status {
			case "approved":
				fmt.Fprintf(os.Stderr, "✅ Approved\n")
				return hookAllow
			case "denied":
				fmt.Fprintf(os.Stderr, "❌ Denied\n")
				return hookDeny
			case "expired":
				fmt.Fprintf(os.Stderr, "⏰ Expired\n")
				return hookDeny
			}
			// still pending, continue polling
		}
	}
}
