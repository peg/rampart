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
	"net/url"
	"os"
	"strings"
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
	errWriter      io.Writer
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
	message = enrichApprovalMessage(message, command)

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
			fmt.Fprintf(c.stderrWriter(), "⚠ Approval cancelled — denying\n")
			return hookDeny
		}
		fmt.Fprintf(c.stderrWriter(), "WARNING: rampart serve unreachable at %s — running without policy enforcement\n", c.serveURL)
		if c.autoDiscovered {
			c.logger.Debug("hook: auto-discovered serve unreachable, falling back to hookAsk", "url", c.serveURL, "error", err)
		} else {
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
		fmt.Fprintf(c.stderrWriter(), "⚠ Rampart serve returned %d, falling back to native prompt\n", resp.StatusCode)
		return hookAsk
	}

	var created createApprovalResponse
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		c.logger.Error("hook: decode approval response", "error", err)
		return hookAsk
	}

	// Guard against a serve bug returning 201 with an empty ID — polling
	// /v1/approvals/ (no ID) would spin silently for the full timeout.
	if created.ID == "" {
		c.logger.Error("hook: server returned 201 with empty approval ID, falling back to native prompt")
		fmt.Fprintf(c.stderrWriter(), "⚠ Rampart serve returned empty approval ID, falling back to native prompt\n")
		return hookAsk
	}

	// Print waiting message
	fmt.Fprintf(c.stderrWriter(), "⏳ Approval required — approve via dashboard (%s/dashboard/) or `rampart watch`\n", c.serveURL)
	fmt.Fprintf(c.stderrWriter(), "   Approval ID: %s\n", created.ID)

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
			fmt.Fprintf(c.stderrWriter(), "⚠ Approval cancelled\n")
			return hookDeny
		case <-deadline:
			fmt.Fprintf(c.stderrWriter(), "⏰ Approval timed out — no response received within %s\n", timeout)
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

			// Non-2xx status codes (404, 500, etc.) mean the approval is
			// gone or the server is broken — don't spin silently until timeout.
			if resp.StatusCode == http.StatusGone || resp.StatusCode == http.StatusNotFound {
				resp.Body.Close()
				fmt.Fprintf(c.stderrWriter(), "⚠ Approval %s no longer exists (status %d) — denying\n", id, resp.StatusCode)
				c.logger.Warn("hook: approval gone during poll, denying", "id", id, "status", resp.StatusCode)
				return hookDeny
			}
			if resp.StatusCode >= 500 {
				resp.Body.Close()
				c.logger.Warn("hook: server error during poll, retrying", "id", id, "status", resp.StatusCode)
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
				fmt.Fprintf(c.stderrWriter(), "✅ Approved\n")
				return hookAllow
			case "denied":
				fmt.Fprintf(c.stderrWriter(), "❌ Denied\n")
				return hookDeny
			case "expired":
				fmt.Fprintf(c.stderrWriter(), "⏰ Expired\n")
				return hookDeny
			}
			// still pending, continue polling
		}
	}
}

func (c *hookApprovalClient) stderrWriter() io.Writer {
	if c.errWriter != nil {
		return c.errWriter
	}
	return os.Stderr
}

func enrichApprovalMessage(message, toolInput string) string {
	registryURL := detectPackageRegistryURL(toolInput)
	if registryURL == "" {
		return message
	}
	return message + "\nPackage info: " + registryURL
}

func detectPackageRegistryURL(toolInput string) string {
	tokens := splitCommandTokens(toolInput)
	if len(tokens) == 0 {
		return ""
	}

	for len(tokens) > 0 {
		tok := tokens[0]
		if tok == "sudo" || strings.HasPrefix(tok, "sudo=") || isEnvAssignment(tok) {
			tokens = tokens[1:]
			continue
		}
		break
	}
	if len(tokens) < 2 {
		return ""
	}

	switch tokens[0] {
	case "npm":
		if tokens[1] != "install" && tokens[1] != "i" {
			return ""
		}
		name := extractInstallTarget(tokens[2:], map[string]bool{
			"--tag":        true,
			"--registry":   true,
			"--prefix":     true,
			"--workspace":  true,
			"-w":           true,
			"--userconfig": true,
			"--cache":      true,
		})
		name = stripNPMVersion(name)
		if name == "" {
			return ""
		}
		return "https://www.npmjs.com/package/" + url.PathEscape(name)
	case "pip":
		if tokens[1] != "install" {
			return ""
		}
		name := extractInstallTarget(tokens[2:], map[string]bool{
			"-r":                true,
			"--requirement":     true,
			"-c":                true,
			"--constraint":      true,
			"-i":                true,
			"--index-url":       true,
			"--extra-index-url": true,
			"--trusted-host":    true,
			"-f":                true,
			"--find-links":      true,
		})
		name = stripPipVersion(name)
		if name == "" {
			return ""
		}
		return "https://pypi.org/project/" + url.PathEscape(name) + "/"
	case "cargo":
		if tokens[1] != "add" {
			return ""
		}
		name := extractInstallTarget(tokens[2:], map[string]bool{
			"--features": true,
			"-F":         true,
			"--registry": true,
		})
		name = stripAtVersion(name)
		if name == "" {
			return ""
		}
		return "https://crates.io/crates/" + url.PathEscape(name)
	case "go":
		if tokens[1] != "get" {
			return ""
		}
		path := extractInstallTarget(tokens[2:], nil)
		path = stripAtVersion(path)
		if path == "" {
			return ""
		}
		return "https://pkg.go.dev/" + path
	case "gem":
		if tokens[1] != "install" {
			return ""
		}
		name := extractInstallTarget(tokens[2:], map[string]bool{
			"-v":        true,
			"--version": true,
			"-s":        true,
			"--source":  true,
		})
		name = stripAtVersion(name)
		if name == "" {
			return ""
		}
		return "https://rubygems.org/gems/" + url.PathEscape(name)
	case "brew":
		if tokens[1] != "install" {
			return ""
		}
		name := extractInstallTarget(tokens[2:], nil)
		name = stripAtVersion(name)
		if name == "" {
			return ""
		}
		return "https://formulae.brew.sh/formula/" + url.PathEscape(name)
	default:
		return ""
	}
}

func splitCommandTokens(s string) []string {
	var tokens []string
	var cur strings.Builder
	inSingle := false
	inDouble := false
	escaped := false

	flush := func() {
		if cur.Len() == 0 {
			return
		}
		tokens = append(tokens, cur.String())
		cur.Reset()
	}

	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\' && !inSingle:
			escaped = true
		case r == '\'' && !inDouble:
			inSingle = !inSingle
		case r == '"' && !inSingle:
			inDouble = !inDouble
		case (r == ' ' || r == '\t' || r == '\n') && !inSingle && !inDouble:
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return tokens
}

func isEnvAssignment(tok string) bool {
	if strings.HasPrefix(tok, "-") {
		return false
	}
	eq := strings.IndexByte(tok, '=')
	return eq > 0
}

func extractInstallTarget(tokens []string, flagsWithValue map[string]bool) string {
	for i := 0; i < len(tokens); i++ {
		tok := strings.TrimSpace(tokens[i])
		if tok == "" {
			continue
		}
		if strings.HasPrefix(tok, "-") {
			if flagsWithValue != nil && flagsWithValue[tok] && !strings.Contains(tok, "=") && i+1 < len(tokens) {
				i++
			}
			continue
		}
		return tok
	}
	return ""
}

func stripNPMVersion(name string) string {
	if name == "" {
		return ""
	}
	if strings.HasPrefix(name, "@") {
		slash := strings.IndexByte(name, '/')
		if slash == -1 {
			return name
		}
		if at := strings.LastIndexByte(name, '@'); at > slash {
			return name[:at]
		}
		return name
	}
	if at := strings.IndexByte(name, '@'); at > 0 {
		return name[:at]
	}
	return name
}

func stripPipVersion(name string) string {
	if name == "" {
		return ""
	}
	for i, r := range name {
		switch r {
		case '=', '<', '>', '!', '~':
			return name[:i]
		}
	}
	return name
}

func stripAtVersion(name string) string {
	if name == "" {
		return ""
	}
	if at := strings.IndexByte(name, '@'); at > 0 {
		return name[:at]
	}
	return name
}
