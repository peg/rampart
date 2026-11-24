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
func newMCPServeApprovalResolver(timeout time.Duration, errWriter io.Writer, logger *slog.Logger) mcp.ApprovalResolver {
	return func(ctx context.Context, call engine.ToolCall, message string) error {
		serveURL, err := resolveServeURLStrict("", fmt.Sprintf("http://localhost:%d", defaultServePort))
		if err != nil {
			return errors.New("local Rampart configuration is invalid; cannot request approval")
		}
		token, _, err := resolveTokenForEndpoint(serveURL, "")
		if err != nil {
			return errors.New("the Rampart credential endpoint is unsafe; cannot request approval")
		}
		if token == "" {
			return errors.New("no Rampart serve token is available; cannot request approval")
		}
		if !isServeRunning(serveURL) {
			return errors.New("approval requires a running Rampart service (`rampart serve`)")
		}
		client := &hookApprovalClient{
			serveURL:       strings.TrimRight(serveURL, "/"),
			token:          token,
			logger:         logger,
			autoDiscovered: true,
			errWriter:      errWriter,
		}
		switch client.requestApprovalCtx(ctx, call, message, timeout) {
		case hookAllow:
			return nil
		case hookAsk:
			return errors.New("the Rampart approval service was unavailable")
		default:
			return errors.New("approval was denied, expired, or timed out")
		}
	}
}
