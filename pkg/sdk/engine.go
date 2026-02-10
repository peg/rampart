// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sdk

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/engine"
)

// contextKey is an unexported type for context keys, preventing collisions
// with keys from other packages.
type contextKey string

const (
	// AgentKey is the context key for the agent identifier.
	AgentKey contextKey = "rampart-agent"

	// SessionKey is the context key for the session identifier.
	SessionKey contextKey = "rampart-session"

	defaultAgent   = "unknown-agent"
	defaultSession = "unknown-session"
)

// ToolFunc is a runtime tool function wrapped by Rampart policy checks.
type ToolFunc func(ctx context.Context, params map[string]any) (any, error)

// AuditSink receives audit events emitted by SDK tool wrappers.
// Implemented by audit.JSONLSink.
type AuditSink interface {
	// Write records a single audit event.
	Write(event audit.Event) error
}

// SDK wraps the policy engine for agent runtime integrations.
type SDK struct {
	engine *engine.Engine
	sink   AuditSink
	logger *slog.Logger
}

// NewSDK creates a new SDK from a policy configuration file path.
func NewSDK(configPath string) (*SDK, error) {
	store := engine.NewFileStore(configPath)
	e, err := engine.New(store, slog.Default())
	if err != nil {
		return nil, fmt.Errorf("sdk: create engine: %w", err)
	}

	return &SDK{
		engine: e,
		logger: slog.Default(),
	}, nil
}

// Wrap returns a policy-enforced wrapper for a tool function.
func (s *SDK) Wrap(toolName string, fn ToolFunc) ToolFunc {
	return func(ctx context.Context, params map[string]any) (any, error) {
		start := time.Now()
		call := buildToolCall(ctx, toolName, params)
		decision := s.engine.Evaluate(call)

		s.logger.Info("sdk: tool evaluated",
			"tool", toolName,
			"agent", call.Agent,
			"session", call.Session,
			"action", decision.Action,
			"eval_duration", decision.EvalDuration,
		)

		if decision.Action == engine.ActionDeny {
			return nil, &ErrDenied{Tool: toolName, Policy: firstPolicy(decision), Message: decision.Message}
		}

		result, err := fn(ctx, params)
		s.logger.Info("sdk: tool completed",
			"tool", toolName,
			"action", decision.Action,
			"total_duration", time.Since(start),
			"error", err,
		)
		return result, err
	}
}

// Preflight checks whether a tool call would be allowed without executing it.
// Returns the decision the engine would make. Agents can use this to plan
// around policy restrictions — choosing alternative approaches, batching
// approval requests, or informing the user before attempting blocked actions.
func (s *SDK) Preflight(ctx context.Context, toolName string, params map[string]any) PreflightResult {
	call := buildToolCall(ctx, toolName, params)
	decision := s.engine.Evaluate(call)

	return PreflightResult{
		Allowed:   decision.Action == engine.ActionAllow || decision.Action == engine.ActionLog,
		Action:    decision.Action.String(),
		Message:   decision.Message,
		Policies:  decision.MatchedPolicies,
		EvalTime:  decision.EvalDuration,
	}
}

// PreflightResult is the outcome of a preflight policy check.
type PreflightResult struct {
	// Allowed is true if the tool call would proceed (allow or log).
	Allowed bool

	// Action is the policy decision (allow, deny, log, require_approval).
	Action string

	// Message is the human-readable reason from the matching policy rule.
	Message string

	// Policies lists the names of policies that matched.
	Policies []string

	// EvalTime is how long evaluation took.
	EvalTime time.Duration
}

// buildToolCall creates an engine.ToolCall from context and tool params.
func buildToolCall(ctx context.Context, toolName string, params map[string]any) engine.ToolCall {
	if params == nil {
		params = make(map[string]any)
	}

	return engine.ToolCall{
		Agent:     valueOrDefault(ctx, AgentKey, defaultAgent),
		Session:   valueOrDefault(ctx, SessionKey, defaultSession),
		Tool:      toolName,
		Params:    params,
		Timestamp: time.Now(),
	}
}

// valueOrDefault returns a context string value for key, or fallback.
func valueOrDefault(ctx context.Context, key contextKey, fallback string) string {
	if ctx == nil {
		return fallback
	}

	value, _ := ctx.Value(key).(string)
	if value == "" {
		return fallback
	}

	return value
}

// firstPolicy returns the first matched policy name, if any.
func firstPolicy(decision engine.Decision) string {
	if len(decision.MatchedPolicies) == 0 {
		return ""
	}
	return decision.MatchedPolicies[0]
}
