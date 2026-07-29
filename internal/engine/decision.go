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

// Package engine implements Rampart's policy evaluation engine.
//
// The engine loads declarative YAML policies and evaluates tool calls
// against them. Evaluation follows a deny-wins model: if any matching
// policy produces a deny decision, the tool call is blocked regardless
// of other allow rules.
//
// This package is the core of Rampart. It has zero external dependencies
// and evaluates policies in microseconds.
package engine

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Action represents the outcome of a policy evaluation.
type Action int

const (
	// ActionAllow permits the tool call to proceed.
	ActionAllow Action = iota

	// ActionDeny blocks the tool call. The agent receives an error.
	ActionDeny

	// ActionWatch permits the tool call but surfaces it prominently in the
	// dashboard Active tab. Use for "allow but I want to see this" behavior.
	// Previously named ActionWatch — "log" was misleading since all actions are logged.
	// The string "log" in policy YAML still works but emits a deprecation lint warning.
	ActionWatch

	// ActionRequireApproval blocks the tool call until a human approves it.
	// The call is held pending with a unique approval ID. Resolve via CLI
	// (rampart approve/deny) or the HTTP API.
	ActionRequireApproval

	// ActionWebhook delegates the allow/deny decision to an external webhook.
	// The proxy POSTs tool call details to the configured URL and uses the
	// response to determine whether to allow or deny the call.
	ActionWebhook

	// ActionAsk emits Claude Code's native permission dialog inline.
	// The user sees: [Allow once] [Allow for session] [Always allow] [Deny]
	// This has no dependency on rampart serve and works fully offline.
	// On Cline and other non-Claude Code agents, falls back to deny.
	// Use match.agent: ["claude-code"] to scope this action appropriately.
	ActionAsk
)

// String returns a human-readable action name.
func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "allow"
	case ActionDeny:
		return "deny"
	case ActionWatch:
		return "watch"
	case ActionRequireApproval:
		return "require_approval"
	case ActionWebhook:
		return "webhook"
	case ActionAsk:
		return "ask"
	default:
		return fmt.Sprintf("action(%d)", int(a))
	}
}

// ToolCall represents a single tool invocation by an agent.
// This is the input to the policy engine.
type ToolCall struct {
	// ID is a unique identifier for this call (ULID).
	ID string

	// Agent identifies which agent is making the call.
	// Used for agent-scoped policy matching.
	Agent string

	// AgentDepth is how deeply nested this call is in sub-agent orchestration.
	// 0 is top-level agent; each sub-agent level increments by 1.
	AgentDepth int `json:"agent_depth,omitempty"`

	// Session identifies the agent's current session.
	Session string

	// RunID groups tool calls from the same orchestration run.
	// Sourced from Claude Code's session_id (shared across all agents in a session),
	// RAMPART_RUN env override, or CLAUDE_CONVERSATION_ID fallback.
	// Empty string means no grouping (standalone call).
	RunID string

	// ToolCallID is the stable invocation identifier supplied by the host harness.
	// Unlike ID, it should remain the same when a host retries the same tool call.
	// Empty string means the host did not provide a stable invocation identity.
	ToolCallID string

	// Tool is the tool being invoked (e.g., "exec", "read", "write").
	Tool string

	// WorkDir is the host-reported directory against which relative filesystem
	// paths are resolved. Hook processes and policy services can run from a
	// different directory than the agent, so using the Rampart process CWD here
	// would evaluate a different file from the one the tool will touch.
	WorkDir string

	// Params contains tool-specific parameters.
	// For exec: {"command": "git push", "workdir": "/home/user/project"}
	// For read: {"path": "/etc/passwd"}
	Params map[string]any

	// Input contains raw MCP tool input arguments (if available).
	Input map[string]any `json:"input,omitempty"`

	// Timestamp is when the tool call was initiated.
	Timestamp time.Time
}

// WorkingDirectory returns the explicit host working directory, falling back
// to common structured parameter names used by SDK and HTTP callers.
func (tc ToolCall) WorkingDirectory() string {
	if workDir := strings.TrimSpace(tc.WorkDir); workDir != "" {
		return workDir
	}
	if workDir := strings.TrimSpace(tc.Param("workdir")); workDir != "" {
		return workDir
	}
	return strings.TrimSpace(tc.Param("cwd"))
}

// Param returns a string value from Params, falling back to Input.
// This ensures policy matching works regardless of whether the API client
// sends tool arguments in "params" (legacy) or "input" (MCP-style).
func (tc ToolCall) Param(key string) string {
	if v, ok := tc.Params[key].(string); ok && strings.TrimSpace(v) != "" {
		return v
	}
	if v, ok := tc.Input[key].(string); ok && strings.TrimSpace(v) != "" {
		return v
	}
	return ""
}

func (tc ToolCall) paramAlias(keys ...string) string {
	for _, values := range []map[string]any{tc.Params, tc.Input} {
		for _, key := range keys {
			if value, ok := values[key].(string); ok && strings.TrimSpace(value) != "" {
				return value
			}
		}
	}
	return ""
}

// Command extracts the command string from an exec tool call's params.
// Returns empty string if not present or not a string.
func (tc ToolCall) Command() string {
	// Command input crosses an untrusted host boundary. Never accept a second,
	// caller-supplied "effective" representation for policy matching: an agent
	// could pair a dangerous raw command with a benign sanitized value. Any
	// normalization must be derived internally from this raw command.
	if strings.EqualFold(strings.TrimSpace(tc.Tool), "exec") {
		return tc.paramAlias("command", "cmd", "input")
	}
	return tc.Param("command")
}

// validateSecurityInput rejects conflicting representations of fields that
// determine what a host will execute or access. ToolCall is used by several
// adapters, and callers may populate both Params and Input; silently choosing
// one lets an untrusted host put a benign decoy in the preferred slot while it
// executes a different value from another alias.
func (tc ToolCall) validateSecurityInput() error {
	tool := strings.ToLower(strings.TrimSpace(tc.Tool))
	if tool == "exec" {
		if err := validateStringAliases("command", []map[string]any{tc.Params, tc.Input}, "command", "cmd", "input"); err != nil {
			return err
		}
	}
	if isPathSecurityTool(tool) {
		if err := validateStringAliases("path", []map[string]any{tc.Params, tc.Input}, "path", "file_path", "file", "filepath", "target"); err != nil {
			return err
		}
	}
	if isURLSecurityTool(tool) {
		if err := validateStringAliases("url", []map[string]any{tc.Params, tc.Input}, "url", "uri", "href"); err != nil {
			return err
		}
	}
	if err := validateStringAliasesWithValues("working directory", []string{tc.WorkDir}, []map[string]any{tc.Params, tc.Input}, "workdir", "cwd"); err != nil {
		return err
	}
	for _, field := range []string{"domain", "scheme"} {
		if err := validateStringAliases(field, []map[string]any{tc.Params, tc.Input}, field); err != nil {
			return err
		}
	}
	return nil
}

func isPathSecurityTool(tool string) bool {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "read", "write", "edit", "mcp-destructive":
		return true
	default:
		return false
	}
}

func isURLSecurityTool(tool string) bool {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "fetch", "http", "web_fetch", "browser":
		return true
	default:
		return false
	}
}

func validateStringAliases(field string, maps []map[string]any, keys ...string) error {
	return validateStringAliasesWithValues(field, nil, maps, keys...)
}

func validateStringAliasesWithValues(field string, initial []string, maps []map[string]any, keys ...string) error {
	values := make(map[string]struct{}, len(initial)+len(maps)*len(keys))
	for _, value := range initial {
		if value = strings.TrimSpace(value); value != "" {
			values[value] = struct{}{}
		}
	}
	for _, valuesMap := range maps {
		for _, key := range keys {
			value, exists := valuesMap[key]
			if !exists || value == nil {
				continue
			}
			text, ok := value.(string)
			if !ok {
				return fmt.Errorf("%s must be a string", field)
			}
			if text = strings.TrimSpace(text); text != "" {
				values[text] = struct{}{}
			}
		}
	}
	if len(values) > 1 {
		return fmt.Errorf("conflicting %s aliases", field)
	}
	return nil
}

// Path extracts the file path from a read/write tool call's params.
// Claude Code uses "file_path" for Read/Write/Edit; other agents may use "path".
// Returns empty string if not present or not a string.
func (tc ToolCall) Path() string {
	if isPathSecurityTool(tc.Tool) {
		return tc.paramAlias("file_path", "path", "file", "filepath", "target")
	}
	return tc.paramAlias("file_path", "path")
}

// URL returns the canonical network destination supplied by the host.
func (tc ToolCall) URL() string {
	if isURLSecurityTool(tc.Tool) {
		return tc.paramAlias("url", "uri", "href")
	}
	return tc.Param("url")
}

// Domain derives the hostname from URL whenever possible. A caller-supplied
// domain is only a fallback for adapters that report a domain without a URL;
// it must never override a concrete destination URL.
func (tc ToolCall) Domain() string {
	rawURL := tc.URL()
	if parsed, err := url.Parse(rawURL); err == nil && parsed.Host != "" {
		return parsed.Hostname()
	}
	return tc.Param("domain")
}

// Decision is the result of evaluating a tool call against all policies.
type Decision struct {
	// Action is the final verdict: allow, deny, or log.
	Action Action

	// Audit is set for ask decisions when audit mirroring is enabled.
	// This is true for:
	// - action: ask with ask.audit: true
	// - action: require_approval (alias for ask+audit)
	Audit bool

	// HeadlessOnly is set for ask decisions when native prompts should be
	// bypassed in favor of serve-backed blocking approval flow.
	HeadlessOnly bool

	// MatchedPolicies lists the names of all policies that matched
	// the tool call. Useful for debugging and audit.
	MatchedPolicies []string

	// FromProjectPolicy is true when the deciding rule came from a
	// project-level policy (.rampart/policy.yaml) rather than global.
	FromProjectPolicy bool

	// Message is a human-readable explanation of the decision.
	// For denials, this tells the agent why the call was blocked.
	Message string

	// EvalDuration is how long policy evaluation took.
	// Tracked for performance monitoring.
	EvalDuration time.Duration

	// WebhookConfig is set when Action is ActionWebhook. Contains the
	// webhook URL and behavior configuration for the proxy to execute.
	WebhookConfig *WebhookActionConfig

	// Suggestions contains human-readable CLI commands showing how to allow
	// this call. Only populated for ActionDeny decisions. Each entry is a
	// ready-to-run "rampart allow ..." command the user can copy and execute.
	Suggestions []string

	// ConsumedOnce is set when a once:true rule was matched and should be
	// removed from the policy file by the caller.
	ConsumedOnce bool

	// ConsumedRulePolicy is the policy name containing the consumed once rule.
	ConsumedRulePolicy string

	// ConsumedRuleIndex is the index of the consumed rule within its policy.
	ConsumedRuleIndex int
}

// ParseAction converts a string to an Action.
func ParseAction(s string) (Action, error) {
	switch s {
	case "allow":
		return ActionAllow, nil
	case "deny":
		return ActionDeny, nil
	case "watch":
		return ActionWatch, nil
	case "log": // deprecated alias for watch
		return ActionWatch, nil
	case "require_approval":
		return 0, fmt.Errorf("action \"require_approval\" was removed in v0.9.9; use \"ask\" instead (see migration guide)")
	case "webhook":
		return ActionWebhook, nil
	case "ask":
		return ActionAsk, nil
	default:
		return ActionAllow, fmt.Errorf("unknown action: %q", s)
	}
}

// Denied returns true if the tool call was blocked.
func (d Decision) Denied() bool {
	return d.Action == ActionDeny
}
