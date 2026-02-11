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
	"time"
)

// Action represents the outcome of a policy evaluation.
type Action int

const (
	// ActionAllow permits the tool call to proceed.
	ActionAllow Action = iota

	// ActionDeny blocks the tool call. The agent receives an error.
	ActionDeny

	// ActionLog permits the tool call but flags it for review in the
	// audit trail. Use for suspicious-but-not-blocked activity.
	ActionLog

	// ActionRequireApproval blocks the tool call until a human approves it.
	// The call is held pending with a unique approval ID. Resolve via CLI
	// (rampart approve/deny) or the HTTP API.
	ActionRequireApproval
)

// String returns a human-readable action name.
func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "allow"
	case ActionDeny:
		return "deny"
	case ActionLog:
		return "log"
	case ActionRequireApproval:
		return "require_approval"
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

	// Session identifies the agent's current session.
	Session string

	// Tool is the tool being invoked (e.g., "exec", "read", "write").
	Tool string

	// Params contains tool-specific parameters.
	// For exec: {"command": "git push", "workdir": "/home/user/project"}
	// For read: {"path": "/etc/passwd"}
	Params map[string]any

	// Timestamp is when the tool call was initiated.
	Timestamp time.Time
}

// Command extracts the command string from an exec tool call's params.
// Returns empty string if not present or not a string.
func (tc ToolCall) Command() string {
	cmd, _ := tc.Params["command"].(string)
	return cmd
}

// Path extracts the file path from a read/write tool call's params.
// Returns empty string if not present or not a string.
func (tc ToolCall) Path() string {
	p, _ := tc.Params["path"].(string)
	return p
}

// Decision is the result of evaluating a tool call against all policies.
type Decision struct {
	// Action is the final verdict: allow, deny, or log.
	Action Action

	// MatchedPolicies lists the names of all policies that matched
	// the tool call. Useful for debugging and audit.
	MatchedPolicies []string

	// Message is a human-readable explanation of the decision.
	// For denials, this tells the agent why the call was blocked.
	Message string

	// EvalDuration is how long policy evaluation took.
	// Tracked for performance monitoring.
	EvalDuration time.Duration
}

// ParseAction converts a string to an Action.
func ParseAction(s string) Action {
	switch s {
	case "allow":
		return ActionAllow
	case "deny":
		return ActionDeny
	case "log":
		return ActionLog
	case "require_approval":
		return ActionRequireApproval
	default:
		return ActionAllow
	}
}

// Denied returns true if the tool call was blocked.
func (d Decision) Denied() bool {
	return d.Action == ActionDeny
}
