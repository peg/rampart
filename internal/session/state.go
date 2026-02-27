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

// Package session provides per-session state management for Rampart's native
// ask prompt integration. Because each hook invocation is a fresh process,
// session state is persisted to disk so that PostToolUse hooks can correlate
// approval outcomes with the corresponding PreToolUse asks.
//
// Files are stored under ~/.rampart/session-state/{session_id}.json and are
// cleaned up automatically after a configurable idle period (default: 24h).
package session

import "time"

// State is the on-disk representation of a single session's ask/approval
// tracking state. It is serialised as JSON and written atomically to
// ~/.rampart/session-state/{session_id}.json.
type State struct {
	SessionID        string                    `json:"session_id"`
	CreatedAt        time.Time                 `json:"created_at"`
	LastActive       time.Time                 `json:"last_active"`
	PendingAsks      map[string]PendingAsk     `json:"pending_asks"`
	SessionApprovals map[string]ApprovalRecord `json:"session_approvals"`
}

// PendingAsk records the details of a PreToolUse event that emitted an ask
// decision. The map key is tool_use_id from the Claude Code hook payload.
type PendingAsk struct {
	Tool               string    `json:"tool"`
	Command            string    `json:"command,omitempty"`
	GeneralizedPattern string    `json:"generalized_pattern"`
	AskedAt            time.Time `json:"asked_at"`
	PolicyName         string    `json:"policy_name,omitempty"`
	DecisionMessage    string    `json:"decision_message,omitempty"`
	Audit              bool      `json:"audit,omitempty"`
	AuditApprovalID    string    `json:"audit_approval_id,omitempty"`
}

// ApprovalRecord tracks cumulative approvals for a generalised command pattern
// within (and optionally across) sessions. The map key is
// "{tool}:{generalized_pattern}" for deduplication.
type ApprovalRecord struct {
	Pattern       string    `json:"pattern"`
	Tool          string    `json:"tool"`
	FirstApproved time.Time `json:"first_approved"`
	LastApproved  time.Time `json:"last_approved"`
	ApprovalCount int       `json:"approval_count"`
}

// maxStateSize is the maximum file size before old entries are trimmed.
const maxStateSize = 64 * 1024 // 64 KB
