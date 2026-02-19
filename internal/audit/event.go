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

// Package audit provides a tamper-evident audit trail for agent tool calls.
//
// Every tool call evaluated by Rampart is recorded as an AuditEvent with
// a cryptographic hash chain. Each event's hash includes the previous event's
// hash, creating an append-only chain where any tampering is detectable.
//
// The audit trail is the strategic foundation for Rampart's future capabilities:
// behavioral fingerprinting, progressive trust, and agent-to-agent attestation
// are all computed from audit data.
package audit

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Event represents a single audited tool call.
//
// Events are written to the audit trail in JSONL format, one per line.
// The hash chain ensures integrity: modifying any event breaks the chain
// for all subsequent events.
type Event struct {
	// ID is a ULID — time-ordered, lexicographically sortable, globally unique.
	ID string `json:"id"`

	// Timestamp is when the tool call was initiated (UTC).
	Timestamp time.Time `json:"timestamp"`

	// Agent identifies which agent made the call.
	Agent string `json:"agent"`

	// Session identifies the agent's session (git repo/branch or RAMPART_SESSION).
	Session string `json:"session"`

	// RunID groups events from the same orchestration run.
	// Sourced from Claude Code's session_id field, RAMPART_RUN env override,
	// or CLAUDE_CONVERSATION_ID fallback. Empty if no grouping applies.
	RunID string `json:"run_id,omitempty"`

	// Tool is the tool that was invoked (e.g., "exec", "read").
	Tool string `json:"tool"`

	// Request contains the tool call parameters.
	Request map[string]any `json:"request"`

	// Decision records the policy engine's verdict.
	Decision EventDecision `json:"decision"`

	// Response captures the tool's output, if the call was allowed.
	// Nil for denied calls.
	Response *ToolResponse `json:"response,omitempty"`

	// PrevHash is the hash of the preceding event in the chain.
	// Empty string for the first event.
	PrevHash string `json:"prev_hash"`

	// Hash is the SHA-256 hash of this event (excluding the hash field itself).
	// Computed by ComputeHash after all other fields are set.
	Hash string `json:"hash"`
}

// EventDecision is the policy engine's verdict, recorded in the audit event.
type EventDecision struct {
	// Action is "allow", "deny", or "log".
	Action string `json:"action"`

	// MatchedPolicies lists which policies matched the tool call.
	MatchedPolicies []string `json:"matched_policies,omitempty"`

	// EvalTimeUS is the policy evaluation duration in microseconds.
	EvalTimeUS int64 `json:"evaluation_time_us"`

	// Message is the human-readable reason for the decision.
	Message string `json:"message,omitempty"`
}

// ToolResponse captures the result of an allowed tool call.
type ToolResponse struct {
	// ExitCode is the process exit code (for exec calls).
	ExitCode *int `json:"exit_code,omitempty"`

	// DurationMS is how long the tool call took to execute.
	DurationMS int64 `json:"duration_ms"`

	// Flags contains any post-execution annotations (e.g., "credential-detected").
	Flags []string `json:"flags,omitempty"`
}

// ComputeHash calculates the SHA-256 hash for this event.
//
// The hash covers all fields EXCEPT the Hash field itself. This is done by
// temporarily clearing Hash, marshaling to JSON, computing SHA-256, and
// restoring the field.
//
// The hash incorporates PrevHash, creating the chain:
//
//	hash(event_N) = SHA-256(prev_hash + json(event_N without hash))
func (e *Event) ComputeHash() error {
	saved := e.Hash
	e.Hash = ""
	defer func() { e.Hash = saved }()

	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: marshal event for hashing: %w", err)
	}

	// Prepend prev_hash to create the chain linkage.
	payload := append([]byte(e.PrevHash), data...)

	h := sha256.Sum256(payload)
	e.Hash = "sha256:" + hex.EncodeToString(h[:])

	// Set the computed value (we deferred restoring the saved value,
	// but we actually want the new hash).
	saved = e.Hash
	return nil
}

// VerifyHash checks whether the event's hash is correct.
// Returns true if the hash matches the computed value.
func (e *Event) VerifyHash() (bool, error) {
	expected := e.Hash

	if err := e.ComputeHash(); err != nil {
		return false, err
	}
	computed := e.Hash
	e.Hash = expected

	return subtle.ConstantTimeCompare([]byte(computed), []byte(expected)) == 1, nil
}

// ChainAnchor records the hash chain state at a checkpoint.
// Written to a separate file every N events as a tamper-detection anchor.
type ChainAnchor struct {
	// EventID is the ULID of the event at this checkpoint.
	EventID string `json:"event_id"`

	// Hash is the chain head hash at this checkpoint.
	Hash string `json:"hash"`

	// EventCount is the total number of events written up to this point.
	EventCount int64 `json:"event_count"`

	// Timestamp is when this anchor was written.
	Timestamp time.Time `json:"timestamp"`

	// File is the audit log file this anchor references.
	File string `json:"file"`
}
