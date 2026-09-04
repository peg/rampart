// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package approval

import (
	"bytes"
	"encoding/json"

	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/internal/notify"
)

// ActionReview is the complete represented action, with credential material
// redacted for operator review. It is display evidence, never a replay token or
// a claim about paths or execution context the host did not supply.
type ActionReview struct {
	Version    int            `json:"version"`
	Tool       string         `json:"tool"`
	Agent      string         `json:"agent,omitempty"`
	AgentDepth int            `json:"agent_depth,omitempty"`
	Session    string         `json:"session,omitempty"`
	RunID      string         `json:"run_id,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
	WorkDir    string         `json:"workdir,omitempty"`
	Params     map[string]any `json:"params"`
	Input      map[string]any `json:"input,omitempty"`
}

// ReviewCall preserves every represented parameter instead of extracting a
// command prefix or first path. Shared audit redaction runs before this value
// reaches an API, dashboard, terminal, or native approval transport.
func ReviewCall(call engine.ToolCall) ActionReview {
	return ActionReview{
		Version:    1,
		Tool:       notify.SanitizeCommand(call.Tool),
		Agent:      notify.SanitizeCommand(call.Agent),
		AgentDepth: call.AgentDepth,
		Session:    notify.SanitizeCommand(call.Session),
		RunID:      notify.SanitizeCommand(call.RunID),
		ToolCallID: notify.SanitizeCommand(call.ToolCallID),
		WorkDir:    notify.SanitizeCommand(call.WorkingDirectory()),
		Params:     audit.RedactEvent(audit.Event{Request: call.Params}).Request,
		Input:      audit.RedactEvent(audit.Event{Request: call.Input}).Request,
	}
}

// snapshotCall serializes caller-owned values once before deriving either
// authorization or display. UseNumber preserves exact JSON numeric values.
func snapshotCall(call engine.ToolCall) (engine.ToolCall, []byte, error) {
	encoded, err := json.Marshal(call)
	if err != nil {
		return engine.ToolCall{}, nil, err
	}
	var snapshot engine.ToolCall
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&snapshot); err != nil {
		return engine.ToolCall{}, nil, err
	}
	return snapshot, encoded, nil
}

func redactedCall(call engine.ToolCall) (engine.ToolCall, bool, error) {
	snapshot, encoded, err := snapshotCall(call)
	if err != nil {
		return engine.ToolCall{}, false, err
	}
	return redactCallSnapshot(snapshot, encoded)
}

// redactCallSnapshot only accepts the fixed snapshot captured above. It never
// consults the caller's maps or invokes their JSON marshalers a second time.
func redactCallSnapshot(snapshot engine.ToolCall, encoded []byte) (engine.ToolCall, bool, error) {
	review := ReviewCall(snapshot)
	snapshot.Tool, snapshot.Agent = review.Tool, review.Agent
	snapshot.Session, snapshot.RunID, snapshot.ToolCallID = review.Session, review.RunID, review.ToolCallID
	snapshot.WorkDir = notify.SanitizeCommand(snapshot.WorkDir)
	snapshot.Params, snapshot.Input = review.Params, review.Input
	redacted, err := json.Marshal(snapshot)
	return snapshot, string(encoded) != string(redacted), err
}

// cloneReviewMap copies the already-redacted private snapshot. Creation and
// journal decoding normalize this data through JSON, so values are only JSON
// maps, arrays and immutable scalars. Do not rerun redaction on every Get/List.
func cloneReviewMap(values map[string]any) map[string]any {
	if values == nil {
		return nil
	}
	out := make(map[string]any, len(values))
	for key, value := range values {
		out[key] = cloneReviewValue(value)
	}
	return out
}

func cloneReviewValue(value any) any {
	switch value := value.(type) {
	case map[string]any:
		return cloneReviewMap(value)
	case []any:
		out := make([]any, len(value))
		for i, item := range value {
			out[i] = cloneReviewValue(item)
		}
		return out
	default:
		return value
	}
}

// Run authority must never be reconstructed from a redaction marker. Keep
// individually approved requests usable, but withhold future authority when
// its displayed grouping identity differs from the original host identity.
func runScopeChangedByRedaction(original, review engine.ToolCall) bool {
	return original.Agent != review.Agent || original.Session != review.Session || original.RunID != review.RunID
}
