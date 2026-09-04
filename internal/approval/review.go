// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package approval

import (
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

// redactedCall snapshots JSON input defensively before redaction. Maps passed
// to Create must not remain a way to change the action an operator reviews.
func redactedCall(call engine.ToolCall) (engine.ToolCall, bool, error) {
	encoded, err := json.Marshal(call)
	if err != nil {
		return engine.ToolCall{}, false, err
	}
	var copy engine.ToolCall
	if err := json.Unmarshal(encoded, &copy); err != nil {
		return engine.ToolCall{}, false, err
	}
	review := ReviewCall(copy)
	copy.Tool, copy.Agent = review.Tool, review.Agent
	copy.Session, copy.RunID, copy.ToolCallID = review.Session, review.RunID, review.ToolCallID
	copy.WorkDir = notify.SanitizeCommand(copy.WorkDir)
	copy.Params, copy.Input = review.Params, review.Input
	redacted, err := json.Marshal(copy)
	return copy, string(encoded) != string(redacted), err
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
