// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package approval

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/peg/rampart/internal/engine"
)

const ExternalActionVersion = 1

// ExternalRequest carries the original action to an external approval owner.
// Unlike ActionReview, it is unredacted transport input. Store creation takes
// an immutable snapshot and redacts it before persistence or operator output.
type ExternalRequest struct {
	ActionVersion int            `json:"action_version,omitempty"`
	EventID       string         `json:"event_id,omitempty"`
	Tool          string         `json:"tool"`
	Agent         string         `json:"agent"`
	AgentDepth    int            `json:"agent_depth,omitempty"`
	Session       string         `json:"session,omitempty"`
	RunID         string         `json:"run_id,omitempty"`
	ToolCallID    string         `json:"tool_call_id,omitempty"`
	WorkDir       string         `json:"workdir,omitempty"`
	Params        map[string]any `json:"params"`
	Input         map[string]any `json:"input,omitempty"`
	Message       string         `json:"message"`
	// Command and Path are accepted only for pre-versioned manual clients.
	Command string `json:"command,omitempty"`
	Path    string `json:"path,omitempty"`
}

func NewExternalRequest(call engine.ToolCall, message string) ExternalRequest {
	return ExternalRequest{
		ActionVersion: ExternalActionVersion, EventID: call.ID,
		Tool: call.Tool, Agent: call.Agent, AgentDepth: call.AgentDepth,
		Session: call.Session, RunID: call.RunID, ToolCallID: call.ToolCallID,
		WorkDir: call.WorkDir, Params: call.Params, Input: call.Input, Message: message,
	}
}

// DecodeExternalRequest preserves exact JSON numbers in action identity and
// refuses unknown fields rather than acknowledging a partially understood call.
func DecodeExternalRequest(r io.Reader) (ExternalRequest, error) {
	var req ExternalRequest
	dec := json.NewDecoder(r)
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return req, fmt.Errorf("approval request must contain exactly one JSON object")
	}
	return req, nil
}

func (r ExternalRequest) ToolCall() (engine.ToolCall, error) {
	call := engine.ToolCall{
		ID: r.EventID, Tool: r.Tool, Agent: r.Agent, AgentDepth: r.AgentDepth,
		Session: r.Session, RunID: r.RunID, ToolCallID: r.ToolCallID,
		WorkDir: r.WorkDir, Params: r.Params, Input: r.Input,
	}
	switch r.ActionVersion {
	case ExternalActionVersion:
		if strings.TrimSpace(r.Tool) == "" || strings.TrimSpace(r.Agent) == "" || r.Params == nil || r.AgentDepth < 0 {
			return engine.ToolCall{}, fmt.Errorf("versioned approval requires tool, agent, params and non-negative agent_depth")
		}
		if r.Command != "" || r.Path != "" {
			return engine.ToolCall{}, fmt.Errorf("versioned approval must represent command and path in params")
		}
	case 0:
		if r.Params != nil || r.Input != nil || r.Session != "" || r.WorkDir != "" || r.EventID != "" || r.AgentDepth != 0 {
			return engine.ToolCall{}, fmt.Errorf("complete action fields require action_version=1")
		}
		call.Session = "hook"
		call.Params = map[string]any{}
		if r.Command != "" {
			call.Params["command"] = r.Command
		}
		if r.Path != "" {
			call.Params["path"] = r.Path
		}
	default:
		return engine.ToolCall{}, fmt.Errorf("unsupported approval action_version")
	}
	return call, nil
}
