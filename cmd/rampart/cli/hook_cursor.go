// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type cursorHookInput struct {
	ConversationID string          `json:"conversation_id"`
	GenerationID   string          `json:"generation_id"`
	HookEventName  string          `json:"hook_event_name"`
	CWD            string          `json:"cwd"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ToolUseID      string          `json:"tool_use_id"`
}

type cursorHookOutput struct {
	Permission   string `json:"permission,omitempty"`
	UserMessage  string `json:"user_message,omitempty"`
	AgentMessage string `json:"agent_message,omitempty"`
}

func parseCursorInput(reader io.Reader) (*hookParseResult, error) {
	var input cursorHookInput
	if err := json.NewDecoder(reader).Decode(&input); err != nil {
		return nil, err
	}
	if input.HookEventName != "preToolUse" {
		return nil, fmt.Errorf("hook: unsupported Cursor hook_event_name %q", input.HookEventName)
	}
	if strings.TrimSpace(input.ToolName) == "" {
		return nil, fmt.Errorf("hook: Cursor tool_name is required")
	}
	if err := validateToolUseID(input.ToolUseID); err != nil {
		return nil, err
	}
	params, err := decodeCopilotValue(input.ToolInput)
	if err != nil {
		return nil, fmt.Errorf("hook: decode Cursor tool_input: %w", err)
	}
	tool := mapCursorTool(input.ToolName, params)
	if tool == "unknown" {
		return nil, fmt.Errorf("hook: unsupported Cursor tool_name %q; update Rampart before allowing this tool", input.ToolName)
	}
	if err := validateCursorActionParams(input.ToolName, tool, params, input.CWD); err != nil {
		return nil, err
	}
	result := &hookParseResult{
		Tool:          tool,
		Params:        params,
		WorkDir:       strings.TrimSpace(input.CWD),
		Agent:         "cursor",
		RunID:         deriveRunID(input.ConversationID),
		HookEventName: input.HookEventName,
		SessionID:     input.ConversationID,
		ToolUseID:     input.ToolUseID,
	}
	if tool == "write" {
		result.PolicyPaths, err = collectNativeHookPaths(params, "Cursor")
		if err != nil {
			return nil, err
		}
		if len(result.PolicyPaths) == 0 {
			return nil, fmt.Errorf("hook: Cursor %s requires at least one file path", input.ToolName)
		}
		params["path"] = result.PolicyPaths[0]
		params["paths"] = append([]string(nil), result.PolicyPaths...)
	}
	return result, nil
}

func mapCursorTool(toolName string, params map[string]any) string {
	name := strings.TrimSpace(toolName)
	if strings.HasPrefix(strings.ToUpper(name), "MCP:") {
		return classifyNativeMCPTool(name, params)
	}
	switch strings.ToLower(name) {
	case "shell":
		return "exec"
	case "read", "grep", "glob":
		return "read"
	case "write", "edit", "delete":
		return "write"
	case "task":
		return "agent"
	case "webfetch", "websearch", "fetch", "browser", "openurl":
		return "fetch"
	default:
		return "unknown"
	}
}

func validateCursorActionParams(toolName, tool string, params map[string]any, cwd string) error {
	context := "hook: Cursor " + toolName
	switch tool {
	case "exec":
		_, err := requireHookStringAliases(params, "command", context, "command", "cmd", "script", "code", "input")
		return err
	case "read":
		if strings.EqualFold(toolName, "grep") || strings.EqualFold(toolName, "glob") {
			if _, err := requireHookStringAliases(params, "pattern", context, "search pattern", "query"); err != nil {
				return err
			}
		}
		path, found, err := normalizeHookStringAliases(params, "path", context, "file path", "filePath", "file_path", "uri", "directory")
		if err != nil {
			return err
		}
		if !found && (strings.EqualFold(toolName, "grep") || strings.EqualFold(toolName, "glob")) {
			if strings.TrimSpace(cwd) == "" {
				return fmt.Errorf("%s requires a file path or working directory", context)
			}
			params["path"] = strings.TrimSpace(cwd)
			path = strings.TrimSpace(cwd)
			found = true
		}
		if !found || path == "" {
			return fmt.Errorf("%s requires a file path", context)
		}
	case "write", "mcp-destructive":
		_, _, err := normalizeHookStringAliases(params, "path", context, "file path", "filePath", "file_path", "uri")
		return err
	case "fetch":
		_, err := requireHookStringAliases(params, "url", context, "URL or query", "uri", "href", "query")
		return err
	}
	return nil
}

func outputCursorHookResult(writer io.Writer, decision hookDecisionType, reason string) error {
	out := cursorHookOutput{}
	switch decision {
	case hookDeny, hookBlock:
		out.Permission = "deny"
		out.UserMessage = "Rampart: " + reason
		out.AgentMessage = "Rampart: " + reason
	case hookAsk:
		// Cursor accepts "ask" in the schema but does not enforce it for
		// preToolUse. Approval calls must resolve through rampart serve first.
		out.Permission = "deny"
		out.UserMessage = "Rampart: approval required — " + reason
		out.AgentMessage = out.UserMessage
	case hookAllow:
		// Empty JSON preserves Cursor's own permission and sandbox decisions.
	}
	return json.NewEncoder(writer).Encode(out)
}
