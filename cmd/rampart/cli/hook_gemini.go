// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// geminiHookInput is the documented Gemini CLI BeforeTool/AfterTool payload.
// Gemini does not currently expose a stable tool-call ID in this protocol, so
// session identity is preserved but ToolUseID intentionally remains empty.
type geminiHookInput struct {
	SessionID      string         `json:"session_id"`
	TranscriptPath string         `json:"transcript_path,omitempty"`
	CWD            string         `json:"cwd,omitempty"`
	HookEventName  string         `json:"hook_event_name"`
	ToolName       string         `json:"tool_name"`
	ToolInput      map[string]any `json:"tool_input"`
	ToolResponse   map[string]any `json:"tool_response,omitempty"`
}

type geminiHookOutput struct {
	Decision string `json:"decision,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

func parseGeminiInput(reader io.Reader) (*hookParseResult, error) {
	var input geminiHookInput
	if err := json.NewDecoder(reader).Decode(&input); err != nil {
		return nil, err
	}
	event := strings.TrimSpace(input.HookEventName)
	if event != "BeforeTool" && event != "AfterTool" {
		return nil, fmt.Errorf("hook: unsupported Gemini hook_event_name %q", input.HookEventName)
	}
	tool := mapGeminiTool(input.ToolName)
	if event == "BeforeTool" && tool == "unknown" {
		return nil, fmt.Errorf("hook: unsupported Gemini tool_name %q; update Rampart before allowing this tool", input.ToolName)
	}

	params := normalizeGeminiParams(input.ToolName, input.ToolInput)
	result := &hookParseResult{
		Tool:          tool,
		Params:        params,
		Agent:         "gemini-cli",
		RunID:         deriveRunID(input.SessionID),
		HookEventName: event,
		SessionID:     input.SessionID,
	}
	if len(input.ToolResponse) > 0 {
		result.Response = extractToolResponse(input.ToolResponse)
		result.RawResponse = input.ToolResponse
	}
	return result, nil
}

func mapGeminiTool(toolName string) string {
	if strings.HasPrefix(toolName, "mcp_") {
		return "mcp"
	}
	switch toolName {
	case "run_shell_command", "shell":
		return "exec"
	case "read_file", "read_many_files", "glob", "grep_search", "list_directory",
		"search_file_content", "list_mcp_resources", "read_mcp_resource", "get_internal_docs", "activate_skill",
		"tracker_get_task", "tracker_list_tasks", "tracker_visualize":
		return "read"
	case "write_file", "replace":
		return "write"
	case "web_fetch", "google_web_search":
		return "fetch"
	case "save_memory":
		return "memory"
	case "delegate_to_agent":
		return "agent"
	case "write_todos", "tracker_create_task", "tracker_update_task", "tracker_add_dependency":
		return "process"
	case "ask_user", "complete_task", "enter_plan_mode", "exit_plan_mode", "update_topic":
		return "interact"
	default:
		return "unknown"
	}
}

func normalizeGeminiParams(toolName string, input map[string]any) map[string]any {
	params := make(map[string]any, len(input)+1)
	for key, value := range input {
		params[key] = value
	}
	if path, ok := params["file_path"].(string); ok && strings.TrimSpace(path) != "" {
		params["path"] = path
	}
	if _, exists := params["path"]; !exists {
		if path, ok := params["dir_path"].(string); ok && strings.TrimSpace(path) != "" {
			params["path"] = path
		}
	}
	if toolName == "read_many_files" {
		switch includes := params["include"].(type) {
		case string:
			params["path"] = includes
		case []any:
			for _, raw := range includes {
				if path, ok := raw.(string); ok && strings.TrimSpace(path) != "" {
					params["path"] = path
					break
				}
			}
		}
	}
	if toolName == "web_fetch" {
		if prompt, ok := params["prompt"].(string); ok {
			params["url"] = prompt
		}
	}
	if toolName == "google_web_search" {
		if query, ok := params["query"].(string); ok {
			params["url"] = query
		}
	}
	return params
}

func outputGeminiHookResult(cmdOutput io.Writer, decision hookDecisionType, reason string) error {
	out := geminiHookOutput{}
	switch decision {
	case hookDeny, hookBlock:
		out.Decision = "deny"
		out.Reason = "Rampart: " + reason
	case hookAsk:
		// Gemini's hook protocol has no native ask result. Empty output would
		// not guarantee a user prompt for every tool, so fail closed.
		out.Decision = "deny"
		out.Reason = "Rampart: approval required — " + reason
	case hookAllow:
		// Empty JSON preserves Gemini's own permission and sandbox checks.
	}
	return json.NewEncoder(cmdOutput).Encode(out)
}
