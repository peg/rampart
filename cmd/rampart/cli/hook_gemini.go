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

	params, policyPaths, err := normalizeGeminiParams(input.ToolName, input.ToolInput, event == "BeforeTool")
	if err != nil {
		return nil, err
	}
	if tool == "mcp" {
		tool = classifyNativeMCPTool(input.ToolName, params)
	}
	result := &hookParseResult{
		Tool:          tool,
		Params:        params,
		PolicyPaths:   policyPaths,
		WorkDir:       strings.TrimSpace(input.CWD),
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
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(toolName)), "mcp_") {
		return classifyNativeMCPTool(toolName, nil)
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

func normalizeGeminiParams(toolName string, input map[string]any, enforce bool) (map[string]any, []string, error) {
	params := make(map[string]any, len(input)+1)
	for key, value := range input {
		params[key] = value
	}
	if enforce {
		if err := validateGeminiActionParams(toolName, params); err != nil {
			return nil, nil, err
		}
	} else {
		if path, ok := params["file_path"].(string); ok && strings.TrimSpace(path) != "" {
			params["path"] = path
		}
		if _, exists := params["path"]; !exists {
			if path, ok := params["dir_path"].(string); ok && strings.TrimSpace(path) != "" {
				params["path"] = path
			}
		}
		switch toolName {
		case "web_fetch":
			if prompt, ok := params["prompt"].(string); ok {
				params["url"] = prompt
			}
		case "google_web_search":
			if query, ok := params["query"].(string); ok {
				params["url"] = query
			}
		}
	}
	if toolName == "read_many_files" {
		if !enforce {
			return params, nil, nil
		}
		seen := make(map[string]struct{})
		paths := make([]string, 0, 4)
		add := func(path string) error {
			path = strings.TrimSpace(path)
			if path == "" {
				return nil
			}
			if _, exists := seen[path]; exists {
				return nil
			}
			if len(paths) >= maxCodexPatchPaths {
				return fmt.Errorf("hook: Gemini read_many_files includes more than %d paths; split it into smaller calls", maxCodexPatchPaths)
			}
			seen[path] = struct{}{}
			paths = append(paths, path)
			return nil
		}
		switch includes := params["include"].(type) {
		case string:
			if err := add(includes); err != nil {
				return nil, nil, err
			}
		case []any:
			for _, raw := range includes {
				path, ok := raw.(string)
				if !ok {
					return nil, nil, fmt.Errorf("hook: Gemini read_many_files include entries must be strings")
				}
				if err := add(path); err != nil {
					return nil, nil, err
				}
			}
		default:
			return nil, nil, fmt.Errorf("hook: Gemini read_many_files requires include paths")
		}
		if len(paths) == 0 {
			return nil, nil, fmt.Errorf("hook: Gemini read_many_files requires at least one include path")
		}
		params["path"] = paths[0]
		params["paths"] = append([]string(nil), paths...)
		return params, paths, nil
	}
	return params, nil, nil
}

// validateGeminiActionParams rejects recognized pre-call actions whose
// security-bearing fields are absent or type-confused. AfterTool payloads are
// intentionally accepted so response scanning survives upstream schema drift.
func validateGeminiActionParams(toolName string, params map[string]any) error {
	context := "hook: Gemini " + toolName
	switch mapGeminiTool(toolName) {
	case "exec":
		_, err := requireHookStringAliases(params, "command", context, "command")
		return err
	case "read", "write":
		_, found, err := normalizeHookStringAliases(params, "path", context, "file path", "file_path", "dir_path")
		if err != nil {
			return err
		}
		switch toolName {
		case "write_file", "replace", "read_file":
			if !found {
				return fmt.Errorf("%s requires a non-empty file path", context)
			}
		}
		return nil
	case "fetch":
		switch toolName {
		case "web_fetch":
			_, err := requireHookStringAliases(params, "url", context, "URL or query", "prompt")
			return err
		case "google_web_search":
			_, err := requireHookStringAliases(params, "url", context, "URL or query", "query")
			return err
		}
	}
	return nil
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
