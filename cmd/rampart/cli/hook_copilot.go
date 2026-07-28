// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// copilotHookInput is the PascalCase PreToolUse/PostToolUse payload shared by
// Copilot CLI's VS Code-compatible mode and the VS Code Copilot agent host.
type copilotHookInput struct {
	HookEventName string          `json:"hook_event_name"`
	SessionID     string          `json:"session_id"`
	CWD           string          `json:"cwd,omitempty"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
	ToolUseID     string          `json:"tool_use_id,omitempty"`
	ToolResult    json.RawMessage `json:"tool_result,omitempty"`
	ToolResponse  json.RawMessage `json:"tool_response,omitempty"`
}

type copilotHookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
	AdditionalContext        string `json:"additionalContext,omitempty"`
}

type copilotModifiedResult struct {
	ResultType       string `json:"resultType"`
	TextResultForLLM string `json:"textResultForLlm"`
}

type copilotHookOutput struct {
	// Copilot CLI consumes the top-level preToolUse fields.
	PermissionDecision       string `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
	// VS Code consumes hookSpecificOutput for PreToolUse.
	HookSpecificOutput *copilotHookSpecificOutput `json:"hookSpecificOutput,omitempty"`
	// Copilot CLI PostToolUse response controls.
	ModifiedResult    *copilotModifiedResult `json:"modifiedResult,omitempty"`
	AdditionalContext string                 `json:"additionalContext,omitempty"`
	// VS Code PostToolUse response controls.
	Decision string `json:"decision,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

func parseCopilotInput(reader io.Reader) (*hookParseResult, error) {
	var input copilotHookInput
	if err := json.NewDecoder(reader).Decode(&input); err != nil {
		return nil, err
	}
	event := strings.TrimSpace(input.HookEventName)
	if event != "PreToolUse" && event != "PostToolUse" {
		return nil, fmt.Errorf("hook: unsupported Copilot hook_event_name %q", input.HookEventName)
	}
	if strings.TrimSpace(input.ToolName) == "" {
		return nil, fmt.Errorf("hook: Copilot tool_name is required")
	}
	if err := validateToolUseID(input.ToolUseID); err != nil {
		return nil, err
	}

	params, err := decodeCopilotValue(input.ToolInput)
	if err != nil {
		return nil, fmt.Errorf("hook: decode Copilot tool_input: %w", err)
	}
	tool := mapCopilotTool(input.ToolName)
	if event == "PreToolUse" && tool == "unknown" {
		return nil, fmt.Errorf("hook: unsupported Copilot tool_name %q; update Rampart before allowing this tool", input.ToolName)
	}
	normalizeCopilotParams(params)
	if tool == "mcp" {
		tool = classifyNativeMCPTool(input.ToolName, params)
	}

	result := &hookParseResult{
		Tool:          tool,
		Params:        params,
		WorkDir:       strings.TrimSpace(input.CWD),
		Agent:         "github-copilot",
		RunID:         deriveRunID(input.SessionID),
		HookEventName: event,
		SessionID:     input.SessionID,
		ToolUseID:     input.ToolUseID,
	}
	if tool == "write" {
		result.PolicyPaths, err = collectCopilotPaths(params)
		if err != nil {
			return nil, err
		}
		if len(result.PolicyPaths) > 0 {
			params["path"] = result.PolicyPaths[0]
			params["paths"] = append([]string(nil), result.PolicyPaths...)
		}
	}
	if event == "PostToolUse" {
		raw := input.ToolResult
		if len(raw) == 0 || string(raw) == "null" {
			raw = input.ToolResponse
		}
		response, rawResponse, decodeErr := decodeCopilotResponse(raw)
		if decodeErr != nil {
			return nil, decodeErr
		}
		result.Response = response
		result.RawResponse = rawResponse
	}
	return result, nil
}

func decodeCopilotValue(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return map[string]any{}, nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	if params, ok := value.(map[string]any); ok {
		return params, nil
	}
	return map[string]any{"input": value}, nil
}

func decodeCopilotResponse(raw json.RawMessage) (string, map[string]any, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil, nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", nil, fmt.Errorf("hook: decode Copilot tool response: %w", err)
	}
	switch typed := value.(type) {
	case string:
		return typed, map[string]any{"output": typed}, nil
	case map[string]any:
		text := extractToolResponse(typed)
		if text == "" {
			encoded, _ := json.Marshal(typed)
			text = string(encoded)
		}
		return text, typed, nil
	default:
		encoded, _ := json.Marshal(value)
		return string(encoded), map[string]any{"output": value}, nil
	}
}

func mapCopilotTool(toolName string) string {
	name := strings.ToLower(strings.TrimSpace(toolName))
	compact := strings.NewReplacer("_", "", "-", "", ".", "", "/", "", " ", "").Replace(name)
	switch compact {
	case "bash", "powershell", "runshellcommand", "runterminalcommand", "terminal", "executecommand", "codeexecution":
		return "exec"
	case "read", "view", "readfile", "readmanyfiles", "getterminaloutput", "glob", "grep", "rg", "filesearch", "textsearch", "semanticsearch", "listdirectory", "problems", "usages", "changes":
		return "read"
	case "write", "create", "edit", "strreplaceeditor", "applypatch", "createfile", "editfiles", "replace", "replaceinfile", "replacestringinfile", "deletefile", "movefile", "renamefile", "notebookedit":
		return "write"
	case "webfetch", "websearch", "fetch", "browser", "openurl":
		return "fetch"
	case "task", "agent", "subagent", "delegate", "delegatetoagent":
		return "agent"
	case "todowrite", "updatetodo", "runtask":
		return "process"
	case "askuser", "askuserquestion", "enterplanmode", "exitplanmode":
		return "interact"
	}
	switch {
	case strings.Contains(compact, "mcp"):
		return classifyNativeMCPTool(toolName, nil)
	case strings.Contains(compact, "terminal") || strings.Contains(compact, "shell") || strings.HasSuffix(compact, "command"):
		return "exec"
	case strings.Contains(compact, "create") || strings.Contains(compact, "write") || strings.Contains(compact, "edit") || strings.Contains(compact, "replace") || strings.Contains(compact, "delete") || strings.Contains(compact, "patch"):
		return "write"
	case strings.Contains(compact, "read") || strings.Contains(compact, "view") || strings.Contains(compact, "search") || strings.Contains(compact, "grep") || strings.Contains(compact, "glob") || strings.Contains(compact, "list"):
		return "read"
	case strings.Contains(compact, "fetch") || strings.Contains(compact, "browser") || strings.Contains(compact, "web"):
		return "fetch"
	case strings.Contains(compact, "agent") || strings.Contains(compact, "delegate"):
		return "agent"
	default:
		return "unknown"
	}
}

func normalizeCopilotParams(params map[string]any) {
	copyAlias := func(destination string, sources ...string) {
		if _, exists := params[destination]; exists {
			return
		}
		for _, source := range sources {
			if value, ok := params[source]; ok {
				params[destination] = value
				return
			}
		}
	}
	copyAlias("command", "cmd", "script", "terminalCommand")
	copyAlias("path", "filePath", "file_path", "uri", "directory", "dirPath", "dir_path")
	copyAlias("url", "uri", "href")
	if command, ok := params["input"].(string); ok {
		if _, exists := params["command"]; !exists {
			params["command"] = command
		}
	}
}

func collectCopilotPaths(params map[string]any) ([]string, error) {
	seen := make(map[string]struct{})
	paths := make([]string, 0, 4)
	add := func(value string) error {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil
		}
		if _, exists := seen[value]; exists {
			return nil
		}
		if len(paths) >= maxCodexPatchPaths {
			return fmt.Errorf("hook: Copilot write touches more than %d paths; split it into smaller calls", maxCodexPatchPaths)
		}
		seen[value] = struct{}{}
		paths = append(paths, value)
		return nil
	}
	for _, key := range []string{"path", "filePath", "file_path", "uri"} {
		if value, ok := params[key].(string); ok {
			if err := add(value); err != nil {
				return nil, err
			}
		}
	}
	for _, key := range []string{"files", "paths"} {
		items, _ := params[key].([]any)
		for _, item := range items {
			switch typed := item.(type) {
			case string:
				if err := add(typed); err != nil {
					return nil, err
				}
			case map[string]any:
				for _, nestedKey := range []string{"path", "filePath", "file_path", "uri"} {
					if value, ok := typed[nestedKey].(string); ok {
						if err := add(value); err != nil {
							return nil, err
						}
					}
				}
			}
		}
	}
	return paths, nil
}

func outputCopilotHookResult(writer io.Writer, decision hookDecisionType, reason string) error {
	out := copilotHookOutput{}
	switch decision {
	case hookDeny:
		out.PermissionDecision = "deny"
		out.PermissionDecisionReason = "Rampart: " + reason
		out.HookSpecificOutput = &copilotHookSpecificOutput{
			HookEventName: "PreToolUse", PermissionDecision: "deny", PermissionDecisionReason: "Rampart: " + reason,
		}
	case hookAsk:
		out.PermissionDecision = "ask"
		out.PermissionDecisionReason = "Rampart: " + reason
		out.HookSpecificOutput = &copilotHookSpecificOutput{
			HookEventName: "PreToolUse", PermissionDecision: "ask", PermissionDecisionReason: "Rampart: " + reason,
		}
	case hookBlock:
		message := "Rampart blocked this tool response: " + reason
		out.ModifiedResult = &copilotModifiedResult{ResultType: "success", TextResultForLLM: redactedToolOutput}
		out.AdditionalContext = message
		out.Decision = "block"
		out.Reason = message
		out.HookSpecificOutput = &copilotHookSpecificOutput{HookEventName: "PostToolUse", AdditionalContext: message}
	case hookAllow:
		// Empty JSON preserves Copilot CLI and VS Code's native permission and
		// sandbox decisions instead of auto-approving the tool.
	}
	return json.NewEncoder(writer).Encode(out)
}
