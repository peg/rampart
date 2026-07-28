// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// antigravityHookInput is Antigravity's documented camelCase PreToolUse
// payload. PostToolUse intentionally is not installed: Antigravity currently
// omits the completed tool call and result from that event, so it cannot support
// Rampart's response scanning or reliable audit correlation.
type antigravityHookInput struct {
	ToolCall              antigravityToolCall `json:"toolCall"`
	StepIndex             int                 `json:"stepIdx"`
	ConversationID        string              `json:"conversationId"`
	WorkspacePaths        []string            `json:"workspacePaths,omitempty"`
	TranscriptPath        string              `json:"transcriptPath,omitempty"`
	ArtifactDirectoryPath string              `json:"artifactDirectoryPath,omitempty"`
}

type antigravityToolCall struct {
	Name string         `json:"name"`
	Args map[string]any `json:"args"`
}

type antigravityHookOutput struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
}

func parseAntigravityInput(reader io.Reader) (*hookParseResult, error) {
	var input antigravityHookInput
	if err := json.NewDecoder(reader).Decode(&input); err != nil {
		return nil, err
	}
	toolName := strings.TrimSpace(input.ToolCall.Name)
	if toolName == "" {
		return nil, fmt.Errorf("hook: Antigravity toolCall.name is required")
	}
	tool := mapAntigravityTool(toolName)
	if tool == "unknown" {
		return nil, fmt.Errorf("hook: unsupported Antigravity tool name %q; update Rampart before allowing this tool", toolName)
	}

	params := normalizeAntigravityParams(input.ToolCall.Args)
	if tool == "mcp" {
		tool = classifyNativeMCPTool(toolName, params)
	}
	result := &hookParseResult{
		Tool:          tool,
		Params:        params,
		WorkDir:       firstNonEmptyString(input.WorkspacePaths),
		Agent:         "antigravity",
		RunID:         deriveRunID(input.ConversationID),
		HookEventName: "PreToolUse",
		SessionID:     input.ConversationID,
	}
	if tool == "write" {
		policyPaths, err := collectAntigravityPaths(params)
		if err != nil {
			return nil, err
		}
		result.PolicyPaths = policyPaths
		if len(result.PolicyPaths) > 0 {
			params["path"] = result.PolicyPaths[0]
			params["paths"] = append([]string(nil), result.PolicyPaths...)
		}
	}
	return result, nil
}

func mapAntigravityTool(toolName string) string {
	name := strings.ToLower(strings.TrimSpace(toolName))
	if strings.HasPrefix(name, "mcp_") || strings.HasPrefix(name, "mcp.") {
		return classifyNativeMCPTool(toolName, nil)
	}
	switch name {
	case "run_command":
		return "exec"
	case "view_file", "list_dir", "find_by_name", "grep_search", "list_permissions":
		return "read"
	case "write_to_file", "replace_file_content", "multi_replace_file_content":
		return "write"
	case "search_web", "read_url_content", "generate_image":
		return "fetch"
	case "manage_task", "schedule":
		return "process"
	case "invoke_subagent", "define_subagent", "send_message", "manage_subagents":
		return "agent"
	case "ask_permission", "ask_question":
		return "interact"
	default:
		return "unknown"
	}
}

func normalizeAntigravityParams(input map[string]any) map[string]any {
	params := make(map[string]any, len(input)+3)
	for key, value := range input {
		params[key] = value
	}
	copyAlias := func(destination string, aliases ...string) {
		if _, exists := params[destination]; exists {
			return
		}
		for _, alias := range aliases {
			if value, exists := params[alias]; exists {
				params[destination] = value
				return
			}
		}
	}
	copyAlias("command", "CommandLine", "commandLine", "Command", "cmd")
	copyAlias("path", "AbsolutePath", "TargetFile", "FilePath", "filePath", "file_path", "Path", "DirectoryPath", "directoryPath", "SearchDirectory", "SearchPath")
	copyAlias("url", "Url", "URL", "Uri", "URI", "url")
	if _, exists := params["url"]; !exists {
		copyAlias("url", "query")
	}
	return params
}

func collectAntigravityPaths(params map[string]any) ([]string, error) {
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
			return fmt.Errorf("hook: Antigravity write touches more than %d paths; split it into smaller calls", maxCodexPatchPaths)
		}
		seen[value] = struct{}{}
		paths = append(paths, value)
		return nil
	}
	for _, key := range []string{"path", "AbsolutePath", "TargetFile", "FilePath", "filePath", "file_path", "Path"} {
		if value, ok := params[key].(string); ok {
			if err := add(value); err != nil {
				return nil, err
			}
		}
	}
	for _, key := range []string{"paths", "TargetFiles", "Files"} {
		switch values := params[key].(type) {
		case []any:
			for _, raw := range values {
				if value, ok := raw.(string); ok {
					if err := add(value); err != nil {
						return nil, err
					}
				}
			}
		case []string:
			for _, value := range values {
				if err := add(value); err != nil {
					return nil, err
				}
			}
		}
	}
	return paths, nil
}

func outputAntigravityHookResult(writer io.Writer, decision hookDecisionType, reason string) error {
	out := antigravityHookOutput{Decision: "allow"}
	switch decision {
	case hookDeny, hookBlock:
		out.Decision = "deny"
		out.Reason = "Rampart: " + reason
	case hookAsk:
		// force_ask prevents an Antigravity cached "Always Allow" permission
		// from bypassing a Rampart approval rule.
		out.Decision = "force_ask"
		out.Reason = "Rampart: approval required — " + reason
	}
	return json.NewEncoder(writer).Encode(out)
}
