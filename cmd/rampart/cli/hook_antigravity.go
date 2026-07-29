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

	params := cloneHookParams(input.ToolCall.Args)
	if tool == "mcp" {
		tool = classifyNativeMCPTool(toolName, params)
	}
	if err := validateAntigravityActionParams(toolName, tool, params); err != nil {
		return nil, err
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
		if len(policyPaths) == 0 {
			return nil, fmt.Errorf("hook: Antigravity %s requires at least one file path", toolName)
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

// validateAntigravityActionParams rejects documented pre-call tools when the
// command, read target, or network target that policy must inspect is missing
// or type-confused. Write paths are validated after collecting the full batch.
func validateAntigravityActionParams(toolName, tool string, params map[string]any) error {
	context := "hook: Antigravity " + toolName
	pathAliases := []string{
		"AbsolutePath", "TargetFile", "FilePath", "filePath", "file_path", "Path",
		"DirectoryPath", "directoryPath", "SearchDirectory", "SearchPath",
	}
	switch tool {
	case "exec":
		_, err := requireHookStringAliases(params, "command", context, "command", "CommandLine", "commandLine", "Command", "cmd")
		return err
	case "read", "write", "mcp", "mcp-destructive":
		_, found, err := normalizeHookStringAliases(params, "path", context, "file path", pathAliases...)
		if err != nil {
			return err
		}
		switch strings.ToLower(strings.TrimSpace(toolName)) {
		case "view_file", "list_dir", "find_by_name", "grep_search":
			if !found {
				return fmt.Errorf("%s requires a non-empty file path", context)
			}
		}
	case "fetch":
		_, found, err := normalizeHookStringAliases(params, "url", context, "URL or query", "Url", "URL", "Uri", "URI", "query")
		if err != nil {
			return err
		}
		switch strings.ToLower(strings.TrimSpace(toolName)) {
		case "search_web", "read_url_content":
			if !found {
				return fmt.Errorf("%s requires a non-empty URL or query", context)
			}
		}
	}
	return nil
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
