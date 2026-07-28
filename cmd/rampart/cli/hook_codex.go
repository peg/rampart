// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/peg/rampart/internal/engine"
	"github.com/spf13/cobra"
)

// codexHookInput is the stable lifecycle-hook payload shared by Codex CLI,
// the IDE extension, and the desktop app.
type codexHookInput struct {
	SessionID      string          `json:"session_id"`
	TurnID         string          `json:"turn_id,omitempty"`
	AgentID        string          `json:"agent_id,omitempty"`
	AgentType      string          `json:"agent_type,omitempty"`
	TranscriptPath *string         `json:"transcript_path"`
	CWD            string          `json:"cwd"`
	HookEventName  string          `json:"hook_event_name"`
	Model          string          `json:"model,omitempty"`
	PermissionMode string          `json:"permission_mode,omitempty"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ToolResponse   json.RawMessage `json:"tool_response,omitempty"`
	ToolUseID      string          `json:"tool_use_id,omitempty"`
}

const maxCodexPatchPaths = 100

func parseCodexInput(reader io.Reader) (*hookParseResult, error) {
	var input codexHookInput
	if err := json.NewDecoder(reader).Decode(&input); err != nil {
		return nil, err
	}
	if input.HookEventName != "PreToolUse" && input.HookEventName != "PostToolUse" {
		return nil, fmt.Errorf("hook: unsupported Codex event %q", input.HookEventName)
	}
	if strings.TrimSpace(input.ToolName) == "" {
		return nil, fmt.Errorf("hook: Codex tool_name is required")
	}
	if strings.TrimSpace(input.SessionID) == "" {
		return nil, fmt.Errorf("hook: Codex session_id is required")
	}
	if strings.TrimSpace(input.ToolUseID) == "" {
		return nil, fmt.Errorf("hook: Codex tool_use_id is required")
	}
	if err := validateToolUseID(input.ToolUseID); err != nil {
		return nil, err
	}

	params, err := decodeCodexToolInput(input.ToolInput)
	if err != nil {
		return nil, err
	}
	mappedTool := mapCodexTool(input.ToolName)
	// Codex adds tool surfaces over time. A newly hook-visible action must not
	// inherit the policy's unmatched/default behavior before Rampart knows its
	// security consequence. Deny the pre-call through the normal parse-failure
	// protocol in enforce mode; monitor/audit modes remain observational.
	if input.HookEventName == "PreToolUse" && mappedTool == "unknown" {
		return nil, fmt.Errorf(
			"hook: unsupported Codex tool_name %q; update Rampart before allowing this tool",
			input.ToolName,
		)
	}
	result := &hookParseResult{
		Tool:          mappedTool,
		Params:        params,
		Agent:         "codex",
		RunID:         deriveRunID(input.SessionID),
		HookEventName: input.HookEventName,
		SessionID:     input.SessionID,
		ToolUseID:     input.ToolUseID,
	}
	if strings.EqualFold(strings.TrimSpace(input.ToolName), "apply_patch") {
		command, _ := params["command"].(string)
		result.PolicyPaths, err = extractCodexPatchPaths(command)
		if err != nil {
			return nil, err
		}
		if len(result.PolicyPaths) > 0 {
			params["paths"] = append([]string(nil), result.PolicyPaths...)
		}
	}

	if input.HookEventName == "PostToolUse" {
		result.Response, err = decodeCodexToolResponse(input.ToolResponse)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

// extractCodexPatchPaths returns every file target in Codex's apply_patch
// envelope. Evaluating all targets independently prevents a protected file
// later in a multi-file patch from hiding behind an allowed first target.
func extractCodexPatchPaths(patch string) ([]string, error) {
	prefixes := []string{
		"*** Add File:",
		"*** Update File:",
		"*** Delete File:",
		"*** Move to:",
	}
	seen := make(map[string]struct{})
	var paths []string
	for _, line := range strings.Split(patch, "\n") {
		line = strings.TrimSuffix(line, "\r")
		for _, prefix := range prefixes {
			if !strings.HasPrefix(line, prefix) {
				continue
			}
			path := strings.TrimSpace(strings.TrimPrefix(line, prefix))
			if path == "" || strings.IndexByte(path, 0) >= 0 {
				return nil, fmt.Errorf("hook: Codex apply_patch contains an invalid file target")
			}
			if _, exists := seen[path]; !exists {
				seen[path] = struct{}{}
				paths = append(paths, path)
				if len(paths) > maxCodexPatchPaths {
					return nil, fmt.Errorf(
						"hook: Codex apply_patch touches more than %d paths; split it into smaller calls",
						maxCodexPatchPaths,
					)
				}
			}
			break
		}
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("hook: Codex apply_patch contains no recognized file targets")
	}
	return paths, nil
}

// evaluateHookCall applies a batched write as a set of indivisible path
// decisions. The most restrictive result wins, so every target must be
// permitted for the host tool call to proceed.
func evaluateHookCall(eng *engine.Engine, call engine.ToolCall, policyPaths []string) (engine.ToolCall, engine.Decision) {
	if len(policyPaths) == 0 {
		return call, eng.EvaluateAndConsume(call, engine.EvalOptions{})
	}

	selectedCall := call
	selectedDecision := engine.Decision{Action: engine.ActionAllow}
	selectedRank := -1
	for _, path := range policyPaths {
		pathCall := call
		pathCall.Params = cloneHookParams(call.Params)
		pathCall.Input = pathCall.Params
		pathCall.Params["path"] = path

		// Claim each one-time allowance before considering the next path. This
		// can conservatively consume an earlier allowance when a later path is
		// denied, but it can never over-authorize a batched write.
		decision := eng.EvaluateAndConsume(pathCall, engine.EvalOptions{})
		rank := hookDecisionRank(decision.Action)
		if rank > selectedRank {
			selectedCall = pathCall
			selectedDecision = decision
			selectedRank = rank
		}
		if decision.Action == engine.ActionDeny {
			break
		}
	}
	return selectedCall, selectedDecision
}

func cloneHookParams(params map[string]any) map[string]any {
	cloned := make(map[string]any, len(params)+1)
	for key, value := range params {
		cloned[key] = value
	}
	return cloned
}

func hookDecisionRank(action engine.Action) int {
	switch action {
	case engine.ActionDeny:
		return 6
	case engine.ActionWebhook:
		return 5
	case engine.ActionRequireApproval:
		return 4
	case engine.ActionAsk:
		return 3
	case engine.ActionWatch:
		return 2
	case engine.ActionAllow:
		return 1
	default:
		return 0
	}
}

func decodeCodexToolInput(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return map[string]any{}, nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("hook: decode Codex tool_input: %w", err)
	}
	if params, ok := value.(map[string]any); ok {
		return params, nil
	}
	return map[string]any{"input": value}, nil
}

func decodeCodexToolResponse(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("hook: decode Codex tool_response: %w", err)
	}
	switch response := value.(type) {
	case string:
		return response, nil
	case map[string]any:
		if text := extractToolResponse(response); text != "" {
			return text, nil
		}
	}
	data, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("hook: encode Codex tool_response: %w", err)
	}
	return string(data), nil
}

func mapCodexTool(toolName string) string {
	switch strings.ToLower(strings.TrimSpace(toolName)) {
	case "bash", "shell", "shell_command", "exec_command", "code_execution":
		return "exec"
	case "apply_patch", "edit", "write", "write_file":
		return "write"
	case "read", "view", "read_file":
		return "read"
	case "webfetch", "web_fetch", "browser", "browser_navigate":
		return "fetch"
	case "spawn_agent", "agent":
		return "agent"
	}
	if strings.HasPrefix(strings.ToLower(toolName), "mcp__") {
		return "mcp"
	}
	return "unknown"
}

// resolveCodexApproval uses Rampart's external approval queue because current
// Codex PreToolUse hooks cannot request the native approval UI. Approval is
// resolved inside this exact hook invocation; Codex receives an empty allow
// response afterward so its own sandbox and permission policy remain active.
func resolveCodexApproval(
	cmd *cobra.Command,
	call engine.ToolCall,
	reason string,
	serveURL string,
	serveToken string,
	autoDiscovered bool,
	logger *slog.Logger,
) error {
	return resolveExternalHookApproval(cmd, "codex", call, reason, serveURL, serveToken, autoDiscovered, logger)
}

// resolveExternalHookApproval handles hook protocols that cannot request a
// native user prompt. The exact invocation waits on Rampart's approval queue;
// an approval continues through the host's own sandbox, and an unavailable
// service fails closed.
func resolveExternalHookApproval(
	cmd *cobra.Command,
	format string,
	call engine.ToolCall,
	reason string,
	serveURL string,
	serveToken string,
	autoDiscovered bool,
	logger *slog.Logger,
) error {
	if serveURL == "" || !isServeRunning(serveURL) {
		return outputHookResult(
			cmd,
			format,
			hookDeny,
			false,
			reason+"; approval requires a running Rampart service (`rampart serve`)",
			extractCommand(call),
		)
	}

	command := call.Command()
	if command == "" && call.Path() == "" {
		if data, err := json.Marshal(call.Params); err == nil {
			command = string(data)
		}
	}
	client := &hookApprovalClient{
		serveURL:       strings.TrimRight(serveURL, "/"),
		token:          serveToken,
		logger:         logger,
		autoDiscovered: autoDiscovered,
		// Codex treats stdout as the hook protocol and may surface stderr as
		// a hook failure. Its configured statusMessage provides progress while
		// this call waits in Rampart's approval queue.
		errWriter: io.Discard,
	}
	result := client.requestApprovalCtx(
		cmd.Context(),
		call.Tool,
		command,
		call.Agent,
		call.Path(),
		call.RunID,
		call.ToolCallID,
		reason,
		5*time.Minute,
	)
	if result == hookAsk {
		result = hookDeny
		reason += "; Rampart approval service was unavailable"
	}
	return outputHookResult(cmd, format, result, false, reason, extractCommand(call))
}
