// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/engine"
	"github.com/spf13/cobra"
)

// hookInput is the JSON sent by Claude Code on stdin for PreToolUse/PostToolUse hooks.
// PostToolUse includes tool_response (free-form object whose schema varies by tool).
type hookInput struct {
	ToolName     string         `json:"tool_name"`
	ToolInput    map[string]any `json:"tool_input"`
	ToolResponse map[string]any `json:"tool_response,omitempty"`
}

// hookOutput is the JSON response for Claude Code hooks.
// PreToolUse uses hookSpecificOutput; PostToolUse uses top-level decision/reason.
type hookOutput struct {
	Decision           string        `json:"decision,omitempty"`
	Reason             string        `json:"reason,omitempty"`
	HookSpecificOutput *hookDecision `json:"hookSpecificOutput,omitempty"`
}

type hookDecision struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
}

// clineHookInput is the JSON sent by Cline on stdin for PreToolUse hooks.
type clineHookInput struct {
	ClineVersion   string        `json:"clineVersion"`
	HookName       string        `json:"hookName"`
	Timestamp      string        `json:"timestamp"`
	TaskID         string        `json:"taskId"`
	WorkspaceRoots []string      `json:"workspaceRoots"`
	PreToolUse     *clineToolUse `json:"preToolUse"`
	PostToolUse    *clineToolUse `json:"postToolUse"`
}

// clineToolUse represents tool usage in Cline's format.
type clineToolUse struct {
	ToolName   string         `json:"toolName"`
	Parameters map[string]any `json:"parameters"`
}

// clineHookOutput is the JSON response for Cline hooks.
type clineHookOutput struct {
	Cancel              bool   `json:"cancel"`
	ContextModification string `json:"contextModification,omitempty"`
	ErrorMessage        string `json:"errorMessage,omitempty"`
}

// hookParseResult holds the parsed hook input including optional response data.
type hookParseResult struct {
	Tool     string
	Params   map[string]any
	Agent    string
	Response string // non-empty for PostToolUse events
}

func newHookCmd(opts *rootOptions) *cobra.Command {
	var auditDir string
	var mode string
	var format string
	var serveURL string
	var serveToken string
	var configDir string

	cmd := &cobra.Command{
		Use:   "hook",
		Short: "AI agent hook — reads JSON from stdin, returns allow/deny",
		Long: `Integrates with AI agent hook systems for native policy enforcement.

Supports multiple formats:
  --format claude-code (default): Claude Code integration
  --format cline: Cline (VS Code extension) integration

Claude Code setup (add to ~/.claude/settings.json):
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "rampart hook" }]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "rampart hook" }]
      }
    ]
  }
}

Cline setup: Use "rampart setup cline" to install hooks automatically.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Resolve serve-url and serve-token from env if not set via flags.
			serveAutoDiscovered := false
			if serveURL == "" {
				serveURL = os.Getenv("RAMPART_SERVE_URL")
			}
			if serveURL == "" {
				serveURL = "http://localhost:18275"
				serveAutoDiscovered = true
			}
			if cmd.Flags().Changed("serve-token") {
				fmt.Fprintln(os.Stderr, "Warning: --serve-token is visible in process list. Prefer RAMPART_TOKEN env var.")
			}
			if serveToken == "" {
				serveToken = os.Getenv("RAMPART_TOKEN")
			}
			// Auto-read token from ~/.rampart/token when not set via env/flag.
			// This means settings.json never needs to contain credentials —
			// the hook discovers both the URL and the token from standard locations.
			if serveToken == "" {
				if tok, err := readPersistedToken(); err == nil && tok != "" {
					serveToken = tok
				}
			}

			if mode != "enforce" && mode != "monitor" && mode != "audit" {
				return fmt.Errorf("hook: invalid mode %q (must be enforce, monitor, or audit)", mode)
			}
			if format != "claude-code" && format != "cline" {
				return fmt.Errorf("hook: invalid format %q (must be claude-code or cline)", format)
			}

			// Resolve audit directory
			if auditDir == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return fmt.Errorf("hook: resolve home: %w", err)
				}
				auditDir = filepath.Join(home, ".rampart", "audit")
			}
			if err := os.MkdirAll(auditDir, 0o700); err != nil {
				return fmt.Errorf("hook: create audit dir: %w", err)
			}

			// Logger goes to stderr — stdout is for the hook response
			logLevel := slog.LevelWarn
			if opts.verbose {
				logLevel = slog.LevelDebug
			}
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

			// Load policies
			policyPath, cleanupPolicy, err := resolveWrapPolicyPath(opts.configPath)
			if err != nil {
				return err
			}
			defer cleanupPolicy()

			// Build policy store: file, dir, or both.
			var store engine.PolicyStore
			effectiveDir := configDir
			if effectiveDir == "" {
				if home, hErr := os.UserHomeDir(); hErr == nil {
					defaultDir := filepath.Join(home, ".rampart", "policies")
					if _, sErr := os.Stat(defaultDir); sErr == nil {
						effectiveDir = defaultDir
					}
				}
			}
			if effectiveDir != "" {
				store = engine.NewMultiStore(policyPath, effectiveDir, logger)
			} else {
				store = engine.NewFileStore(policyPath)
			}

			eng, err := engine.New(store, logger)
			if err != nil {
				return fmt.Errorf("hook: create engine: %w", err)
			}

			// Audit: append to a daily file so watch can tail it.
			today := time.Now().UTC().Format("2006-01-02")
			auditPath := filepath.Join(auditDir, "audit-hook-"+today+".jsonl")
			auditFile, err := os.OpenFile(auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				return fmt.Errorf("hook: open audit file: %w", err)
			}
			defer auditFile.Close()

			// Parse input based on format
			var parsed *hookParseResult

			switch format {
			case "claude-code":
				parsed, err = parseClaudeCodeInput(os.Stdin, logger)
			case "cline":
				parsed, err = parseClineInput(os.Stdin, logger)
			}
			if err != nil {
				logger.Warn("hook: failed to parse input", "format", format, "error", err)
				// Best-effort audit entry for parse failure. This is written directly
				// to the hook's audit file and is NOT part of the hash chain (the hook
				// command does not maintain chain state). The schema matches the normal
				// audit Event format for consistency with downstream consumers.
				parseFailureEvent := audit.Event{
					ID:        audit.NewEventID(),
					Timestamp: time.Now().UTC(),
					Agent:     format,
					Session:   "hook",
					Tool:      "unknown",
					Request:   map[string]any{"raw_error": err.Error()},
					Decision: audit.EventDecision{
						Action:  "allow",
						Message: fmt.Sprintf("parse failure (format=%s): %v — allowing by default", format, err),
					},
				}
				if line, marshalErr := json.Marshal(parseFailureEvent); marshalErr == nil {
					line = append(line, '\n')
					_, _ = auditFile.Write(line)
				}
				return outputHookResult(cmd, format, hookAllow, false, "", "")
			}

			// Build tool call for evaluation
			call := engine.ToolCall{
				ID:        audit.NewEventID(),
				Agent:     parsed.Agent,
				Session:   "hook",
				Tool:      parsed.Tool,
				Params:    parsed.Params,
				Timestamp: time.Now().UTC(),
			}

			isPostToolUse := parsed.Response != ""

			// Evaluate: for PreToolUse, run command-side policy check.
			// For PostToolUse, run response-side evaluation.
			var decision engine.Decision
			if isPostToolUse {
				decision = eng.EvaluateResponse(call, parsed.Response)
			} else {
				decision = eng.Evaluate(call)
			}

			// Write audit event
			eventDecision := audit.EventDecision{
				Action:          decision.Action.String(),
				MatchedPolicies: decision.MatchedPolicies,
				Message:         decision.Message,
				EvalTimeUS:      decision.EvalDuration.Microseconds(),
			}
			event := audit.Event{
				ID:        call.ID,
				Timestamp: call.Timestamp,
				Agent:     call.Agent,
				Session:   call.Session,
				Tool:      call.Tool,
				Request:   parsed.Params,
				Decision:  eventDecision,
			}
			line, err := json.Marshal(event)
			if err != nil {
				logger.Error("hook: marshal audit event", "error", err)
			} else {
				line = append(line, '\n')
				if _, err := auditFile.Write(line); err != nil {
					logger.Error("hook: audit write failed", "error", err)
				}
			}

			// Send webhook notification if configured
			config, err := store.Load()
			if err != nil {
				logger.Error("hook: failed to reload config for notifications", "error", err)
			} else if config.Notify != nil && config.Notify.URL != "" {
				go sendNotification(config.Notify, call, decision, logger)
			}

			// Return decision
			cmdStr := extractCommand(call)
			if mode != "enforce" {
				return outputHookResult(cmd, format, hookAllow, isPostToolUse, decision.Message, cmdStr)
			}

			switch decision.Action {
			case engine.ActionDeny:
				if isPostToolUse {
					return outputHookResult(cmd, format, hookBlock, true, decision.Message, cmdStr)
				}
				return outputHookResult(cmd, format, hookDeny, false, decision.Message, cmdStr)
			case engine.ActionRequireApproval:
				if serveURL != "" {
					approvalClient := &hookApprovalClient{
						serveURL:       strings.TrimRight(serveURL, "/"),
						token:          serveToken,
						logger:         logger,
						autoDiscovered: serveAutoDiscovered,
					}
					command, _ := call.Params["command"].(string)
					path, _ := call.Params["path"].(string)
					result := approvalClient.requestApprovalCtx(cmd.Context(), call.Tool, command, call.Agent, path, decision.Message, 5*time.Minute)
					return outputHookResult(cmd, format, result, false, decision.Message, cmdStr)
				}
				return outputHookResult(cmd, format, hookAsk, false, decision.Message, cmdStr)
			default:
				return outputHookResult(cmd, format, hookAllow, isPostToolUse, decision.Message, cmdStr)
			}
		},
	}

	cmd.Flags().StringVar(&mode, "mode", "enforce", "Mode: enforce | monitor | audit")
	cmd.Flags().StringVar(&format, "format", "claude-code", "Input format: claude-code | cline")
	cmd.Flags().StringVar(&auditDir, "audit-dir", "", "Directory for audit logs (default: ~/.rampart/audit)")
	cmd.Flags().StringVar(&serveURL, "serve-url", "", "URL of rampart serve instance (default: auto-discover on localhost:18275, env: RAMPART_SERVE_URL)")
	cmd.Flags().StringVar(&serveToken, "serve-token", "", "Auth token for rampart serve (env: RAMPART_TOKEN)")
	cmd.Flags().MarkDeprecated("serve-token", "use RAMPART_TOKEN env var instead (--serve-token is visible in process list)")
	cmd.Flags().StringVar(&configDir, "config-dir", "", "Directory of additional policy YAML files (default: ~/.rampart/policies/ if it exists)")

	return cmd
}

// parseClaudeCodeInput parses Claude Code hook input format.
// Returns a hookParseResult; Response is non-empty for PostToolUse events.
func parseClaudeCodeInput(reader interface{ Read([]byte) (int, error) }, logger *slog.Logger) (*hookParseResult, error) {
	var input hookInput
	if err := json.NewDecoder(reader).Decode(&input); err != nil {
		return nil, err
	}

	toolType := mapClaudeCodeTool(input.ToolName)
	params := input.ToolInput
	if params == nil {
		params = map[string]any{}
	}

	result := &hookParseResult{
		Tool:   toolType,
		Params: params,
		Agent:  "claude-code",
	}

	// Extract response text from PostToolUse tool_response.
	if len(input.ToolResponse) > 0 {
		result.Response = extractToolResponse(input.ToolResponse)
	}

	return result, nil
}

// extractToolResponse extracts string values from the tool_response map.
// The schema varies by tool (Bash has stdout/stderr, Write has filePath/success, etc.)
// so we check well-known fields first, then fall back to all string values.
func extractToolResponse(resp map[string]any) string {
	var parts []string
	for _, key := range []string{"stdout", "stderr", "content", "output"} {
		if v, ok := resp[key]; ok {
			if s, ok := v.(string); ok && s != "" {
				parts = append(parts, s)
			}
		}
	}
	if len(parts) == 0 {
		for _, v := range resp {
			if s, ok := v.(string); ok && s != "" {
				parts = append(parts, s)
			}
		}
	}
	return strings.Join(parts, "\n")
}

// parseClineInput parses Cline hook input format
func parseClineInput(reader interface{ Read([]byte) (int, error) }, logger *slog.Logger) (*hookParseResult, error) {
	var input clineHookInput
	if err := json.NewDecoder(reader).Decode(&input); err != nil {
		return nil, err
	}

	// Extract tool info from PreToolUse or PostToolUse
	var toolUse *clineToolUse
	isPost := false
	if input.PreToolUse != nil {
		toolUse = input.PreToolUse
	} else if input.PostToolUse != nil {
		toolUse = input.PostToolUse
		isPost = true
	} else {
		return nil, fmt.Errorf("no tool use found in input")
	}

	toolType := mapClineTool(toolUse.ToolName)
	params := toolUse.Parameters
	if params == nil {
		params = map[string]any{}
	}

	result := &hookParseResult{
		Tool:   toolType,
		Params: params,
		Agent:  "cline",
	}

	// For PostToolUse, extract output from parameters if present
	if isPost {
		if output, ok := params["output"].(string); ok {
			result.Response = output
		}
	}

	return result, nil
}

// mapClaudeCodeTool maps Claude Code tool names to Rampart tool types.
func mapClaudeCodeTool(toolName string) string {
	switch toolName {
	case "Bash":
		return "exec"
	case "Read", "ReadFile":
		return "read"
	case "Write", "WriteFile", "Edit", "EditFile":
		return "write"
	case "WebFetch", "Fetch", "web_search", "web_fetch":
		return "fetch"
	case "memory":
		return "memory"
	case "code_execution":
		return "exec"
	case "tool_search":
		return "read"
	default:
		slog.Warn("hook: unmapped Claude Code tool name, defaulting to unknown", "tool_name", toolName)
		return "unknown"
	}
}

// mapClineTool maps Cline tool names to Rampart tool types.
func mapClineTool(toolName string) string {
	switch toolName {
	case "execute_command":
		return "exec"
	case "read_file":
		return "read"
	case "write_to_file":
		return "write"
	case "search_files", "list_files", "list_code_definition_names":
		return "read"
	case "browser_action":
		return "fetch"
	case "use_mcp_tool", "access_mcp_resource":
		return "mcp"
	case "ask_followup_question", "attempt_completion", "new_task", "fetch_instructions", "plan_mode_respond":
		return "interact"
	default:
		slog.Warn("hook: unmapped Cline tool name, defaulting to unknown", "tool_name", toolName)
		return "unknown"
	}
}

// hookDecisionType represents the possible hook outcomes.
type hookDecisionType int

const (
	hookAllow hookDecisionType = iota
	hookDeny
	hookAsk   // require_approval → Claude Code native prompt
	hookBlock // PostToolUse: block response from being shown to agent
)

// outputHookResult writes the allow/deny/ask/block response in the correct format.
// When denied or blocked, it prints a branded message to stderr.
// When ask, Claude Code shows its native permission prompt; Cline cancels
// (Cline has no native ask equivalent).
func outputHookResult(cmd *cobra.Command, format string, decision hookDecisionType, isPostToolUse bool, reason string, command string) error {
	if decision == hookDeny || decision == hookBlock {
		fmt.Fprint(os.Stderr, formatDenyMessage(command, reason))
	}
	if decision == hookAsk {
		fmt.Fprint(os.Stderr, formatApprovalRequiredMessage(command, reason))
	}
	switch format {
	case "cline":
		// Cline has no "ask" — cancel on deny, block, and require_approval.
		cancel := decision == hookDeny || decision == hookAsk || decision == hookBlock
		out := clineHookOutput{Cancel: cancel}
		if decision == hookDeny || decision == hookBlock {
			out.ErrorMessage = "Blocked by Rampart: " + reason
		}
		if decision == hookAsk {
			out.ErrorMessage = "Rampart: approval required — " + reason
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
	default: // claude-code
		var out hookOutput
		switch decision {
		case hookDeny:
			out.HookSpecificOutput = &hookDecision{
				HookEventName:            "PreToolUse",
				PermissionDecision:       "deny",
				PermissionDecisionReason: "Rampart: " + reason,
			}
		case hookAsk:
			out.HookSpecificOutput = &hookDecision{
				HookEventName:            "PreToolUse",
				PermissionDecision:       "ask",
				PermissionDecisionReason: "Rampart: " + reason,
			}
		case hookAllow:
			// PreToolUse: explicit permissionDecision bypasses Claude Code's
			// permission system, which is the correct semantics after rampart
			// has evaluated and approved the command.
			// PostToolUse: empty JSON — PostToolUse only supports "block" or omission.
			if !isPostToolUse {
				out.HookSpecificOutput = &hookDecision{
					HookEventName:      "PreToolUse",
					PermissionDecision: "allow",
				}
			}
		case hookBlock:
			// PostToolUse uses top-level decision/reason per Claude Code docs.
			out.Decision = "block"
			out.Reason = "Rampart: " + reason
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
	}
}
