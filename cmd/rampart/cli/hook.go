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
	"time"

	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/engine"
	"github.com/spf13/cobra"
)

// hookInput is the JSON sent by Claude Code on stdin for PreToolUse hooks.
type hookInput struct {
	ToolName  string         `json:"tool_name"`
	ToolInput map[string]any `json:"tool_input"`
}

// hookOutput is the JSON response for Claude Code hooks.
type hookOutput struct {
	HookSpecificOutput hookDecision `json:"hookSpecificOutput"`
}

type hookDecision struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
}

// clineHookInput is the JSON sent by Cline on stdin for PreToolUse hooks.
type clineHookInput struct {
	ClineVersion    string        `json:"clineVersion"`
	HookName        string        `json:"hookName"`
	Timestamp       string        `json:"timestamp"`
	TaskID          string        `json:"taskId"`
	WorkspaceRoots  []string      `json:"workspaceRoots"`
	PreToolUse      *clineToolUse `json:"preToolUse"`
	PostToolUse     *clineToolUse `json:"postToolUse"`
}

// clineToolUse represents tool usage in Cline's format.
type clineToolUse struct {
	ToolName   string         `json:"toolName"`
	Parameters map[string]any `json:"parameters"`
}

// clineHookOutput is the JSON response for Cline hooks.
type clineHookOutput struct {
	Cancel               bool   `json:"cancel"`
	ContextModification  string `json:"contextModification,omitempty"`
	ErrorMessage         string `json:"errorMessage,omitempty"`
}

func newHookCmd(opts *rootOptions) *cobra.Command {
	var auditDir string
	var mode string
	var format string

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
    ]
  }
}

Cline setup: Use "rampart setup cline" to install hooks automatically.`,
		RunE: func(cmd *cobra.Command, args []string) error {
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

			store := engine.NewFileStore(policyPath)
			eng, err := engine.New(store, logger)
			if err != nil {
				return fmt.Errorf("hook: create engine: %w", err)
			}

			// Audit: append to a daily file so watch can tail it.
			// Unlike long-lived processes, the hook is invoked per-call,
			// so we append to one file rather than creating a new one each time.
			today := time.Now().UTC().Format("2006-01-02")
			auditPath := filepath.Join(auditDir, "audit-hook-"+today+".jsonl")
			auditFile, err := os.OpenFile(auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				return fmt.Errorf("hook: open audit file: %w", err)
			}
			defer auditFile.Close()

			// Parse input based on format
			var toolType string
			var params map[string]any
			var agentName string
			
			switch format {
			case "claude-code":
				toolType, params, agentName, err = parseClaudeCodeInput(os.Stdin, logger)
			case "cline":
				toolType, params, agentName, err = parseClineInput(os.Stdin, logger)
			}
			if err != nil {
				logger.Warn("hook: failed to parse input", "format", format, "error", err)
				return outputHookResult(cmd, format, hookAllow, "", "")
			}

			// Build tool call for evaluation
			call := engine.ToolCall{
				ID:        audit.NewEventID(),
				Agent:     agentName,
				Session:   "hook",
				Tool:      toolType,
				Params:    params,
				Timestamp: time.Now().UTC(),
			}

			// Evaluate
			decision := eng.Evaluate(call)

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
				Request:   params,
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
				return outputHookResult(cmd, format, hookAllow, decision.Message, cmdStr)
			}
			switch decision.Action {
			case engine.ActionDeny:
				return outputHookResult(cmd, format, hookDeny, decision.Message, cmdStr)
			case engine.ActionRequireApproval:
				return outputHookResult(cmd, format, hookAsk, decision.Message, cmdStr)
			default:
				return outputHookResult(cmd, format, hookAllow, decision.Message, cmdStr)
			}
		},
	}

	cmd.Flags().StringVar(&mode, "mode", "enforce", "Mode: enforce | monitor | audit")
	cmd.Flags().StringVar(&format, "format", "claude-code", "Input format: claude-code | cline")
	cmd.Flags().StringVar(&auditDir, "audit-dir", "", "Directory for audit logs (default: ~/.rampart/audit)")

	return cmd
}

// parseClaudeCodeInput parses Claude Code hook input format
func parseClaudeCodeInput(reader interface{ Read([]byte) (int, error) }, logger *slog.Logger) (string, map[string]any, string, error) {
	var input hookInput
	if err := json.NewDecoder(reader).Decode(&input); err != nil {
		return "", nil, "", err
	}
	
	toolType := mapClaudeCodeTool(input.ToolName)
	params := input.ToolInput
	if params == nil {
		params = map[string]any{}
	}
	
	return toolType, params, "claude-code", nil
}

// parseClineInput parses Cline hook input format
func parseClineInput(reader interface{ Read([]byte) (int, error) }, logger *slog.Logger) (string, map[string]any, string, error) {
	var input clineHookInput
	if err := json.NewDecoder(reader).Decode(&input); err != nil {
		return "", nil, "", err
	}
	
	// Extract tool info from PreToolUse or PostToolUse
	var toolUse *clineToolUse
	if input.PreToolUse != nil {
		toolUse = input.PreToolUse
	} else if input.PostToolUse != nil {
		toolUse = input.PostToolUse
	} else {
		return "", nil, "", fmt.Errorf("no tool use found in input")
	}
	
	toolType := mapClineTool(toolUse.ToolName)
	params := toolUse.Parameters
	if params == nil {
		params = map[string]any{}
	}
	
	return toolType, params, "cline", nil
}

// mapClaudeCodeTool maps Claude Code tool names to Rampart tool types.
func mapClaudeCodeTool(toolName string) string {
	switch toolName {
	case "Bash":
		return "exec"
	case "Read", "ReadFile":
		return "read"
	case "Write", "WriteFile", "EditFile":
		return "write"
	case "WebFetch", "Fetch":
		return "fetch"
	default:
		return "exec"
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
		return "exec"
	}
}

// hookDecisionType represents the three possible hook outcomes.
type hookDecisionType int

const (
	hookAllow hookDecisionType = iota
	hookDeny
	hookAsk // require_approval → Claude Code native prompt
)

// outputHookResult writes the allow/deny/ask response in the correct format.
// When denied, it prints a branded message to stderr.
// When ask, Claude Code shows its native permission prompt; Cline cancels
// (Cline has no native ask equivalent).
func outputHookResult(cmd *cobra.Command, format string, decision hookDecisionType, reason string, command string) error {
	if decision == hookDeny {
		fmt.Fprint(os.Stderr, formatDenyMessage(command, reason))
	}
	if decision == hookAsk {
		fmt.Fprint(os.Stderr, formatApprovalRequiredMessage(command, reason))
	}
	switch format {
	case "cline":
		// Cline has no "ask" — cancel on both deny and require_approval.
		cancel := decision == hookDeny || decision == hookAsk
		out := clineHookOutput{Cancel: cancel}
		if decision == hookDeny {
			out.ErrorMessage = "Blocked by Rampart: " + reason
		}
		if decision == hookAsk {
			out.ErrorMessage = "Rampart: approval required — " + reason
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
	default: // claude-code
		out := hookOutput{
			HookSpecificOutput: hookDecision{
				HookEventName: "PreToolUse",
			},
		}
		switch decision {
		case hookDeny:
			out.HookSpecificOutput.PermissionDecision = "deny"
			out.HookSpecificOutput.PermissionDecisionReason = "Rampart: " + reason
		case hookAsk:
			out.HookSpecificOutput.PermissionDecision = "ask"
			out.HookSpecificOutput.PermissionDecisionReason = "Rampart: " + reason
		}
		// hookAllow: omit permissionDecision (Claude Code treats absent as allow)
		return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
	}
}
