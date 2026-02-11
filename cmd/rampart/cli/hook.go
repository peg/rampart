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
	"github.com/peg/rampart/internal/notify"
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

func newHookCmd(opts *rootOptions) *cobra.Command {
	var auditDir string
	var mode string

	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Claude Code PreToolUse hook — reads JSON from stdin, returns allow/deny",
		Long: `Integrates with Claude Code's hook system for native policy enforcement.

Add to ~/.claude/settings.json:
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "rampart hook" }]
      }
    ]
  }
}`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if mode != "enforce" && mode != "monitor" {
				return fmt.Errorf("hook: invalid mode %q (must be enforce or monitor)", mode)
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

			// Read hook input from stdin
			var input hookInput
			if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
				// If we can't parse input, allow by default (don't break the agent)
				logger.Warn("hook: failed to parse stdin", "error", err)
				return outputAllow(cmd)
			}

			// Map Claude Code tool names to Rampart tool types
			toolType := mapHookTool(input.ToolName)

			// Extract command for exec tools
			params := input.ToolInput
			if params == nil {
				params = map[string]any{}
			}

			// Build tool call for evaluation
			call := engine.ToolCall{
				ID:        audit.NewEventID(),
				Agent:     "claude-code",
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
			if decision.Action == engine.ActionDeny && mode == "enforce" {
				return outputDeny(cmd, decision.Message)
			}

			return outputAllow(cmd)
		},
	}

	cmd.Flags().StringVar(&mode, "mode", "enforce", "Mode: enforce | monitor")
	cmd.Flags().StringVar(&auditDir, "audit-dir", "", "Directory for audit logs (default: ~/.rampart/audit)")

	return cmd
}

// sendNotification sends a webhook notification for the policy decision.
func sendNotification(config *engine.NotifyConfig, call engine.ToolCall, decision engine.Decision, logger *slog.Logger) {
	// Check if this action should trigger a notification
	actionStr := decision.Action.String()
	shouldNotify := false
	for _, triggerAction := range config.On {
		if triggerAction == actionStr {
			shouldNotify = true
			break
		}
	}
	if !shouldNotify {
		return
	}

	// Extract command/path from tool parameters
	command := ""
	switch call.Tool {
	case "exec":
		if cmd, ok := call.Params["command"].(string); ok {
			command = cmd
		}
	case "read", "write":
		if path, ok := call.Params["path"].(string); ok {
			command = path
		} else if filePath, ok := call.Params["file_path"].(string); ok {
			command = filePath
		}
	case "fetch":
		if url, ok := call.Params["url"].(string); ok {
			command = url
		}
	}

	// Get the matched policy name
	policyName := "unknown"
	if len(decision.MatchedPolicies) > 0 {
		policyName = decision.MatchedPolicies[0]
	}

	// Create notification event
	event := notify.NotifyEvent{
		Action:    actionStr,
		Tool:      call.Tool,
		Command:   command,
		Policy:    policyName,
		Message:   decision.Message,
		Agent:     call.Agent,
		Timestamp: call.Timestamp.Format(time.RFC3339),
	}

	// Create and send notification
	notifier := notify.NewNotifier(config.URL, config.Platform)
	if err := notifier.Send(event); err != nil {
		logger.Error("hook: webhook notification failed", "error", err, "url", config.URL)
	} else {
		logger.Debug("hook: webhook notification sent", "action", actionStr, "policy", policyName)
	}
}

// mapHookTool maps Claude Code tool names to Rampart tool types.
func mapHookTool(toolName string) string {
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

func outputAllow(cmd *cobra.Command) error {
	out := hookOutput{
		HookSpecificOutput: hookDecision{
			HookEventName: "PreToolUse",
		},
	}
	return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
}

func outputDeny(cmd *cobra.Command, reason string) error {
	out := hookOutput{
		HookSpecificOutput: hookDecision{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "deny",
			PermissionDecisionReason: "Rampart: " + reason,
		},
	}
	return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
}
