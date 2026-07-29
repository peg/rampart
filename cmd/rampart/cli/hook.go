// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/peg/rampart/internal/audit"
	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/internal/session"
	"github.com/spf13/cobra"
)

const maxHookInputBytes = 4 * 1024 * 1024

// hookInput is the JSON sent by Claude Code on stdin for PreToolUse/PostToolUse hooks.
// The base object (from oZ() in Claude Code source) includes session_id, transcript_path,
// cwd, and permission_mode. PreToolUse adds hook_event_name, tool_name, tool_input, and
// tool_use_id. PostToolUse additionally includes tool_response.
type hookInput struct {
	// Base fields (present on all hook events)
	SessionID      string `json:"session_id"`
	TranscriptPath string `json:"transcript_path,omitempty"`
	CWD            string `json:"cwd,omitempty"`
	PermissionMode string `json:"permission_mode,omitempty"`

	// Event-type fields
	HookEventName string `json:"hook_event_name,omitempty"`
	ToolUseID     string `json:"tool_use_id,omitempty"`

	// Tool-specific fields
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
	AdditionalContext        string `json:"additionalContext,omitempty"`
	UpdatedToolOutput        any    `json:"updatedToolOutput,omitempty"`
}

// clineHookInput is the JSON sent by Cline on stdin for PreToolUse hooks.
type clineHookInput struct {
	ClineVersion   string           `json:"clineVersion"`
	HookName       string           `json:"hookName"`
	Timestamp      string           `json:"timestamp"`
	TaskID         string           `json:"taskId"`
	WorkspaceRoots []string         `json:"workspaceRoots"`
	PreToolUse     *clineToolUse    `json:"preToolUse"`
	PostToolUse    *clineToolUse    `json:"postToolUse"`
	ToolCall       *clineToolRecord `json:"tool_call"`
	ToolResult     *clineToolRecord `json:"tool_result"`
}

// clineToolUse represents tool usage in Cline's format.
type clineToolUse struct {
	// ToolName is emitted by current Cline editor and CLI hosts. Tool is kept
	// for compatibility with releases that used the shorter field name.
	Tool       string         `json:"tool"`
	ToolName   string         `json:"toolName"`
	Parameters map[string]any `json:"parameters"`
	Result     any            `json:"result,omitempty"`
}

// clineToolRecord is the lossless current Cline CLI tool_call/tool_result
// record. The parallel preToolUse/postToolUse parameters stringify nested
// values, so Rampart prefers this record when both representations are present.
type clineToolRecord struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Input  any    `json:"input,omitempty"`
	Output any    `json:"output,omitempty"`
}

// clineHookOutput is the JSON response for Cline hooks.
type clineHookOutput struct {
	Cancel              bool   `json:"cancel"`
	ContextModification string `json:"contextModification,omitempty"`
	ErrorMessage        string `json:"errorMessage,omitempty"`
}

// hookParseResult holds the parsed hook input including optional response data.
type hookParseResult struct {
	Tool          string
	Params        map[string]any
	PolicyPaths   []string // every independently evaluated path in a batched write
	WorkDir       string   // host-reported working directory for project policy discovery
	Agent         string
	Response      string // non-empty for PostToolUse events
	RawResponse   map[string]any
	RunID         string // run ID derived from session_id (or env overrides)
	HookEventName string // e.g. "PreToolUse", "PostToolUse", "PostToolUseFailure"
	SessionID     string // raw session_id from Claude Code input (for session state)
	ToolUseID     string // tool_use_id from Claude Code input (for ask correlation)
}

// gitContext holds the git repository context for the current working directory.
type gitContext struct {
	session string // "reponame/branch" e.g. "myapp/main"
	root    string // absolute git root path e.g. "/home/user/projects/myapp"
}

func readBoundedHookInput(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxHookInputBytes+1))
	if err != nil {
		return nil, fmt.Errorf("hook: read stdin: %w", err)
	}
	if len(data) > maxHookInputBytes {
		return nil, fmt.Errorf("hook: stdin exceeds %d-byte limit", maxHookInputBytes)
	}
	return data, nil
}

// normalizeHookStringAliases validates every representation of a
// security-bearing string before selecting one canonical value. Host hook
// payloads are untrusted: silently preferring one alias would let a benign
// decoy hide a different command or path in another field.
func normalizeHookStringAliases(
	params map[string]any,
	canonical, context, field string,
	aliases ...string,
) (string, bool, error) {
	keys := append([]string{canonical}, aliases...)
	seenKeys := make(map[string]struct{}, len(keys))
	selected := ""
	found := false
	for _, key := range keys {
		if _, duplicate := seenKeys[key]; duplicate {
			continue
		}
		seenKeys[key] = struct{}{}
		raw, exists := params[key]
		if !exists {
			continue
		}
		value, ok := raw.(string)
		if !ok {
			return "", false, fmt.Errorf("%s requires %s alias %q to be a string", context, field, key)
		}
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if found && value != selected {
			return "", false, fmt.Errorf("%s has conflicting %s aliases", context, field)
		}
		selected = value
		found = true
	}
	if found {
		params[canonical] = selected
	}
	return selected, found, nil
}

func requireHookStringAliases(
	params map[string]any,
	canonical, context, field string,
	aliases ...string,
) (string, error) {
	value, found, err := normalizeHookStringAliases(params, canonical, context, field, aliases...)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("%s requires a non-empty %s", context, field)
	}
	return value, nil
}

// copyFirstHookAlias preserves the tolerant normalization used for completed
// tool events. Post-tool payload drift must not prevent response scanning;
// strict ambiguity rejection belongs at the pre-execution boundary.
func copyFirstHookAlias(params map[string]any, canonical string, aliases ...string) {
	if _, exists := params[canonical]; exists {
		return
	}
	for _, alias := range aliases {
		if value, exists := params[alias]; exists {
			params[canonical] = value
			return
		}
	}
}

func hookEventIsPost(event string) bool {
	switch strings.TrimSpace(event) {
	case "PostToolUse", "AfterTool":
		return true
	default:
		return false
	}
}

func hookPayloadPhase(format string, input []byte) (bool, any) {
	var payload map[string]any
	if len(input) == 0 || json.Unmarshal(input, &payload) != nil {
		return false, nil
	}
	event, _ := payload["hook_event_name"].(string)
	if event == "" {
		event, _ = payload["hookName"].(string)
	}
	isPost := hookEventIsPost(event) || (format == "cline" && event == "tool_result")
	if !isPost {
		return false, nil
	}
	for _, key := range []string{"tool_response", "tool_result"} {
		if response, ok := payload[key]; ok {
			return true, response
		}
	}
	if post, ok := payload["postToolUse"].(map[string]any); ok {
		if response, exists := post["result"]; exists {
			return true, response
		}
	}
	return true, nil
}

// deriveRunID returns the run ID for the current hook invocation, used to group
// all tool calls from the same agent orchestration run.
//
// Priority order:
//  1. RAMPART_RUN env var — explicit override, useful for scripted orchestration
//  2. sessionID — the session_id field from Claude Code's hook stdin JSON,
//     shared across all agents in the same Claude Code session
//  3. CLAUDE_CONVERSATION_ID env var — fallback for future Claude Code versions
//  4. "" — no grouping; each call is standalone
func deriveRunID(sessionID string) string {
	if v := strings.TrimSpace(os.Getenv("RAMPART_RUN")); v != "" {
		return v
	}
	if v := strings.TrimSpace(sessionID); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("CLAUDE_CONVERSATION_ID")); v != "" {
		return v
	}
	return ""
}

// deriveGitContext returns the git context for the current working directory.
// The RAMPART_SESSION env var overrides the session name if set (root is still detected).
// Returns an empty gitContext if not in a git repo or git is unavailable.
func deriveGitContext() gitContext {
	return deriveGitContextAt("")
}

func deriveGitContextAt(workDir string) gitContext {
	if s := strings.TrimSpace(os.Getenv("RAMPART_SESSION")); s != "" {
		root, _ := gitRevParseTopLevelAt(workDir)
		return gitContext{session: s, root: root}
	}
	root, err := gitRevParseTopLevelAt(workDir)
	if err != nil || root == "" {
		return gitContext{}
	}
	repo := filepath.Base(root)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel2()
	branchOut, _ := exec.CommandContext(ctx2, "git", "-C", root, "rev-parse", "--abbrev-ref", "HEAD").Output()
	branch := strings.TrimSpace(string(branchOut))
	if branch == "" || branch == "HEAD" {
		branch = "detached"
	}
	return gitContext{session: repo + "/" + branch, root: root}
}

func gitRevParseTopLevelAt(workDir string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	args := []string{"rev-parse", "--show-toplevel"}
	if workDir = strings.TrimSpace(workDir); workDir != "" {
		args = append([]string{"-C", workDir}, args...)
	}
	out, err := exec.CommandContext(ctx, "git", args...).Output()
	if err != nil || len(out) == 0 {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// sessionStateDir returns the directory used for per-session state files.
// The directory is ~/.rampart/session-state/ by default.
func sessionStateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".rampart", "session-state")
}

// hookCallCountStatePath returns the cross-process call-count sidecar used by
// one-shot native hook invocations.
func hookCallCountStatePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("hook: resolve home for call counter: %w", err)
	}
	return filepath.Join(home, ".rampart", "hook-call-counts.json"), nil
}

// isServeRunning checks if rampart serve is actually running by hitting the healthz endpoint.
// Returns true if serve responds within the timeout, false otherwise.
// This is used for require_approval fallback: if serve isn't running, we fall back to
// native ask prompts instead of hanging on a dashboard approval that will never come.
func isServeRunning(serveURL string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	healthURL := strings.TrimRight(serveURL, "/") + "/healthz"
	return isRampartHealthReady(ctx, rampartHTTPClient, healthURL)
}

func newHookCmd(opts *rootOptions) *cobra.Command {
	var auditDir string
	var mode string
	var format string
	var serveURL string
	var configDir string

	cmd := &cobra.Command{
		Use:   "hook",
		Short: "AI agent hook — reads JSON from stdin, returns allow/deny",
		Long: `Integrates with AI agent hook systems for native policy enforcement.

Supports multiple formats:
  --format claude-code (default): Claude Code integration
  --format codex: Codex CLI, IDE, and desktop lifecycle hooks
  --format cline: Cline editor and CLI integration
  --format gemini: Gemini CLI lifecycle hooks
  --format antigravity: Antigravity CLI and IDE PreToolUse hooks
  --format copilot: GitHub Copilot CLI and VS Code agent hooks

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
			// Attempt Windows legacy-directory recovery before doing any command
			// work, including local option validation. Defer reporting a recovery
			// failure until after the host payload is read so enforce mode can still
			// return the integration's protocol-shaped deny response.
			rampartDirErr := ensureDefaultRampartDirAccessible()

			if mode != "enforce" && mode != "monitor" && mode != "audit" {
				return fmt.Errorf("hook: invalid mode %q (must be enforce, monitor, or audit)", mode)
			}
			if format != "claude-code" && format != "codex" && format != "cline" && format != "gemini" && format != "antigravity" && format != "copilot" {
				return fmt.Errorf("hook: invalid format %q (must be claude-code, codex, cline, gemini, antigravity, or copilot)", format)
			}

			// Read the protocol payload before any local setup which might fail. That
			// lets enforce mode return the host's correct pre- or post-tool control
			// shape even when Rampart state or policy files are unavailable.
			input, readErr := readBoundedHookInput(cmd.InOrStdin())
			inputIsPost, inputRawResponse := hookPayloadPhase(format, input)
			outputEnforceFailure := func(reason string) error {
				if inputIsPost {
					return outputHookResultWithResponse(
						cmd,
						format,
						hookBlock,
						true,
						reason,
						"",
						redactClaudeToolOutput(inputRawResponse),
					)
				}
				return outputHookResult(cmd, format, hookDeny, false, reason, "")
			}

			if rampartDirErr != nil {
				if mode == "enforce" {
					return outputEnforceFailure("Rampart data directory is inaccessible; refusing host data until permissions are repaired")
				}
				return fmt.Errorf("hook: prepare Rampart data directory: %w", rampartDirErr)
			}

			// Derive session identity once at the top (git repo/branch or RAMPART_SESSION env).
			gitCtx := deriveGitContext()
			hookSession := gitCtx.session

			// Resolve serve-url and serve-token from standard config/env locations.
			serveAutoDiscovered := serveURL == ""
			resolvedServeURL, resolveErr := resolveServeURLStrict(serveURL, fmt.Sprintf("http://localhost:%d", defaultServePort))
			if resolveErr != nil {
				if mode == "enforce" {
					return outputEnforceFailure("Rampart config error; refusing host data until configuration is fixed")
				}
				return fmt.Errorf("hook: resolve serve URL: %w", resolveErr)
			}
			serveURL = resolvedServeURL
			serveToken, _, tokenErr := resolveTokenForEndpoint(serveURL, "")
			if tokenErr != nil {
				if mode == "enforce" {
					return outputEnforceFailure("Rampart credential endpoint is unsafe; refusing host data until configuration is fixed")
				}
				return fmt.Errorf("hook: resolve serve credentials: %w", tokenErr)
			}

			// Resolve audit directory
			if auditDir == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					if mode == "enforce" {
						return outputEnforceFailure("Rampart cannot resolve its data directory; refusing host data")
					}
					return fmt.Errorf("hook: resolve home: %w", err)
				}
				auditDir = filepath.Join(home, ".rampart", "audit")
			}
			if err := os.MkdirAll(auditDir, 0o700); err != nil {
				if mode == "enforce" {
					return outputEnforceFailure("Rampart audit storage is unavailable; refusing host data")
				}
				return fmt.Errorf("hook: create audit dir: %w", err)
			}

			// Stdout is the hook protocol response. Stderr is also treated as a hook
			// failure by some agents, so keep routine hook execution stderr-clean.
			// Verbose mode is intentionally opt-in for manual debugging.
			logLevel := slog.LevelWarn
			logWriter := io.Discard
			if opts.verbose {
				logLevel = slog.LevelDebug
				logWriter = cmd.ErrOrStderr()
			}
			logger := slog.New(slog.NewTextHandler(logWriter, &slog.HandlerOptions{Level: logLevel}))

			// Cleanup stale session state files in the background (best-effort).
			// This runs once per hook invocation; typically fires every few seconds
			// during active sessions, which is sufficient to keep the directory clean.
			var cleanupWg sync.WaitGroup
			cleanupWg.Add(1)
			go func() {
				defer cleanupWg.Done()
				mgr := session.NewManager(sessionStateDir(), "", logger)
				_ = mgr.Cleanup(24 * time.Hour)
			}()
			defer cleanupWg.Wait()

			// Native hooks are one-shot processes, but their decisions still join the
			// same hash chain as service and MCP events. The validated checkpoint
			// avoids rescanning the complete trail on every host tool call.
			auditSink, err := audit.NewJSONLSink(
				auditDir,
				audit.WithFsync(false),
				audit.WithCheckpointStartup(),
				audit.WithLogger(logger),
			)
			if err != nil {
				if mode == "enforce" {
					return outputEnforceFailure("Rampart audit storage is unavailable; refusing host data")
				}
				return fmt.Errorf("hook: open audit trail: %w", err)
			}
			defer auditSink.Close()
			appendAudit := auditSink.Write

			// Read hook input through a bounded buffer before parsing. Hook payloads
			// are single JSON objects; accepting an unbounded stream would let a
			// malformed host exhaust memory before policy evaluation starts.
			var parsed *hookParseResult
			if readErr != nil {
				err = readErr
			} else {
				inputReader := bytes.NewReader(input)
				switch format {
				case "claude-code":
					parsed, err = parseClaudeCodeInput(inputReader, logger)
				case "codex":
					parsed, err = parseCodexInput(inputReader)
				case "cline":
					parsed, err = parseClineInput(inputReader, logger)
				case "gemini":
					parsed, err = parseGeminiInput(inputReader)
				case "antigravity":
					parsed, err = parseAntigravityInput(inputReader)
				case "copilot":
					parsed, err = parseCopilotInput(inputReader)
				default:
					// Should be unreachable — format is validated above.
					return fmt.Errorf("hook: unhandled format %q", format)
				}
			}
			if err != nil {
				logger.Warn("hook: failed to parse input", "format", format, "error", err)

				// Clean EOF is normal — hook process exits when the agent
				// restarts or stdin closes.  Don't record an audit entry;
				// it's not a real policy decision and just creates noise in
				// `rampart log --deny`.
				if errors.Is(err, io.EOF) || err.Error() == "EOF" {
					logger.Debug("hook: clean EOF on stdin, skipping audit")
					return outputHookResult(cmd, format, hookAllow, false, "parse failure: EOF", "")
				}

				// In enforce mode, fail closed — a parse failure must not silently
				// allow the tool call. In monitor/audit modes, allow through so the
				// agent is never blocked by a Rampart bug.
				outcome := "allow"
				hookOutcome := hookAllow
				isPost, rawResponse := hookPayloadPhase(format, input)
				if mode == "enforce" {
					outcome = "deny"
					if isPost {
						hookOutcome = hookBlock
					} else {
						hookOutcome = hookDeny
					}
				}
				// Best-effort audit entry for parse failure. Native-hook records join
				// the shared audit chain under its cross-process writer lock.
				parseFailureEvent := audit.Event{
					ID:        audit.NewEventID(),
					Timestamp: time.Now().UTC(),
					Agent:     format,
					Session:   hookSession,
					Tool:      "unknown",
					Request:   map[string]any{"raw_error": err.Error()},
					Decision: audit.EventDecision{
						Action:  outcome,
						Message: fmt.Sprintf("parse failure (format=%s): %v", format, err),
					},
				}
				if auditErr := appendAudit(parseFailureEvent); auditErr != nil {
					logger.Error("hook: audit parse failure", "error", auditErr)
				}
				return outputHookResultWithResponse(
					cmd,
					format,
					hookOutcome,
					isPost,
					fmt.Sprintf("parse failure: %v", err),
					"",
					redactClaudeToolOutput(rawResponse),
				)
			}

			// Use the host-reported working directory for repository identity and
			// project-policy discovery. Hook processes are not guaranteed to inherit
			// the agent's working directory on every host or editor platform.
			if parsed.WorkDir != "" {
				gitCtx = deriveGitContextAt(parsed.WorkDir)
				hookSession = gitCtx.session
			}

			// Load policies only after parsing the host context, so a project policy
			// is selected from the tool call's repository rather than Rampart's
			// process working directory.
			policyPath, cleanupPolicy, err := resolveWrapPolicyPath(opts.configPath)
			if err != nil {
				if mode == "enforce" {
					return outputEnforceFailure("Rampart policy configuration is unavailable; refusing host data")
				}
				return err
			}
			defer cleanupPolicy()

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

			if gitCtx.root != "" && os.Getenv("RAMPART_NO_PROJECT_POLICY") == "" {
				candidate := filepath.Join(gitCtx.root, ".rampart", "policy.yaml")
				if _, statErr := os.Stat(candidate); statErr == nil {
					logger.Debug("hook: loading project policy", "path", candidate)
					store = engine.NewLayeredStore(store, candidate, logger)
				} else if !os.IsNotExist(statErr) {
					if mode == "enforce" {
						return outputEnforceFailure("Rampart cannot inspect the repository policy; refusing host data")
					}
					return fmt.Errorf("hook: inspect project policy %s: %w", candidate, statErr)
				}
			}

			eng, err := engine.New(store, logger)
			if err != nil {
				// Agent hook runners often treat any stderr output or non-zero exit as a
				// scary hook failure. In enforce mode, fail closed through the hook
				// protocol instead: the agent sees a normal policy block, not a broken
				// Bash/PreToolUse hook.
				if mode == "enforce" {
					logger.Warn("hook: create engine", "error", err)
					return outputEnforceFailure("Rampart policy configuration error; refusing host data until policy is fixed")
				}
				return fmt.Errorf("hook: create engine: %w", err)
			}

			// PostToolUseFailure: only inject policy guidance when the failure appears to
			// be Rampart-mediated (a deny or a stored ask-flow decision). Ordinary tool
			// failures should not be mislabeled as security blocks.
			if parsed.HookEventName == "PostToolUseFailure" {
				failedCall := engine.ToolCall{
					Tool:    parsed.Tool,
					WorkDir: parsed.WorkDir,
					Params:  parsed.Params,
				}
				decision := eng.Evaluate(failedCall)

				// A pending ask alone is not evidence of a denial: the user may have
				// approved the native prompt and the tool may have failed afterward.
				// So PostToolUseFailure must not dismiss ask state or mark mirrored serve
				// approvals denied based solely on this hook event.
				if decision.Action != engine.ActionDeny {
					// For ask-mediated flows, PostToolUseFailure is ambiguous: it can mean
					// either native-prompt denial or an approved tool that later failed.
					// Do not inject denial guidance or mutate state based on an ambiguous event.
					return json.NewEncoder(cmd.OutOrStdout()).Encode(hookOutput{})
				}

				postToolUseFailureEvent := audit.Event{
					ID:         audit.NewEventID(),
					Timestamp:  time.Now().UTC(),
					Agent:      parsed.Agent,
					Session:    hookSession,
					RunID:      parsed.RunID,
					ToolCallID: parsed.ToolUseID,
					Tool:       parsed.Tool,
					Request:    parsed.Params,
					Decision: audit.EventDecision{
						Action:  "feedback",
						Message: "PostToolUseFailure short-circuit: injecting denial guidance to stop retry loops",
					},
				}
				if auditErr := appendAudit(postToolUseFailureEvent); auditErr != nil {
					logger.Error("hook: audit post-tool failure", "error", auditErr)
				}

				explainCmd := "rampart policy explain '" + parsed.Tool + "'"
				msg := "This tool call failed or was blocked by a security policy. " +
					"Do not attempt alternative approaches or workarounds — " +
					"if an operation is restricted, report it to the user and stop.\n\n" +
					"To diagnose: run `" + explainCmd + "` to see which policy applies, " +
					"or `rampart watch` to view the live audit log. " +
					"To allow this operation, update the policy at ~/.rampart/policies/ — " +
					"see https://rampart.sh/docs/exceptions for guidance."

				// Prepend the specific deny reason if available — gives the agent
				// (and user) immediate context on why the call was blocked.
				if decision.Action == engine.ActionDeny && decision.Message != "" {
					policyHint := ""
					if len(decision.MatchedPolicies) > 0 {
						policyHint = " [" + decision.MatchedPolicies[0] + "]"
					}
					if decision.FromProjectPolicy {
						policyHint += " [Project Policy]"
					}
					msg = "⛔ Blocked" + policyHint + ": " + decision.Message + "\n\n" + msg
				}
				suggestions := engine.GenerateSuggestions(failedCall)
				if len(suggestions) > 0 {
					msg += "\n\nTo allow this specific operation, a human can run:\n"
					for _, s := range suggestions {
						msg += "  " + s + "\n"
					}
					msg += "\n⚠️ Surface these commands to the user — do NOT run them yourself."
				}

				out := hookOutput{
					HookSpecificOutput: &hookDecision{
						HookEventName:     "PostToolUseFailure",
						AdditionalContext: msg,
					},
				}
				return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
			}

			// Build tool call for evaluation
			depth, _ := strconv.Atoi(strings.TrimSpace(os.Getenv("RAMPART_AGENT_DEPTH")))
			if depth < 0 {
				depth = 0
			}
			if parsed.Tool == "agent" {
				depth++
			}
			arrivalTime := time.Now().UTC()
			call := engine.ToolCall{
				ID:         audit.NewEventID(),
				Agent:      parsed.Agent,
				AgentDepth: depth,
				Session:    hookSession,
				RunID:      parsed.RunID,
				ToolCallID: parsed.ToolUseID,
				Tool:       parsed.Tool,
				WorkDir:    parsed.WorkDir,
				Params:     parsed.Params,
				Input:      parsed.Params,
				Timestamp:  arrivalTime,
			}

			isPostToolUse := hookEventIsPost(parsed.HookEventName) || parsed.Response != ""
			requiresCallCount := !isPostToolUse && eng.RequiresCallCount(call)
			var counterErr error
			if requiresCallCount {
				// Native hooks are one-shot processes. Only calls which can affect an
				// active call_count rule need the locked, durable sidecar; unrelated
				// shell and file calls stay on the ordinary no-I/O evaluation path.
				var counterPath string
				counterPath, counterErr = hookCallCountStatePath()
				if counterErr == nil {
					var counter *engine.PersistentCallCounter
					counter, counterErr = engine.NewPersistentCallCounter(counterPath)
					if counterErr == nil {
						eng.SetCallCounter(counter)
					}
				}
				if counterErr != nil {
					logger.Warn("hook: persistent call counter unavailable", "error", counterErr)
				}
			}

			// Evaluate: for PreToolUse, run command-side policy check.
			// For PostToolUse, run response-side evaluation.
			var decision engine.Decision
			if isPostToolUse && parsed.Tool == "unknown" {
				// A newly introduced host tool cannot safely skip tool-scoped
				// response policies merely because it did not exist when this
				// Rampart version shipped. The tool has already run, so block and
				// redact its output until the adapter knows its consequences.
				decision = engine.Decision{
					Action:  engine.ActionDeny,
					Message: "unsupported host tool response; update Rampart before exposing its output",
				}
			} else if isPostToolUse {
				decision = eng.EvaluateResponse(call, parsed.Response)
			} else if counterErr != nil && mode == "enforce" {
				decision = engine.Decision{
					Action:  engine.ActionDeny,
					Message: "Rampart call counter unavailable; refusing tool call",
				}
			} else if requiresCallCount {
				if err := eng.IncrementCallCount(call.Tool, arrivalTime); err != nil {
					logger.Error("hook: call counter unavailable; failing closed", "tool", call.Tool, "error", err)
					decision = engine.Decision{
						Action:  engine.ActionDeny,
						Message: "call counter capacity unavailable; refusing tool call",
					}
				} else {
					call, decision = evaluateHookCall(eng, call, parsed.PolicyPaths)
				}
			} else {
				call, decision = evaluateHookCall(eng, call, parsed.PolicyPaths)
			}
			decision = failClosedUnsupportedNativeHookAction(decision)

			// Write audit event
			eventDecision := audit.EventDecision{
				Action:          decision.Action.String(),
				MatchedPolicies: decision.MatchedPolicies,
				Message:         decision.Message,
				EvalTimeUS:      decision.EvalDuration.Microseconds(),
				Suggestions:     decision.Suggestions,
			}
			event := audit.Event{
				ID:         call.ID,
				Timestamp:  call.Timestamp,
				Agent:      call.Agent,
				Session:    call.Session,
				RunID:      call.RunID,
				ToolCallID: call.ToolCallID,
				Tool:       call.Tool,
				Request:    parsed.Params,
				Decision:   eventDecision,
			}
			if auditErr := appendAudit(event); auditErr != nil {
				logger.Error("hook: audit write failed", "error", auditErr)
				if mode == "enforce" {
					return outputEnforceFailure("Rampart audit storage is unavailable; refusing host data")
				}
			}

			// Send webhook notification if configured
			config, err := store.Load()
			if err != nil {
				logger.Error("hook: failed to reload config for notifications", "error", err)
			} else if config.Notify != nil && config.Notify.URL != "" {
				// Hook processes exit immediately after writing their protocol result;
				// an unjoined goroutine is routinely terminated before the request is
				// sent. Keep notification delivery bounded so a slow endpoint cannot
				// consume the host's hook timeout budget.
				sendNotificationWithTimeout(config.Notify, call, decision, logger, time.Second)
			}

			// PostToolUse: observe approval for any pending ask entries in session state.
			// This fires when tool_response is present, indicating the user approved the ask.
			// The observation is best-effort — errors are logged but do not block the hook.
			if parsed.HookEventName == "PostToolUse" && parsed.ToolUseID != "" && parsed.SessionID != "" {
				sessionMgr := session.NewManager(sessionStateDir(), parsed.SessionID, logger)
				ask, record, obsErr := sessionMgr.ObserveApprovalWithAsk(parsed.ToolUseID)
				if obsErr != nil {
					// Not found means this PostToolUse was not preceded by an ActionAsk —
					// that is normal (most tool calls are allowed/denied, not asked).
					logger.Debug("hook: PostToolUse observe approval (no pending ask or other issue)",
						"session_id", parsed.SessionID,
						"tool_use_id", parsed.ToolUseID,
						"error", obsErr,
					)
				} else {
					logger.Info("hook: observed approval for ask",
						"session_id", parsed.SessionID,
						"tool_use_id", parsed.ToolUseID,
						"tool", record.Tool,
						"pattern", record.Pattern,
						"approval_count", record.ApprovalCount,
					)

					// Best-effort: if this ask was mirrored to serve, mark it approved so
					// dashboard/watch pending state resolves with the user's decision.
					if ask != nil && ask.Audit && ask.AuditApprovalID != "" && serveURL != "" && isServeRunning(serveURL) {
						approvalClient := &hookApprovalClient{
							serveURL:       strings.TrimRight(serveURL, "/"),
							token:          serveToken,
							logger:         logger,
							autoDiscovered: serveAutoDiscovered,
							errWriter:      cmd.ErrOrStderr(),
						}
						resolveCtx, cancelResolve := context.WithTimeout(cmd.Context(), 400*time.Millisecond)
						_ = approvalClient.resolveAskAuditCtx(resolveCtx, ask.AuditApprovalID, true, "hook-posttooluse")
						cancelResolve()
					}
				}
			}

			// Return decision
			cmdStr := extractCommand(call)
			reasonMsg := projectPolicyPrefix(decision.Message, decision.FromProjectPolicy)
			if mode != "enforce" {
				return outputHookResult(cmd, format, hookAllow, isPostToolUse, reasonMsg, cmdStr)
			}

			switch decision.Action {
			case engine.ActionDeny:
				if isPostToolUse {
					return outputHookResultWithResponse(
						cmd,
						format,
						hookBlock,
						true,
						reasonMsg,
						cmdStr,
						redactClaudeToolOutput(parsed.RawResponse),
						decision.Suggestions...,
					)
				}
				return outputHookResult(cmd, format, hookDeny, false, reasonMsg, cmdStr, decision.Suggestions...)
			case engine.ActionAsk:
				if format == "codex" || format == "gemini" {
					return resolveExternalHookApproval(cmd, format, call, reasonMsg, serveURL, serveToken, serveAutoDiscovered, logger)
				}
				if decision.HeadlessOnly {
					if serveURL == "" || !isServeRunning(serveURL) {
						return fmt.Errorf("hook: ask.headless_only requires rampart serve, but no serve instance is reachable at %s", serveURL)
					}
					approvalClient := &hookApprovalClient{
						serveURL:       strings.TrimRight(serveURL, "/"),
						token:          serveToken,
						logger:         logger,
						autoDiscovered: serveAutoDiscovered,
						errWriter:      cmd.ErrOrStderr(),
					}
					command, _ := call.Params["command"].(string)
					path := call.Path() // handles both "file_path" (Claude Code) and "path"
					result := approvalClient.requestApprovalCtx(cmd.Context(), call.Tool, command, call.Agent, path, call.RunID, call.ToolCallID, reasonMsg, 5*time.Minute)
					if result == hookAsk {
						return fmt.Errorf("hook: ask.headless_only could not reach rampart serve approval flow; native ask fallback is disabled")
					}
					return outputHookResult(cmd, format, result, false, reasonMsg, cmdStr)
				}

				askAudit := decision.Audit
				auditApprovalID := ""
				// For ask+audit, best-effort mirror pending state into serve if reachable.
				if askAudit && serveURL != "" && isServeRunning(serveURL) {
					approvalClient := &hookApprovalClient{
						serveURL:       strings.TrimRight(serveURL, "/"),
						token:          serveToken,
						logger:         logger,
						autoDiscovered: serveAutoDiscovered,
						errWriter:      cmd.ErrOrStderr(),
					}
					command, _ := call.Params["command"].(string)
					path := call.Path()
					registerCtx, cancelRegister := context.WithTimeout(cmd.Context(), 400*time.Millisecond)
					if approvalID, regErr := approvalClient.registerAskAuditCtx(registerCtx, call.Tool, command, call.Agent, path, call.RunID, call.ToolCallID, reasonMsg); regErr == nil {
						auditApprovalID = approvalID
					} else {
						logger.Debug("hook: ask audit registration failed (best-effort)", "error", regErr)
					}
					cancelRegister()
				}

				// Write pending ask to session state so PostToolUse can correlate the outcome.
				if parsed.SessionID != "" && parsed.ToolUseID != "" {
					sessionMgr := session.NewManager(sessionStateDir(), parsed.SessionID, logger)
					// Build a generalised pattern for the command (use command as-is for now;
					// Phase 2 will add pattern generalisation via engine.GeneralizePattern).
					cmdStr2 := extractCommand(call)
					policyName := ""
					if len(decision.MatchedPolicies) > 0 {
						policyName = decision.MatchedPolicies[0]
					}
					if err := sessionMgr.RecordAskWithAudit(parsed.ToolUseID, call.Tool, cmdStr2, cmdStr2, policyName, reasonMsg, askAudit, auditApprovalID); err != nil {
						// NOTE: Use Debug, not Warn. Claude Code treats ANY stderr as a hook error
						// for ask decisions. RecordAsk is best-effort anyway.
						logger.Debug("hook: failed to record ask in session state", "error", err)
					}
				}
				// Emit native ask prompt (Claude Code shows the 4-button dialog).
				return outputHookResult(cmd, format, hookAsk, false, reasonMsg, cmdStr)
			case engine.ActionRequireApproval:
				if format == "codex" || format == "gemini" {
					return resolveExternalHookApproval(cmd, format, call, reasonMsg, serveURL, serveToken, serveAutoDiscovered, logger)
				}
				askAudit := true
				auditApprovalID := ""
				// For ask+audit, best-effort mirror pending state into serve if reachable.
				if askAudit && serveURL != "" && isServeRunning(serveURL) {
					approvalClient := &hookApprovalClient{
						serveURL:       strings.TrimRight(serveURL, "/"),
						token:          serveToken,
						logger:         logger,
						autoDiscovered: serveAutoDiscovered,
						errWriter:      cmd.ErrOrStderr(),
					}
					command, _ := call.Params["command"].(string)
					path := call.Path()
					registerCtx, cancelRegister := context.WithTimeout(cmd.Context(), 400*time.Millisecond)
					if approvalID, regErr := approvalClient.registerAskAuditCtx(registerCtx, call.Tool, command, call.Agent, path, call.RunID, call.ToolCallID, reasonMsg); regErr == nil {
						auditApprovalID = approvalID
					} else {
						logger.Debug("hook: ask audit registration failed (best-effort)", "error", regErr)
					}
					cancelRegister()
				}

				// Write pending ask to session state so PostToolUse can correlate the outcome.
				if parsed.SessionID != "" && parsed.ToolUseID != "" {
					sessionMgr := session.NewManager(sessionStateDir(), parsed.SessionID, logger)
					cmdStr2 := extractCommand(call)
					policyName := ""
					if len(decision.MatchedPolicies) > 0 {
						policyName = decision.MatchedPolicies[0]
					}
					if err := sessionMgr.RecordAskWithAudit(parsed.ToolUseID, call.Tool, cmdStr2, cmdStr2, policyName, reasonMsg, askAudit, auditApprovalID); err != nil {
						logger.Debug("hook: failed to record ask in session state", "error", err)
					}
				}
				// Emit native ask prompt (Claude Code shows the 4-button dialog).
				return outputHookResult(cmd, format, hookAsk, false, reasonMsg, cmdStr)
			case engine.ActionAllow, engine.ActionWatch:
				return outputHookResult(cmd, format, hookAllow, isPostToolUse, reasonMsg, cmdStr)
			case engine.ActionWebhook:
				// Defensive fallback: webhook is normalized to deny before audit.
				return outputHookResult(cmd, format, hookDeny, isPostToolUse, "Rampart native hook cannot safely enforce webhook; refusing tool call", cmdStr)
			default:
				return outputHookResult(cmd, format, hookDeny, isPostToolUse, "Rampart received an unsupported policy action; refusing tool call", cmdStr)
			}
		},
	}

	cmd.Flags().StringVar(&mode, "mode", "enforce", "Mode: enforce | monitor | audit")
	cmd.Flags().StringVar(&format, "format", "claude-code", "Input format: claude-code | codex | cline | gemini | antigravity | copilot")
	cmd.Flags().StringVar(&auditDir, "audit-dir", "", "Directory for audit logs (default: ~/.rampart/audit)")
	cmd.Flags().StringVar(&serveURL, "serve-url", "", "Rampart service URL override (default: auto-discover via url/config/state; env: RAMPART_URL or RAMPART_SERVE_URL)")
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
	event := strings.TrimSpace(input.HookEventName)
	if event != "PreToolUse" && event != "PostToolUse" && event != "PostToolUseFailure" {
		return nil, fmt.Errorf("hook: unsupported Claude Code hook_event_name %q", input.HookEventName)
	}
	if strings.TrimSpace(input.ToolName) == "" {
		return nil, fmt.Errorf("hook: Claude Code tool_name is required")
	}

	// Validate tool_use_id format to prevent injection attacks
	if err := validateToolUseID(input.ToolUseID); err != nil {
		return nil, err
	}

	toolType := mapClaudeCodeTool(input.ToolName)
	// Claude Code adds tool surfaces over time. A newly hook-visible action must
	// not inherit the policy's unmatched/default behavior before Rampart knows
	// its security consequence. Match the Codex adapter's fail-closed behavior
	// for unknown pre-call tools; post-call payloads remain available for
	// response scanning and audit compatibility.
	if event == "PreToolUse" && toolType == "unknown" {
		return nil, fmt.Errorf(
			"hook: unsupported Claude Code tool_name %q; update Rampart before allowing this tool",
			input.ToolName,
		)
	}
	params := input.ToolInput
	if params == nil {
		params = map[string]any{}
	}
	// Monitor can either run a command or open a WebSocket. Normalize the
	// WebSocket form to fetch with a top-level URL so network policies apply.
	if input.ToolName == "Monitor" {
		if websocket, ok := params["ws"].(map[string]any); ok {
			toolType = "fetch"
			normalized := make(map[string]any, len(params)+1)
			for key, value := range params {
				normalized[key] = value
			}
			normalized["url"] = websocket["url"]
			params = normalized
		}
	}
	if event == "PreToolUse" {
		if err := validateClaudePreToolParams(input.ToolName, params); err != nil {
			return nil, err
		}
	}

	result := &hookParseResult{
		Tool:          toolType,
		Params:        params,
		WorkDir:       strings.TrimSpace(input.CWD),
		Agent:         "claude-code",
		RunID:         deriveRunID(input.SessionID),
		HookEventName: event,
		SessionID:     input.SessionID,
		ToolUseID:     input.ToolUseID,
	}

	// Extract response text from PostToolUse tool_response.
	if len(input.ToolResponse) > 0 {
		result.Response = extractToolResponse(input.ToolResponse)
		result.RawResponse = input.ToolResponse
	}

	return result, nil
}

func validateClaudePreToolParams(toolName string, params map[string]any) error {
	requireString := func(description string, keys ...string) error {
		for _, key := range keys {
			if value, ok := params[key].(string); ok && strings.TrimSpace(value) != "" {
				return nil
			}
		}
		return fmt.Errorf("hook: Claude Code %s requires a non-empty %s", toolName, description)
	}

	switch toolName {
	case "Bash", "PowerShell":
		_, err := requireHookStringAliases(params, "command", "hook: Claude Code "+toolName, "command")
		return err
	case "code_execution":
		_, err := requireHookStringAliases(params, "command", "hook: Claude Code "+toolName, "command or code", "code", "input")
		return err
	case "Monitor":
		_, commandFound, err := normalizeHookStringAliases(params, "command", "hook: Claude Code "+toolName, "command")
		if err != nil {
			return err
		}
		if commandFound {
			return nil
		}
		if websocket, ok := params["ws"].(map[string]any); ok {
			if value, ok := websocket["url"].(string); ok && strings.TrimSpace(value) != "" {
				return nil
			}
		}
		return fmt.Errorf("hook: Claude Code Monitor requires a non-empty command or WebSocket URL")
	case "Read", "ReadFile":
		_, err := requireHookStringAliases(params, "path", "hook: Claude Code "+toolName, "file path", "file_path")
		return err
	case "Glob":
		return requireString("pattern", "pattern")
	case "Grep":
		return requireString("pattern", "pattern")
	case "LSP":
		_, err := requireHookStringAliases(params, "path", "hook: Claude Code "+toolName, "file path", "filePath", "file_path")
		return err
	case "Write", "WriteFile", "Edit", "EditFile":
		_, err := requireHookStringAliases(params, "path", "hook: Claude Code "+toolName, "file path", "file_path")
		return err
	case "NotebookEdit":
		_, err := requireHookStringAliases(params, "path", "hook: Claude Code "+toolName, "notebook path", "notebook_path", "file_path")
		return err
	case "EnterWorktree":
		// Claude's name field is an opaque worktree label, not the resolved
		// filesystem destination. Treating it as a path would let path-scoped
		// write policies evaluate the wrong resource. Accept a real path when a
		// host provides one; otherwise fail closed at the pre-tool boundary.
		if _, err := requireHookStringAliases(params, "path", "hook: Claude Code "+toolName, "resolved worktree path"); err != nil {
			if name, ok := params["name"].(string); ok && strings.TrimSpace(name) != "" {
				return fmt.Errorf("hook: Claude Code %s requires a non-empty resolved worktree path; name is only an opaque label", toolName)
			}
			return err
		}
		return nil
	case "WebFetch", "Fetch", "web_fetch":
		return requireString("URL", "url")
	case "WebSearch", "web_search":
		return requireString("search query", "query")
	default:
		return nil
	}
}

// extractToolResponse extracts every string leaf from the tool_response map.
// Host response schemas vary and frequently nest model-visible content inside
// arrays and result objects. Traversing the complete value prevents a nested
// credential or prompt-injection marker from bypassing response policies.
func extractToolResponse(resp map[string]any) string {
	parts := make([]string, 0, 4)
	stack := []any{resp}
	for len(stack) > 0 {
		value := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		switch typed := value.(type) {
		case string:
			if typed != "" {
				parts = append(parts, typed)
			}
		case []any:
			for index := len(typed) - 1; index >= 0; index-- {
				stack = append(stack, typed[index])
			}
		case []string:
			for index := len(typed) - 1; index >= 0; index-- {
				stack = append(stack, typed[index])
			}
		case map[string]any:
			keys := orderedResponseKeys(typed)
			for index := len(keys) - 1; index >= 0; index-- {
				stack = append(stack, typed[keys[index]])
			}
		}
	}
	return strings.Join(parts, "\n")
}

func orderedResponseKeys(value map[string]any) []string {
	priority := []string{"stdout", "stderr", "content", "output"}
	keys := make([]string, 0, len(value))
	seen := make(map[string]struct{}, len(priority))
	for _, key := range priority {
		if _, ok := value[key]; ok {
			keys = append(keys, key)
			seen[key] = struct{}{}
		}
	}
	rest := make([]string, 0, len(value)-len(keys))
	for key := range value {
		if _, ok := seen[key]; !ok {
			rest = append(rest, key)
		}
	}
	sort.Strings(rest)
	return append(keys, rest...)
}

const redactedToolOutput = "[blocked by Rampart response policy]"

// redactClaudeToolOutput preserves the host's response shape while removing
// every string value. Claude Code validates built-in updatedToolOutput values
// against the original tool schema, so replacing the response with a scalar
// would be ignored for structured tools such as Bash.
func redactClaudeToolOutput(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			out[key] = redactClaudeToolOutput(item)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for index, item := range typed {
			out[index] = redactClaudeToolOutput(item)
		}
		return out
	case string:
		return redactedToolOutput
	default:
		return value
	}
}

// parseClineInput parses Cline hook input format
func parseClineInput(reader interface{ Read([]byte) (int, error) }, logger *slog.Logger) (*hookParseResult, error) {
	var input clineHookInput
	if err := json.NewDecoder(reader).Decode(&input); err != nil {
		return nil, err
	}

	// Cline's editor uses PreToolUse/PostToolUse hook names. Current Cline CLI
	// file hooks use tool_call/tool_result while retaining the nested
	// preToolUse/postToolUse compatibility objects. Normalize both protocols.
	var toolUse *clineToolUse
	var record *clineToolRecord
	isPost := false
	event := ""
	switch {
	case input.PreToolUse != nil && input.PostToolUse != nil:
		return nil, fmt.Errorf("hook: Cline payload contains both preToolUse and postToolUse")
	case input.PreToolUse != nil:
		if input.HookName != "PreToolUse" && input.HookName != "tool_call" {
			return nil, fmt.Errorf("hook: Cline preToolUse payload has hookName %q", input.HookName)
		}
		toolUse = input.PreToolUse
		record = input.ToolCall
		event = "PreToolUse"
	case input.PostToolUse != nil:
		if input.HookName != "PostToolUse" && input.HookName != "tool_result" {
			return nil, fmt.Errorf("hook: Cline postToolUse payload has hookName %q", input.HookName)
		}
		toolUse = input.PostToolUse
		record = input.ToolResult
		isPost = true
		event = "PostToolUse"
	default:
		return nil, fmt.Errorf("no tool use found in input")
	}
	if !isPost && input.ToolResult != nil {
		return nil, fmt.Errorf("hook: Cline preToolUse payload contains tool_result")
	}
	if isPost && input.ToolCall != nil {
		return nil, fmt.Errorf("hook: Cline postToolUse payload contains tool_call")
	}

	toolName := strings.TrimSpace(toolUse.ToolName)
	compatToolName := strings.TrimSpace(toolUse.Tool)
	if toolName != "" && compatToolName != "" && toolName != compatToolName {
		return nil, fmt.Errorf("hook: Cline payload has conflicting tool and toolName values")
	}
	if toolName == "" {
		toolName = compatToolName
	}
	if record != nil {
		recordName := strings.TrimSpace(record.Name)
		if recordName != "" && toolName != "" && recordName != toolName {
			return nil, fmt.Errorf("hook: Cline payload has conflicting nested and record tool names")
		}
		if toolName == "" {
			toolName = recordName
		}
	}
	if toolName == "" {
		return nil, fmt.Errorf("hook: Cline tool name is required")
	}

	params := cloneHookParams(toolUse.Parameters)
	if record != nil && record.Input != nil {
		params = clineParamsFromRecordInput(record.Input)
	}
	toolType := mapClineTool(toolName)
	var policyPaths []string
	var err error
	params, policyPaths, err = normalizeClineParams(toolName, toolType, params, !isPost)
	if err != nil {
		return nil, err
	}
	if toolType == "mcp" {
		if _, exists := params["tool_name"]; !exists {
			parts := strings.Split(toolName, "__")
			if len(parts) > 1 && strings.TrimSpace(parts[len(parts)-1]) != "" {
				params["tool_name"] = parts[len(parts)-1]
			}
		}
		toolType = classifyNativeMCPTool(toolName, params)
	}
	if !isPost && toolType == "unknown" {
		return nil, fmt.Errorf("hook: unsupported Cline tool %q; update Rampart before allowing this tool", toolName)
	}
	toolUseID := ""
	if record != nil {
		toolUseID = strings.TrimSpace(record.ID)
		if err := validateToolUseID(toolUseID); err != nil {
			return nil, err
		}
	}

	result := &hookParseResult{
		Tool:          toolType,
		Params:        params,
		PolicyPaths:   policyPaths,
		WorkDir:       firstNonEmptyString(input.WorkspaceRoots),
		Agent:         "cline",
		HookEventName: event,
		SessionID:     input.TaskID,
		ToolUseID:     toolUseID,
		// Cline's taskId is scoped to a single task/conversation — equivalent
		// to Claude Code's session_id for run grouping purposes.
		RunID: deriveRunID(input.TaskID),
	}

	// The editor emits result inside postToolUse; the current CLI retains the
	// lossless output in tool_result. Keep parameters.output as a legacy fallback.
	if isPost {
		var response any
		if record != nil {
			response = record.Output
		}
		if response == nil {
			response = toolUse.Result
		}
		if response != nil {
			encoded, err := json.Marshal(response)
			if err != nil {
				return nil, fmt.Errorf("hook: encode Cline postToolUse result: %w", err)
			}
			if text, ok := response.(string); ok {
				result.Response = text
			} else {
				result.Response = string(encoded)
			}
			result.RawResponse = map[string]any{"result": response}
		} else if output, ok := params["output"].(string); ok {
			result.Response = output
			result.RawResponse = map[string]any{"output": output}
		}
	}

	return result, nil
}

func firstNonEmptyString(values []string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func clineParamsFromRecordInput(input any) map[string]any {
	if params, ok := input.(map[string]any); ok {
		return cloneHookParams(params)
	}
	if input == nil {
		return map[string]any{}
	}
	return map[string]any{"input": input}
}

func normalizeClineParams(toolName, toolType string, input map[string]any, enforce bool) (map[string]any, []string, error) {
	params := cloneHookParams(input)
	name := strings.ToLower(strings.TrimSpace(toolName))
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
	copyAlias("command", "cmd", "script")
	copyAlias("path", "file_path", "filePath", "uri", "directory", "dir_path", "dirPath")
	copyAlias("url", "uri", "href")
	if name == "web_search" {
		copyAlias("url", "query")
	}

	if name == "execute_command" || name == "run_commands" || name == "bash" {
		commands, err := collectClineCommands(params)
		if err != nil {
			return nil, nil, err
		}
		if len(commands) == 0 && enforce {
			return nil, nil, fmt.Errorf("hook: Cline %s requires at least one command", toolName)
		}
		if len(commands) > 0 {
			params["command"] = strings.Join(commands, " && ")
			params["commands"] = append([]string(nil), commands...)
		}
	}

	var policyPaths []string
	if name == "read_file" || name == "read_files" || toolType == "write" {
		var err error
		policyPaths, err = collectClinePaths(params)
		if err != nil {
			return nil, nil, err
		}
		if name == "apply_patch" {
			patch, _ := params["input"].(string)
			if strings.TrimSpace(patch) == "" {
				patch, _ = params["command"].(string)
			}
			if strings.TrimSpace(patch) != "" {
				patchPaths, patchErr := extractCodexPatchPaths(patch)
				if patchErr != nil {
					return nil, nil, fmt.Errorf("%s", strings.ReplaceAll(patchErr.Error(), "Codex", "Cline"))
				}
				policyPaths = mergeClinePaths(policyPaths, patchPaths)
				if len(policyPaths) > maxCodexPatchPaths {
					return nil, nil, fmt.Errorf("hook: Cline apply_patch touches more than %d paths; split it into smaller calls", maxCodexPatchPaths)
				}
			}
		}
		if len(policyPaths) == 0 && enforce && (name == "read_file" || name == "read_files" || toolType == "write") {
			return nil, nil, fmt.Errorf("hook: Cline %s requires at least one file path", toolName)
		}
		if len(policyPaths) > 0 {
			params["path"] = policyPaths[0]
			params["paths"] = append([]string(nil), policyPaths...)
		}
	}

	if name == "fetch_web_content" || name == "fetch_web" || name == "web_fetch" || name == "web_search" {
		urls, err := collectClineURLs(params)
		if err != nil {
			return nil, nil, err
		}
		if len(urls) == 0 && enforce {
			return nil, nil, fmt.Errorf("hook: Cline %s requires a URL", toolName)
		}
		if len(urls) > 1 && enforce {
			return nil, nil, fmt.Errorf("hook: Cline %s includes multiple URLs; split it into smaller calls", toolName)
		}
		if len(urls) > 0 {
			params["url"] = urls[0]
		}
	}

	return params, policyPaths, nil
}

func decodeClineNestedValue(value any) any {
	text, ok := value.(string)
	if !ok {
		return value
	}
	trimmed := strings.TrimSpace(text)
	if trimmed == "" || (trimmed[0] != '[' && trimmed[0] != '{') || !json.Valid([]byte(trimmed)) {
		return value
	}
	var decoded any
	if json.Unmarshal([]byte(trimmed), &decoded) == nil {
		return decoded
	}
	return value
}

func collectClineCommands(params map[string]any) ([]string, error) {
	root, exists := params["commands"]
	if !exists {
		for _, key := range []string{"command", "cmd", "input"} {
			if value, ok := params[key]; ok {
				root = value
				exists = true
				break
			}
		}
	}
	if !exists {
		return nil, nil
	}

	commands := make([]string, 0, 4)
	var visit func(any) error
	visit = func(value any) error {
		value = decodeClineNestedValue(value)
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) == "" {
				return nil
			}
			if len(commands) >= maxCodexPatchPaths {
				return fmt.Errorf("hook: Cline run_commands includes more than %d commands; split it into smaller calls", maxCodexPatchPaths)
			}
			commands = append(commands, typed)
			return nil
		case []any:
			for _, item := range typed {
				if err := visit(item); err != nil {
					return err
				}
			}
			return nil
		case []string:
			for _, item := range typed {
				if err := visit(item); err != nil {
					return err
				}
			}
			return nil
		case map[string]any:
			if nested, ok := typed["commands"]; ok {
				return visit(nested)
			}
			command, _ := typed["command"].(string)
			if strings.TrimSpace(command) == "" {
				if alias, ok := typed["cmd"].(string); ok {
					command = alias
				}
			}
			if strings.TrimSpace(command) == "" {
				return fmt.Errorf("hook: Cline run_commands contains an entry without a command")
			}
			if rawArgs, ok := typed["args"]; ok {
				args, ok := decodeClineNestedValue(rawArgs).([]any)
				if !ok {
					return fmt.Errorf("hook: Cline structured command args must be an array")
				}
				for _, rawArg := range args {
					arg, ok := rawArg.(string)
					if !ok {
						return fmt.Errorf("hook: Cline structured command args must be strings")
					}
					command += " " + shellQuoteCodexHookArg(arg)
				}
			}
			return visit(command)
		default:
			return fmt.Errorf("hook: Cline run_commands has an unsupported command envelope")
		}
	}
	if err := visit(root); err != nil {
		return nil, err
	}
	return commands, nil
}

func collectClinePaths(params map[string]any) ([]string, error) {
	paths := make([]string, 0, 4)
	seen := make(map[string]struct{})
	add := func(path string) error {
		path = strings.TrimSpace(path)
		if path == "" {
			return nil
		}
		if strings.IndexByte(path, 0) >= 0 {
			return fmt.Errorf("hook: Cline file path contains a NUL byte")
		}
		if _, exists := seen[path]; exists {
			return nil
		}
		if len(paths) >= maxCodexPatchPaths {
			return fmt.Errorf("hook: Cline file operation includes more than %d paths; split it into smaller calls", maxCodexPatchPaths)
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
		return nil
	}
	var visit func(any) error
	visit = func(value any) error {
		value = decodeClineNestedValue(value)
		switch typed := value.(type) {
		case string:
			return add(typed)
		case []any:
			for _, item := range typed {
				if err := visit(item); err != nil {
					return err
				}
			}
		case []string:
			for _, item := range typed {
				if err := add(item); err != nil {
					return err
				}
			}
		case map[string]any:
			for _, key := range []string{"path", "file_path", "filePath", "uri"} {
				if nested, ok := typed[key]; ok {
					if err := visit(nested); err != nil {
						return err
					}
				}
			}
		default:
			return fmt.Errorf("hook: Cline file path has an unsupported value")
		}
		return nil
	}
	for _, key := range []string{"path", "file_path", "filePath", "files", "file_paths", "paths"} {
		if value, ok := params[key]; ok {
			if err := visit(value); err != nil {
				return nil, err
			}
		}
	}
	return paths, nil
}

func mergeClinePaths(left, right []string) []string {
	seen := make(map[string]struct{}, len(left)+len(right))
	merged := make([]string, 0, len(left)+len(right))
	for _, paths := range [][]string{left, right} {
		for _, path := range paths {
			if _, exists := seen[path]; exists {
				continue
			}
			seen[path] = struct{}{}
			merged = append(merged, path)
		}
	}
	return merged
}

func collectClineURLs(params map[string]any) ([]string, error) {
	urls := make([]string, 0, 2)
	seen := make(map[string]struct{})
	add := func(url string) {
		url = strings.TrimSpace(url)
		if url == "" {
			return
		}
		if _, exists := seen[url]; exists {
			return
		}
		seen[url] = struct{}{}
		urls = append(urls, url)
	}
	var visit func(any) error
	visit = func(value any) error {
		value = decodeClineNestedValue(value)
		switch typed := value.(type) {
		case string:
			add(typed)
		case []any:
			for _, item := range typed {
				if err := visit(item); err != nil {
					return err
				}
			}
		case map[string]any:
			value, ok := typed["url"]
			if !ok {
				return fmt.Errorf("hook: Cline web request is missing a URL")
			}
			return visit(value)
		default:
			return fmt.Errorf("hook: Cline web request has an unsupported value")
		}
		return nil
	}
	for _, key := range []string{"url", "requests"} {
		if value, ok := params[key]; ok {
			if err := visit(value); err != nil {
				return nil, err
			}
		}
	}
	return urls, nil
}

// mapClaudeCodeTool maps Claude Code tool names to Rampart tool types.
func mapClaudeCodeTool(toolName string) string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(toolName)), "mcp__") {
		return classifyNativeMCPTool(toolName, nil)
	}
	switch toolName {
	case "Bash", "PowerShell", "Monitor":
		return "exec"
	case "Read", "ReadFile", "Glob", "Grep", "LSP":
		return "read"
	case "Write", "WriteFile", "Edit", "EditFile", "NotebookEdit", "EnterWorktree":
		return "write"
	case "WebFetch", "WebSearch", "Fetch", "web_search", "web_fetch":
		return "fetch"
	case "memory":
		return "memory"
	case "code_execution":
		return "exec"
	case "ToolSearch", "tool_search", "ListMcpResourcesTool", "ReadMcpResourceTool", "WaitForMcpServers", "Skill",
		"TaskGet", "TaskList", "TaskOutput":
		return "read"
	case "Task", "Agent", "Workflow", "RemoteTrigger":
		// Sub-agent spawn: the orchestrator is delegating a task to a new agent.
		// Mapped to "agent" so policies can match `tool: ["agent"]` and watch
		// displays it distinctly from exec/read/write.
		return "agent"
	case "CronCreate", "CronDelete", "ScheduleWakeup", "TaskCreate", "TaskStop", "TaskUpdate", "TodoWrite":
		return "process"
	case "CronList":
		return "read"
	case "Artifact", "PushNotification", "SendMessage", "SendUserFile", "ShareOnboardingGuide":
		return "message"
	case "AskUserQuestion", "EnterPlanMode", "ExitPlanMode", "ExitWorktree", "EndConversation", "ReportFindings":
		return "interact"
	default:
		// NOTE: Don't log here - this function is called before the logger is available,
		// and any stderr output causes Claude Code to report "hook error".
		// Unknown tools are handled gracefully by returning "unknown".
		return "unknown"
	}
}

func failClosedUnsupportedNativeHookAction(decision engine.Decision) engine.Decision {
	switch decision.Action {
	case engine.ActionAllow, engine.ActionWatch, engine.ActionDeny, engine.ActionAsk, engine.ActionRequireApproval:
		return decision
	case engine.ActionWebhook:
		decision.Action = engine.ActionDeny
		decision.Message = "Rampart native hooks do not execute webhook policy actions; refusing tool call"
		return decision
	default:
		action := decision.Action.String()
		decision.Action = engine.ActionDeny
		decision.Message = fmt.Sprintf("Rampart received unsupported policy action %s; refusing tool call", action)
		return decision
	}
}

// mapClineTool maps Cline tool names to Rampart tool types.
func mapClineTool(toolName string) string {
	name := strings.ToLower(strings.TrimSpace(toolName))
	switch name {
	case "execute_command", "run_commands", "bash":
		return "exec"
	case "read_file", "read_files":
		return "read"
	case "write_to_file", "replace_in_file", "apply_patch", "editor", "new_rule":
		return "write"
	case "search_files", "list_files", "list_code_definition_names", "search_codebase", "search":
		return "read"
	case "browser_action", "web_fetch", "web_search", "fetch_web_content", "fetch_web":
		return "fetch"
	case "use_mcp_tool", "access_mcp_resource":
		return "mcp"
	case "spawn_agent", "use_subagents", "new_task",
		"team_spawn_teammate", "team_shutdown_teammate", "team_status", "team_task",
		"team_run_task", "team_cancel_run", "team_list_runs", "team_await_runs",
		"team_read_mailbox", "team_mission_log", "team_cleanup", "team_create_outcome",
		"team_attach_outcome_fragment", "team_review_outcome_fragment", "team_finalize_outcome",
		"team_list_outcomes":
		return "agent"
	case "team_send_message", "team_broadcast", "report_bug":
		return "message"
	case "ask_followup_question", "ask_question", "attempt_completion", "fetch_instructions",
		"plan_mode_respond", "act_mode_respond", "switch_to_act_mode", "focus_chain",
		"load_mcp_documentation", "condense", "summarize_task", "skills", "use_skill",
		"submit_and_exit":
		return "interact"
	default:
		// Current Cline SDK MCP tool names are server__tool. The full name is
		// retained so the shared MCP classifier can conservatively infer risk.
		if strings.Contains(name, "__") || strings.HasPrefix(name, "mcp_") || strings.HasPrefix(name, "mcp.") {
			return "mcp"
		}
		// NOTE: Don't log here - any stderr output causes the agent to report "hook error".
		return "unknown"
	}
}

// hookDecisionType represents the possible hook outcomes.
type hookDecisionType int

const (
	hookAllow hookDecisionType = iota
	hookDeny
	hookAsk   // ask (and require_approval alias) → Claude Code native prompt
	hookBlock // PostToolUse: block response from being shown to agent
)

// projectPolicyPrefix returns the message with a "[Project Policy] " prefix
// if fromProject is true. This indicates to users that the rule came from a
// repository's .rampart/policy.yaml rather than global Rampart policies.
func projectPolicyPrefix(msg string, fromProject bool) string {
	if fromProject {
		return "[Project Policy] " + msg
	}
	return msg
}

// validateToolUseID validates the tool_use_id format to prevent injection attacks.
// Claude Code uses formats like "toolu_01ABC..." — alphanumeric with underscores/hyphens.
// Returns an error if invalid characters are detected.
func validateToolUseID(id string) error {
	if id == "" {
		return nil // allow empty (some contexts don't have it)
	}
	for _, r := range id {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return fmt.Errorf("hook: invalid character %q in tool_use_id", r)
		}
	}
	return nil
}

// outputHookResult writes the allow/deny/ask/block response in the correct format.
// When denied or blocked, it prints a branded message to stderr.
// When ask, Claude Code shows its native permission prompt; Cline cancels
// (Cline has no native ask equivalent).
// suggestions contains ready-to-run "rampart allow ..." commands shown on deny.
func outputHookResult(cmd *cobra.Command, format string, decision hookDecisionType, isPostToolUse bool, reason string, command string, suggestions ...string) error {
	return outputHookResultWithResponse(cmd, format, decision, isPostToolUse, reason, command, nil, suggestions...)
}

func outputHookResultWithResponse(
	cmd *cobra.Command,
	format string,
	decision hookDecisionType,
	isPostToolUse bool,
	reason string,
	command string,
	updatedToolOutput any,
	suggestions ...string,
) error {
	// NOTE: Do NOT print to stderr for Claude Code hook decisions — Claude Code
	// can interpret stderr as a hook failure. The structured JSON response carries
	// deny/ask reasons. Keep Cline's historical stderr deny output for now.
	if format == "cline" && (decision == hookDeny || decision == hookBlock) {
		fmt.Fprint(os.Stderr, formatDenyMessage(command, reason, suggestions))
	}
	switch format {
	case "gemini":
		return outputGeminiHookResult(cmd.OutOrStdout(), decision, reason)
	case "antigravity":
		return outputAntigravityHookResult(cmd.OutOrStdout(), decision, reason)
	case "copilot":
		return outputCopilotHookResult(cmd.OutOrStdout(), decision, reason)
	case "cline":
		// Cline has no "ask" — cancel on deny, block, and ask.
		cancel := decision == hookDeny || decision == hookAsk || decision == hookBlock
		out := clineHookOutput{Cancel: cancel}
		if decision == hookDeny || decision == hookBlock {
			out.ErrorMessage = "Blocked by Rampart: " + reason
		}
		if decision == hookAsk {
			out.ErrorMessage = "Rampart: approval required — " + reason
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
	case "codex":
		var out hookOutput
		switch decision {
		case hookDeny:
			out.HookSpecificOutput = &hookDecision{
				HookEventName:            "PreToolUse",
				PermissionDecision:       "deny",
				PermissionDecisionReason: "Rampart: " + reason,
			}
		case hookAsk:
			// Codex currently rejects permissionDecision:"ask" from PreToolUse.
			// Approval-requiring calls must be resolved through rampart serve
			// before reaching this formatter; fail closed if one reaches it.
			out.HookSpecificOutput = &hookDecision{
				HookEventName:            "PreToolUse",
				PermissionDecision:       "deny",
				PermissionDecisionReason: "Rampart: approval required — " + reason,
			}
		case hookAllow:
			// Empty output leaves Codex's own sandbox and approval policy intact.
			// An explicit allow without updatedInput is rejected by current Codex,
			// and Rampart must never bypass Codex's native permission system.
		case hookBlock:
			out.Decision = "block"
			out.Reason = "Rampart: " + reason
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
			if updatedToolOutput != nil {
				out.HookSpecificOutput = &hookDecision{
					HookEventName:     "PostToolUse",
					UpdatedToolOutput: updatedToolOutput,
				}
			}
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
	}
}
