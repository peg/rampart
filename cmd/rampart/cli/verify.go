// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const verifyJSONSchemaVersion = "rampart.verify.v1"

type verificationStatus string

const (
	verificationPass       verificationStatus = "pass"
	verificationFail       verificationStatus = "fail"
	verificationUnverified verificationStatus = "unverified"
)

type verificationCheck struct {
	ID       string             `json:"id"`
	Name     string             `json:"name"`
	Status   verificationStatus `json:"status"`
	Expected string             `json:"expected,omitempty"`
	Actual   string             `json:"actual,omitempty"`
	Message  string             `json:"message"`
	Hint     string             `json:"hint,omitempty"`
}

type verificationSummary struct {
	Checks     int `json:"checks"`
	Passed     int `json:"passed"`
	Failed     int `json:"failed"`
	Unverified int `json:"unverified"`
}

type verificationReport struct {
	SchemaVersion string              `json:"schema_version"`
	GeneratedAt   string              `json:"generated_at"`
	Target        string              `json:"target"`
	SafeCanaries  bool                `json:"safe_canaries"`
	Summary       verificationSummary `json:"summary"`
	Checks        []verificationCheck `json:"checks"`
}

type behavioralCanary struct {
	ID       string
	Name     string
	Tool     string
	Agent    string
	Params   map[string]any
	Expected []string
}

type preflightResponse struct {
	Allowed  bool   `json:"allowed"`
	Decision string `json:"decision"`
	Message  string `json:"message"`
}

func newVerifyCmd() *cobra.Command {
	var jsonOut bool
	var serveURL string
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "verify [openclaw|claude-code|cline|codex|gemini|copilot|policy]",
		Short: "Actively verify that agent safety boundaries really block",
		Long: `Run non-destructive behavioral canaries against the live Rampart policy path.

The canaries never execute commands, read files, send messages, or contact an
external network. They use Rampart's policy endpoint and a decoy path/domain
to prove the decisions the installed integration would receive. OpenClaw
verification also runs fixed canaries through the live before_tool_call
implementation.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := ""
			if len(args) == 1 {
				target = strings.ToLower(strings.TrimSpace(args[0]))
			}
			if target == "" {
				if isOpenClawInstalled() {
					target = "openclaw"
				} else {
					target = "policy"
				}
			}
			if target != "policy" {
				driver, ok := findIntegrationDriver(target)
				if !ok {
					return fmt.Errorf("verify: unsupported target %q (supported: openclaw, claude-code, cline, codex, gemini, copilot, policy)", target)
				}
				target = driver.VerifyTarget
			}

			resolvedURL, err := resolveServeURLStrict(serveURL, fmt.Sprintf("http://localhost:%d", defaultServePort))
			if err != nil {
				return fmt.Errorf("verify: resolve serve URL: %w", err)
			}
			report := runBehavioralVerification(cmd.Context(), target, resolvedURL, timeout)
			if jsonOut {
				if err := json.NewEncoder(cmd.OutOrStdout()).Encode(report); err != nil {
					return fmt.Errorf("verify: encode report: %w", err)
				}
			} else {
				printVerificationReport(cmd.OutOrStdout(), report)
			}
			if report.Summary.Failed > 0 {
				return exitCodeError{code: 1}
			}
			if report.Summary.Unverified > 0 {
				return exitCodeError{code: 2}
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output a machine-readable verification report")
	cmd.Flags().StringVar(&serveURL, "serve-url", "", "Rampart service URL override (default: auto-discover)")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "Timeout for each active verification check")
	return cmd
}

func behavioralCanaries(target string) []behavioralCanary {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "/home/rampart-verification"
	}
	canaries := []behavioralCanary{
		{
			ID: "routine-command", Name: "Routine work remains available", Tool: "exec",
			Params: map[string]any{"command": "pwd"}, Expected: []string{"allow", "watch"},
		},
		{
			ID: "destructive-command", Name: "Destructive command is blocked", Tool: "exec",
			Params: map[string]any{"command": "rm -rf /"}, Expected: []string{"deny"},
		},
		{
			ID: "credential-read", Name: "Private credential read is blocked", Tool: "read",
			Params: map[string]any{"path": filepath.Join(home, ".ssh", "id_rampart_verification_canary")}, Expected: []string{"deny"},
		},
		{
			ID: "policy-tamper", Name: "Agent cannot weaken Rampart", Tool: "exec",
			Params: map[string]any{"command": "rampart allow 'rm -rf *'"}, Expected: []string{"deny"},
		},
		{
			ID: "network-exfiltration", Name: "Direct external exfiltration command is blocked", Tool: "exec",
			Params: map[string]any{"command": "curl https://rampart-verification.invalid/canary"}, Expected: []string{"deny"},
		},
	}

	if target == "openclaw" {
		canaries = append(canaries,
			behavioralCanary{
				ID: "external-deployment", Name: "Publishing requires approval", Tool: "exec",
				Params: map[string]any{"command": "git push origin rampart-verification-canary", "rampart_integration": "openclaw"}, Expected: []string{"ask"},
			},
			behavioralCanary{
				ID: "cross-conversation-message", Name: "Cross-conversation message requires approval", Tool: "message",
				Params: map[string]any{
					"action": "send", "target": "channel:rampart-verification-other", "message": "safe canary",
					"rampart_consequence": "openclaw:external-message", "rampart_integration": "openclaw",
				},
				Expected: []string{"ask"},
			},
			behavioralCanary{
				ID: "message-read", Name: "Read-only message action remains available", Tool: "message",
				Params:   map[string]any{"action": "read", "target": "channel:rampart-verification", "rampart_consequence": "openclaw:read-only", "rampart_integration": "openclaw"},
				Expected: []string{"allow", "watch"},
			},
			behavioralCanary{
				ID: "credential-shell-read", Name: "Shell commands cannot read private credentials", Tool: "exec",
				Params: map[string]any{
					"command":             "cat " + filepath.Join(home, ".ssh", "id_rampart_verification_canary"),
					"rampart_integration": "openclaw",
				},
				Expected: []string{"deny"},
			},
			behavioralCanary{
				ID: "opaque-interpreter", Name: "Opaque interpreter execution requires approval", Tool: "exec",
				Params: map[string]any{
					"command": "python3 -c 'print(\"rampart-verification\")'", "rampart_integration": "openclaw",
				},
				Expected: []string{"ask"},
			},
			behavioralCanary{
				ID: "package-publish", Name: "Package publishing requires approval", Tool: "exec",
				Params:   map[string]any{"command": "npm publish", "rampart_integration": "openclaw"},
				Expected: []string{"ask"},
			},
		)
		for i := range canaries {
			canaries[i].Agent = "rampart-verification"
			canaries[i].Params["rampart_integration"] = "openclaw"
		}
	} else if target == "claude-code" || target == "cline" || target == "codex" || target == "gemini" || target == "copilot" {
		for i := range canaries {
			canaries[i].Agent = target
		}
	}
	return canaries
}

func runBehavioralVerification(ctx context.Context, target, serveURL string, timeout time.Duration) verificationReport {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	report := verificationReport{
		SchemaVersion: verifyJSONSchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Target:        target,
		SafeCanaries:  true,
		Checks:        make([]verificationCheck, 0),
	}

	if target != "policy" {
		if driver, ok := findIntegrationDriver(target); ok && driver.VerifyChecks != nil {
			report.Checks = append(report.Checks, driver.VerifyChecks(ctx, timeout)...)
		}
	}

	token, err := readPersistedToken()
	if err != nil || strings.TrimSpace(token) == "" {
		for _, canary := range behavioralCanaries(target) {
			report.Checks = append(report.Checks, verificationCheck{
				ID: canary.ID, Name: canary.Name, Status: verificationUnverified,
				Expected: strings.Join(canary.Expected, " or "), Actual: "no token",
				Message: "Rampart token is unavailable, so the live policy path could not be tested",
				Hint:    "Start Rampart with `rampart serve install`, then rerun `rampart verify`",
			})
		}
		return summarizeVerification(report)
	}

	client := &http.Client{Timeout: timeout}
	for _, canary := range behavioralCanaries(target) {
		report.Checks = append(report.Checks, runPreflightCanary(ctx, client, strings.TrimRight(serveURL, "/"), token, canary))
	}
	return summarizeVerification(report)
}

func verifyClaudeHooksInstalled() verificationCheck {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return verificationCheck{
			ID: "claude-hook-installation", Name: "Claude Code lifecycle hooks are installed",
			Status: verificationUnverified, Actual: "home unavailable", Message: "Could not locate Claude Code settings",
			Hint: "Run `rampart setup claude-code`, then rerun `rampart verify claude-code`",
		}
	}
	data, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	var settings claudeSettings
	configured := err == nil && json.Unmarshal(data, &settings) == nil && hasRampartHook(settings)
	if !configured {
		return verificationCheck{
			ID: "claude-hook-installation", Name: "Claude Code lifecycle hooks are installed",
			Status: verificationFail, Expected: "PreToolUse, PostToolUse, and PostToolUseFailure", Actual: "missing or incomplete",
			Message: "Claude Code is not configured to invoke Rampart for every required lifecycle event",
			Hint:    "Run `rampart setup claude-code`, then rerun verification",
		}
	}
	return verificationCheck{
		ID: "claude-hook-installation", Name: "Claude Code lifecycle hooks are installed",
		Status: verificationPass, Expected: "all required lifecycle hooks", Actual: "configured",
		Message: "Claude Code settings contain the complete Rampart lifecycle hook set",
	}
}

func verifyClineHooksInstalled() verificationCheck {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return verificationCheck{
			ID: "cline-hook-installation", Name: "Cline lifecycle hooks are installed",
			Status: verificationUnverified, Actual: "home unavailable", Message: "Could not locate Cline hooks",
			Hint: "Run `rampart setup cline`, then rerun `rampart verify cline`",
		}
	}
	base := filepath.Join(home, "Documents", "Cline", "Hooks")
	pre := filepath.Join(base, "PreToolUse", "rampart-policy")
	post := filepath.Join(base, "PostToolUse", "rampart-audit")
	if _, preErr := os.Stat(pre); preErr != nil {
		return verificationCheck{
			ID: "cline-hook-installation", Name: "Cline lifecycle hooks are installed",
			Status: verificationFail, Expected: "PreToolUse and PostToolUse", Actual: "missing or incomplete",
			Message: "Cline is not configured to invoke Rampart for both lifecycle events",
			Hint:    "Run `rampart setup cline`, then rerun verification",
		}
	}
	if _, postErr := os.Stat(post); postErr != nil {
		return verificationCheck{
			ID: "cline-hook-installation", Name: "Cline lifecycle hooks are installed",
			Status: verificationFail, Expected: "PreToolUse and PostToolUse", Actual: "missing or incomplete",
			Message: "Cline is not configured to invoke Rampart for both lifecycle events",
			Hint:    "Run `rampart setup cline`, then rerun verification",
		}
	}
	return verificationCheck{
		ID: "cline-hook-installation", Name: "Cline lifecycle hooks are installed",
		Status: verificationPass, Expected: "PreToolUse and PostToolUse", Actual: "configured",
		Message: "Cline's global hook directory contains both Rampart lifecycle scripts",
	}
}

func verifyNativeHookAdapter(ctx context.Context, target string) verificationCheck {
	format := target
	agent := target
	checkID := target + "-native-deny"
	checkName := target + " native deny response works"
	payload := ""
	switch target {
	case "claude-code":
		payload = `{"session_id":"rampart-verification","cwd":".","hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":"rampart-verification","tool_input":{"command":"rm -rf /"}}`
	case "cline":
		agent = "cline"
		payload = `{"clineVersion":"3","hookName":"PreToolUse","taskId":"rampart-verification","preToolUse":{"toolName":"execute_command","parameters":{"command":"rm -rf /"}}}`
	default:
		return verificationCheck{ID: checkID, Name: checkName, Status: verificationUnverified, Message: "unsupported adapter verifier"}
	}

	auditDir, err := os.MkdirTemp("", "rampart-verify-"+target+"-*")
	if err != nil {
		return verificationCheck{ID: checkID, Name: checkName, Status: verificationUnverified, Actual: "temporary directory unavailable", Message: err.Error()}
	}
	defer os.RemoveAll(auditDir)
	var stdout, stderr bytes.Buffer
	hookCmd := NewRootCmd(ctx, &stdout, &stderr)
	hookCmd.SetIn(strings.NewReader(payload))
	hookCmd.SetArgs([]string{"hook", "--format", format, "--audit-dir", auditDir})
	if err := hookCmd.Execute(); err != nil {
		return verificationCheck{ID: checkID, Name: checkName, Status: verificationFail, Expected: "structured deny", Actual: "hook error", Message: err.Error()}
	}
	var output map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		return verificationCheck{ID: checkID, Name: checkName, Status: verificationFail, Expected: "structured deny", Actual: strings.TrimSpace(stdout.String()), Message: "Rampart's hook response was not valid JSON"}
	}
	denied := false
	if target == "claude-code" {
		specific, _ := output["hookSpecificOutput"].(map[string]any)
		denied = specific["permissionDecision"] == "deny"
	} else {
		denied, _ = output["cancel"].(bool)
	}
	if !denied {
		return verificationCheck{ID: checkID, Name: checkName, Status: verificationFail, Expected: "structured deny", Actual: strings.TrimSpace(stdout.String()), Message: "The live Rampart hook adapter did not block the destructive canary"}
	}
	auditMatches, _ := filepath.Glob(filepath.Join(auditDir, "audit-hook-*.jsonl"))
	if len(auditMatches) != 1 {
		return verificationCheck{ID: checkID, Name: checkName, Status: verificationFail, Expected: "deny audit", Actual: "audit record missing", Message: "The hook denied the canary but did not produce an audit record"}
	}
	auditData, err := os.ReadFile(auditMatches[0])
	if err != nil {
		return verificationCheck{ID: checkID, Name: checkName, Status: verificationFail, Expected: "deny audit", Actual: "audit unreadable", Message: err.Error()}
	}
	auditLines := bytes.Split(bytes.TrimSpace(auditData), []byte{'\n'})
	var auditRecord map[string]any
	if len(auditLines) == 0 || json.Unmarshal(auditLines[len(auditLines)-1], &auditRecord) != nil || auditRecord["agent"] != agent {
		return verificationCheck{ID: checkID, Name: checkName, Status: verificationFail, Expected: "correlated deny audit", Actual: "correlation missing", Message: "The hook audit did not preserve host identity"}
	}
	return verificationCheck{ID: checkID, Name: checkName, Status: verificationPass, Expected: "structured deny and audit", Actual: "deny + audit", Message: "The live Rampart hook adapter blocked the destructive canary and recorded its decision"}
}

func verifyGeminiHooksInstalled() verificationCheck {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return verificationCheck{
			ID: "gemini-hook-installation", Name: "Gemini CLI lifecycle hooks are installed",
			Status: verificationUnverified, Actual: "home unavailable",
			Message: "Could not locate the Gemini CLI user configuration",
			Hint:    "Run `rampart setup gemini`, then rerun `rampart verify gemini`",
		}
	}
	if !geminiHooksConfiguredForHome(home) {
		return verificationCheck{
			ID: "gemini-hook-installation", Name: "Gemini CLI lifecycle hooks are installed",
			Status: verificationFail, Expected: "BeforeTool and AfterTool", Actual: "missing or incomplete",
			Message: "Gemini CLI is not configured to invoke Rampart for both lifecycle events",
			Hint:    "Run `rampart setup gemini`, then rerun verification",
		}
	}
	return verificationCheck{
		ID: "gemini-hook-installation", Name: "Gemini CLI lifecycle hooks are installed",
		Status: verificationPass, Expected: "BeforeTool and AfterTool", Actual: "configured",
		Message: "The Gemini CLI user settings contain both Rampart lifecycle hooks",
	}
}

func verifyGeminiHookAdapter(ctx context.Context) verificationCheck {
	auditDir, err := os.MkdirTemp("", "rampart-verify-gemini-*")
	if err != nil {
		return verificationCheck{
			ID: "gemini-native-deny", Name: "Gemini CLI native deny response works",
			Status: verificationUnverified, Actual: "temporary directory unavailable", Message: err.Error(),
		}
	}
	defer os.RemoveAll(auditDir)

	payload := `{
		"session_id":"rampart-verification",
		"cwd":".",
		"hook_event_name":"BeforeTool",
		"tool_name":"run_shell_command",
		"tool_input":{"command":"rm -rf /"}
	}`
	var stdout, stderr bytes.Buffer
	hookCmd := NewRootCmd(ctx, &stdout, &stderr)
	hookCmd.SetIn(strings.NewReader(payload))
	hookCmd.SetArgs([]string{"hook", "--format", "gemini", "--audit-dir", auditDir})
	if err := hookCmd.Execute(); err != nil {
		return verificationCheck{
			ID: "gemini-native-deny", Name: "Gemini CLI native deny response works",
			Status: verificationFail, Expected: "structured deny", Actual: "hook error", Message: err.Error(),
		}
	}
	var output map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		return verificationCheck{
			ID: "gemini-native-deny", Name: "Gemini CLI native deny response works",
			Status: verificationFail, Expected: "structured deny", Actual: strings.TrimSpace(stdout.String()),
			Message: "Rampart's Gemini CLI hook response was not valid JSON",
		}
	}
	if output["decision"] != "deny" {
		return verificationCheck{
			ID: "gemini-native-deny", Name: "Gemini CLI native deny response works",
			Status: verificationFail, Expected: "decision=deny", Actual: strings.TrimSpace(stdout.String()),
			Message: "The live Rampart hook adapter did not block the destructive canary",
		}
	}
	auditMatches, _ := filepath.Glob(filepath.Join(auditDir, "audit-hook-*.jsonl"))
	if len(auditMatches) != 1 {
		return verificationCheck{
			ID: "gemini-native-deny", Name: "Gemini CLI native deny response works",
			Status: verificationFail, Expected: "deny audit", Actual: "audit record missing",
			Message: "The Gemini CLI hook denied the canary but did not produce an audit record",
		}
	}
	auditData, err := os.ReadFile(auditMatches[0])
	if err != nil {
		return verificationCheck{
			ID: "gemini-native-deny", Name: "Gemini CLI native deny response works",
			Status: verificationFail, Expected: "deny audit", Actual: "audit unreadable", Message: err.Error(),
		}
	}
	auditLines := bytes.Split(bytes.TrimSpace(auditData), []byte{'\n'})
	var auditRecord map[string]any
	if len(auditLines) == 0 || json.Unmarshal(auditLines[len(auditLines)-1], &auditRecord) != nil ||
		auditRecord["agent"] != "gemini-cli" || auditRecord["run_id"] != "rampart-verification" {
		return verificationCheck{
			ID: "gemini-native-deny", Name: "Gemini CLI native deny response works",
			Status: verificationFail, Expected: "session-correlated deny audit", Actual: "correlation missing",
			Message: "The Gemini CLI hook audit did not preserve the host session identity",
		}
	}
	return verificationCheck{
		ID: "gemini-native-deny", Name: "Gemini CLI native deny response works",
		Status: verificationPass, Expected: "structured deny and session-correlated audit", Actual: "deny + audit",
		Message: "The live Rampart hook adapter returned Gemini CLI's deny schema and preserved session identity in audit",
	}
}

func verifyCopilotHooksInstalled() verificationCheck {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return verificationCheck{
			ID: "copilot-hook-installation", Name: "Copilot CLI / VS Code lifecycle hooks are installed",
			Status: verificationUnverified, Actual: "home unavailable",
			Message: "Could not locate the Copilot user hook directory",
			Hint:    "Run `rampart setup copilot`, then rerun `rampart verify copilot`",
		}
	}
	if !copilotHooksConfiguredForHome(home) {
		return verificationCheck{
			ID: "copilot-hook-installation", Name: "Copilot CLI / VS Code lifecycle hooks are installed",
			Status: verificationFail, Expected: "PreToolUse and PostToolUse", Actual: "missing or incomplete",
			Message: "Copilot is not configured to invoke Rampart for both lifecycle events",
			Hint:    "Run `rampart setup copilot`, then restart Copilot CLI or reload VS Code",
		}
	}
	return verificationCheck{
		ID: "copilot-hook-installation", Name: "Copilot CLI / VS Code lifecycle hooks are installed",
		Status: verificationPass, Expected: "PreToolUse and PostToolUse", Actual: "configured",
		Message: "The shared Copilot user hook file contains both Rampart lifecycle hooks",
	}
}

func verifyCopilotHookAdapter(ctx context.Context) verificationCheck {
	auditDir, err := os.MkdirTemp("", "rampart-verify-copilot-*")
	if err != nil {
		return verificationCheck{
			ID: "copilot-native-deny", Name: "Copilot CLI / VS Code native deny response works",
			Status: verificationUnverified, Actual: "temporary directory unavailable", Message: err.Error(),
		}
	}
	defer os.RemoveAll(auditDir)

	payload := `{
		"session_id":"rampart-verification",
		"cwd":".",
		"hook_event_name":"PreToolUse",
		"tool_name":"Bash",
		"tool_use_id":"rampart-verification",
		"tool_input":{"command":"rm -rf /"}
	}`
	var stdout, stderr bytes.Buffer
	hookCmd := NewRootCmd(ctx, &stdout, &stderr)
	hookCmd.SetIn(strings.NewReader(payload))
	hookCmd.SetArgs([]string{"hook", "--format", "copilot", "--audit-dir", auditDir})
	if err := hookCmd.Execute(); err != nil {
		return verificationCheck{
			ID: "copilot-native-deny", Name: "Copilot CLI / VS Code native deny response works",
			Status: verificationFail, Expected: "dual-host structured deny", Actual: "hook error", Message: err.Error(),
		}
	}
	var output map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		return verificationCheck{
			ID: "copilot-native-deny", Name: "Copilot CLI / VS Code native deny response works",
			Status: verificationFail, Expected: "dual-host structured deny", Actual: strings.TrimSpace(stdout.String()),
			Message: "Rampart's Copilot hook response was not valid JSON",
		}
	}
	specific, _ := output["hookSpecificOutput"].(map[string]any)
	if output["permissionDecision"] != "deny" || specific["permissionDecision"] != "deny" {
		return verificationCheck{
			ID: "copilot-native-deny", Name: "Copilot CLI / VS Code native deny response works",
			Status: verificationFail, Expected: "CLI and VS Code deny fields", Actual: strings.TrimSpace(stdout.String()),
			Message: "The live adapter did not return both Copilot CLI and VS Code deny controls",
		}
	}
	auditMatches, _ := filepath.Glob(filepath.Join(auditDir, "audit-hook-*.jsonl"))
	if len(auditMatches) != 1 {
		return verificationCheck{
			ID: "copilot-native-deny", Name: "Copilot CLI / VS Code native deny response works",
			Status: verificationFail, Expected: "deny audit", Actual: "audit record missing",
			Message: "The Copilot hook denied the canary but did not produce an audit record",
		}
	}
	auditData, err := os.ReadFile(auditMatches[0])
	if err != nil {
		return verificationCheck{
			ID: "copilot-native-deny", Name: "Copilot CLI / VS Code native deny response works",
			Status: verificationFail, Expected: "deny audit", Actual: "audit unreadable", Message: err.Error(),
		}
	}
	auditLines := bytes.Split(bytes.TrimSpace(auditData), []byte{'\n'})
	var auditRecord map[string]any
	if len(auditLines) == 0 || json.Unmarshal(auditLines[len(auditLines)-1], &auditRecord) != nil ||
		auditRecord["agent"] != "github-copilot" || auditRecord["run_id"] != "rampart-verification" {
		return verificationCheck{
			ID: "copilot-native-deny", Name: "Copilot CLI / VS Code native deny response works",
			Status: verificationFail, Expected: "session-correlated deny audit", Actual: "correlation missing",
			Message: "The Copilot hook audit did not preserve host session identity",
		}
	}
	return verificationCheck{
		ID: "copilot-native-deny", Name: "Copilot CLI / VS Code native deny response works",
		Status: verificationPass, Expected: "CLI + VS Code deny and session-correlated audit", Actual: "dual deny + audit",
		Message: "The live adapter blocked the destructive canary for both Copilot hook schemas and preserved session identity",
	}
}

func verifyCodexHooksInstalled() verificationCheck {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return verificationCheck{
			ID: "codex-hook-installation", Name: "Codex lifecycle hooks are installed",
			Status: verificationUnverified, Actual: "home unavailable",
			Message: "Could not locate the Codex user configuration",
			Hint:    "Run `rampart setup codex`, then rerun `rampart verify codex`",
		}
	}
	if !codexHooksConfiguredForHome(home) {
		return verificationCheck{
			ID: "codex-hook-installation", Name: "Codex lifecycle hooks are installed",
			Status: verificationFail, Expected: "PreToolUse and PostToolUse", Actual: "missing or incomplete",
			Message: "Codex is not configured to invoke Rampart for both lifecycle events",
			Hint:    "Run `rampart setup codex`, review the hooks with `/hooks`, then rerun verification",
		}
	}
	return verificationCheck{
		ID: "codex-hook-installation", Name: "Codex lifecycle hooks are installed",
		Status: verificationPass, Expected: "PreToolUse and PostToolUse", Actual: "configured",
		Message: "The user-level Codex hook configuration contains both Rampart lifecycle hooks",
	}
}

func verifyCodexHookAdapter(ctx context.Context) verificationCheck {
	auditDir, err := os.MkdirTemp("", "rampart-verify-codex-*")
	if err != nil {
		return verificationCheck{
			ID: "codex-native-deny", Name: "Codex native deny response works",
			Status: verificationUnverified, Actual: "temporary directory unavailable",
			Message: err.Error(),
		}
	}
	defer os.RemoveAll(auditDir)

	payload := `{
		"session_id":"rampart-verification",
		"turn_id":"rampart-verification",
		"cwd":".",
		"hook_event_name":"PreToolUse",
		"tool_name":"Bash",
		"tool_use_id":"rampart-verification",
		"tool_input":{"command":"rm -rf /"}
	}`
	var stdout, stderr bytes.Buffer
	hookCmd := NewRootCmd(ctx, &stdout, &stderr)
	hookCmd.SetIn(strings.NewReader(payload))
	hookCmd.SetArgs([]string{"hook", "--format", "codex", "--audit-dir", auditDir})
	if err := hookCmd.Execute(); err != nil {
		return verificationCheck{
			ID: "codex-native-deny", Name: "Codex native deny response works",
			Status: verificationFail, Expected: "structured deny", Actual: "hook error",
			Message: err.Error(),
		}
	}
	var output map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		return verificationCheck{
			ID: "codex-native-deny", Name: "Codex native deny response works",
			Status: verificationFail, Expected: "structured deny", Actual: strings.TrimSpace(stdout.String()),
			Message: "Rampart's Codex hook response was not valid JSON",
		}
	}
	specific, _ := output["hookSpecificOutput"].(map[string]any)
	if specific["hookEventName"] != "PreToolUse" || specific["permissionDecision"] != "deny" {
		return verificationCheck{
			ID: "codex-native-deny", Name: "Codex native deny response works",
			Status: verificationFail, Expected: "structured deny", Actual: strings.TrimSpace(stdout.String()),
			Message: "The live Rampart hook adapter did not block the destructive canary",
		}
	}
	auditMatches, _ := filepath.Glob(filepath.Join(auditDir, "audit-hook-*.jsonl"))
	if len(auditMatches) != 1 {
		return verificationCheck{
			ID: "codex-native-deny", Name: "Codex native deny response works",
			Status: verificationFail, Expected: "correlated deny audit", Actual: "audit record missing",
			Message: "The Codex hook denied the canary but did not produce its correlated audit record",
		}
	}
	auditData, err := os.ReadFile(auditMatches[0])
	if err != nil {
		return verificationCheck{
			ID: "codex-native-deny", Name: "Codex native deny response works",
			Status: verificationFail, Expected: "correlated deny audit", Actual: "audit unreadable",
			Message: err.Error(),
		}
	}
	auditLines := bytes.Split(bytes.TrimSpace(auditData), []byte{'\n'})
	var auditRecord map[string]any
	if len(auditLines) == 0 || json.Unmarshal(auditLines[len(auditLines)-1], &auditRecord) != nil ||
		auditRecord["agent"] != "codex" || auditRecord["tool_call_id"] != "rampart-verification" {
		return verificationCheck{
			ID: "codex-native-deny", Name: "Codex native deny response works",
			Status: verificationFail, Expected: "correlated deny audit", Actual: "correlation missing",
			Message: "The Codex hook audit did not preserve the host tool-call identity",
		}
	}
	return verificationCheck{
		ID: "codex-native-deny", Name: "Codex native deny response works",
		Status: verificationPass, Expected: "structured deny and correlated audit", Actual: "deny + audit",
		Message: "The live Rampart hook adapter returned Codex's supported deny schema and preserved the exact tool-call identity in audit",
	}
}

func runPreflightCanary(ctx context.Context, client *http.Client, serveURL, token string, canary behavioralCanary) verificationCheck {
	agent := canary.Agent
	if agent == "" {
		agent = "rampart-verify"
	}
	body, err := json.Marshal(map[string]any{
		"agent": agent, "session": "rampart-verification", "params": canary.Params, "verification": true,
	})
	if err != nil {
		return verificationCheck{ID: canary.ID, Name: canary.Name, Status: verificationUnverified, Message: err.Error()}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serveURL+"/v1/preflight/"+canary.Tool, bytes.NewReader(body))
	if err != nil {
		return verificationCheck{ID: canary.ID, Name: canary.Name, Status: verificationUnverified, Message: err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return verificationCheck{
			ID: canary.ID, Name: canary.Name, Status: verificationUnverified,
			Expected: strings.Join(canary.Expected, " or "), Actual: "unreachable",
			Message: "The Rampart policy service could not be reached", Hint: "Run `rampart serve install` and retry",
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return verificationCheck{
			ID: canary.ID, Name: canary.Name, Status: verificationUnverified,
			Expected: strings.Join(canary.Expected, " or "), Actual: fmt.Sprintf("HTTP %d", resp.StatusCode),
			Message: "The policy service did not accept the safe preflight canary", Hint: "Run `rampart doctor` to check service authentication",
		}
	}

	var result preflightResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return verificationCheck{
			ID: canary.ID, Name: canary.Name, Status: verificationUnverified,
			Expected: strings.Join(canary.Expected, " or "), Actual: "invalid response",
			Message: "The policy service returned an unreadable preflight response",
		}
	}

	check := verificationCheck{
		ID: canary.ID, Name: canary.Name, Expected: strings.Join(canary.Expected, " or "),
		Actual: result.Decision, Message: result.Message,
	}
	for _, expected := range canary.Expected {
		if result.Decision == expected {
			check.Status = verificationPass
			if check.Message == "" {
				check.Message = "Live policy path returned the expected decision"
			}
			return check
		}
	}
	check.Status = verificationFail
	check.Hint = "Run `rampart protect openclaw` to restore the managed Guard policy, then verify again"
	return check
}

func verifyOpenClawPluginLive(ctx context.Context, timeout time.Duration) verificationCheck {
	check := verificationCheck{
		ID: "openclaw-plugin-self-test", Name: "OpenClaw plugin policy self-test",
		Expected: "all plugin canaries pass", Actual: "unverified",
	}
	state := getOpenClawPluginState()
	if !state.Installed || !state.Enabled || !state.Allowed {
		check.Status = verificationFail
		check.Actual = "not configured"
		check.Message = "The Rampart plugin is not installed and enabled in the active OpenClaw state"
		check.Hint = "Run `rampart protect openclaw`"
		return check
	}
	if !openClawPluginCurrent(state) {
		check.Status = verificationFail
		check.Actual = "plugin integrity mismatch"
		check.Message = "The installed Rampart plugin does not match the version bundled with this binary"
		check.Hint = "Run `rampart protect openclaw --reinstall`, restart the gateway, and verify again"
		return check
	}

	bin, err := findOpenClawBinary()
	if err != nil {
		check.Status = verificationUnverified
		check.Actual = "OpenClaw CLI unavailable"
		check.Message = "Plugin files exist, but the OpenClaw CLI could not be used for a live probe"
		return check
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := osexec.CommandContext(probeCtx, bin, "gateway", "call", "rampart.verify", "--json", "--timeout", fmt.Sprintf("%d", timeout.Milliseconds()))
	cmd.Env = append(os.Environ(), "OPENCLAW_HIDE_BANNER=1", "OPENCLAW_SUPPRESS_NOTES=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		check.Status = verificationUnverified
		check.Actual = "gateway probe unavailable"
		check.Message = "Plugin configuration is present, but the live gateway method could not be reached"
		check.Hint = "Restart the OpenClaw gateway and rerun `rampart verify openclaw`"
		if bytes.Contains(bytes.ToLower(output), []byte("unknown method")) {
			check.Hint = "Upgrade OpenClaw, restart its gateway, and rerun verification"
		}
		return check
	}
	var payload any
	if err := decodeOpenClawJSON(output, &payload); err != nil {
		check.Status = verificationUnverified
		check.Actual = "unreadable gateway response"
		check.Message = "The live plugin responded, but OpenClaw returned an unreadable verification payload"
		return check
	}
	pluginResult, ok := findPluginVerificationResult(payload)
	if !ok {
		check.Status = verificationUnverified
		check.Actual = "missing verification payload"
		check.Message = "The gateway responded without Rampart's behavioral verification result"
		check.Hint = "Reinstall the current plugin with `rampart protect openclaw --reinstall`"
		return check
	}
	if err := validatePluginVerificationResult(pluginResult); err != nil {
		check.Status = verificationFail
		check.Actual = "invalid canary proof"
		check.Message = "The running OpenClaw plugin did not return the complete expected canary proof: " + err.Error()
		check.Hint = "Run `rampart protect openclaw --reinstall`, restart the gateway, and verify again"
		return check
	}

	check.Status = verificationPass
	check.Actual = "complete and current"
	check.Message = "The current bundled plugin reached Rampart through its policy mapping path and returned every expected canary decision"
	return check
}

var expectedPluginCanaries = map[string]string{
	"routine-command":            "allow",
	"destructive-command":        "deny",
	"external-deployment":        "ask",
	"cross-conversation-message": "ask",
	"credential-shell-read":      "deny",
	"opaque-interpreter":         "ask",
}

func validatePluginVerificationResult(result map[string]any) error {
	if result["schema"] != "rampart.plugin.verify.v1" {
		return fmt.Errorf("unexpected schema")
	}
	if safe, ok := result["safeCanaries"].(bool); !ok || !safe {
		return fmt.Errorf("safe-canary marker missing")
	}
	if verified, ok := result["ok"].(bool); !ok || !verified {
		return fmt.Errorf("plugin reported a canary mismatch")
	}
	checks, ok := result["checks"].([]any)
	if !ok || len(checks) != len(expectedPluginCanaries) {
		return fmt.Errorf("expected %d checks, got %d", len(expectedPluginCanaries), len(checks))
	}
	seen := make(map[string]bool, len(checks))
	for _, raw := range checks {
		item, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("check payload is not an object")
		}
		id, _ := item["id"].(string)
		want, exists := expectedPluginCanaries[id]
		if !exists || seen[id] {
			return fmt.Errorf("unexpected or duplicate check %q", id)
		}
		seen[id] = true
		expected, _ := item["expected"].(string)
		actual, _ := item["actual"].(string)
		passed, _ := item["pass"].(bool)
		if expected != want || actual != want || !passed {
			return fmt.Errorf("check %q did not prove %q", id, want)
		}
	}
	return nil
}

func findPluginVerificationResult(value any) (map[string]any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		if typed["schema"] == "rampart.plugin.verify.v1" {
			return typed, true
		}
		for _, child := range typed {
			if result, ok := findPluginVerificationResult(child); ok {
				return result, true
			}
		}
	case []any:
		for _, child := range typed {
			if result, ok := findPluginVerificationResult(child); ok {
				return result, true
			}
		}
	}
	return nil, false
}

func summarizeVerification(report verificationReport) verificationReport {
	report.Summary.Checks = len(report.Checks)
	for _, check := range report.Checks {
		switch check.Status {
		case verificationPass:
			report.Summary.Passed++
		case verificationFail:
			report.Summary.Failed++
		default:
			report.Summary.Unverified++
		}
	}
	return report
}

func printVerificationReport(w io.Writer, report verificationReport) {
	fmt.Fprintf(w, "Rampart behavioral verification — %s\n\n", report.Target)
	fmt.Fprintln(w, "Safe canaries only: no commands, file reads, messages, or external network requests are executed.")
	fmt.Fprintln(w, "Verification uses the local admin path and does not add events to Rampart's audit log.")
	fmt.Fprintln(w)
	for _, check := range report.Checks {
		icon := "?"
		switch check.Status {
		case verificationPass:
			icon = "✓"
		case verificationFail:
			icon = "✗"
		case verificationUnverified:
			icon = "!"
		}
		fmt.Fprintf(w, "%s %-38s %s", icon, check.Name, strings.ToUpper(string(check.Status)))
		if check.Actual != "" {
			fmt.Fprintf(w, " (%s)", check.Actual)
		}
		fmt.Fprintln(w)
		if check.Hint != "" {
			fmt.Fprintf(w, "    → %s\n", check.Hint)
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%d passed, %d failed, %d unverified\n", report.Summary.Passed, report.Summary.Failed, report.Summary.Unverified)
}
