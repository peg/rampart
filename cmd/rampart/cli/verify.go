// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	osexec "os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/peg/rampart/internal/audit"
	ochardening "github.com/peg/rampart/internal/openclaw/hardening"
	"github.com/spf13/cobra"
)

const (
	verifyJSONSchemaVersion    = "rampart.verify.v1"
	verifyAllJSONSchemaVersion = "rampart.verify-all.v1"
)

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

func latestAuditEvent(auditDir string) (audit.Event, error) {
	files, err := listAuditFiles(auditDir)
	if err != nil {
		return audit.Event{}, err
	}
	files = preferManagedAuditFiles(files)
	for i := len(files) - 1; i >= 0; i-- {
		events, readErr := readAuditEvents(files[i])
		if readErr != nil {
			return audit.Event{}, readErr
		}
		if len(events) > 0 {
			return events[len(events)-1], nil
		}
	}
	return audit.Event{}, fmt.Errorf("audit record missing")
}

type verificationReport struct {
	SchemaVersion  string              `json:"schema_version"`
	GeneratedAt    string              `json:"generated_at"`
	Target         string              `json:"target"`
	SafeCanaries   bool                `json:"safe_canaries"`
	Assurance      assuranceLevel      `json:"assurance_level"`
	Summary        verificationSummary `json:"summary"`
	Checks         []verificationCheck `json:"checks"`
	policyEndpoint string
}

type verificationBatchSummary struct {
	Targets           int `json:"targets"`
	PassedTargets     int `json:"passed_targets"`
	FailedTargets     int `json:"failed_targets"`
	UnverifiedTargets int `json:"unverified_targets"`
	Checks            int `json:"checks"`
	PassedChecks      int `json:"passed_checks"`
	FailedChecks      int `json:"failed_checks"`
	UnverifiedChecks  int `json:"unverified_checks"`
}

type verificationBatchReport struct {
	SchemaVersion string                   `json:"schema_version"`
	GeneratedAt   string                   `json:"generated_at"`
	SafeCanaries  bool                     `json:"safe_canaries"`
	Summary       verificationBatchSummary `json:"summary"`
	Results       []verificationReport     `json:"results"`
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
	var all bool
	var jsonOut bool
	var serveURL string
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "verify [openclaw|claude-code|cline|codex|gemini|antigravity|copilot|policy]",
		Short: "Actively verify that agent safety boundaries really block",
		Long: `Run non-destructive behavioral canaries against the live Rampart policy path.

The canaries never execute commands, read files, send messages, or contact an
external network. They use Rampart's policy endpoint and a decoy path/domain
to prove the decisions the installed integration would receive. OpenClaw
verification also runs fixed canaries through the live before_tool_call
implementation.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if all {
				if len(args) > 0 {
					return fmt.Errorf("verify: --all cannot be combined with target %q", args[0])
				}
				resolvedURL, err := resolveServeURLStrict(serveURL, fmt.Sprintf("http://localhost:%d", defaultServePort))
				if err != nil {
					return fmt.Errorf("verify: resolve serve URL: %w", err)
				}
				report, receiptErr := runAllBehavioralVerifications(cmd.Context(), resolvedURL, timeout)
				if jsonOut {
					if err := json.NewEncoder(cmd.OutOrStdout()).Encode(report); err != nil {
						return fmt.Errorf("verify: encode aggregate report: %w", err)
					}
				} else {
					printVerificationBatchReport(cmd.OutOrStdout(), report)
				}
				if report.Summary.FailedTargets > 0 {
					return exitCodeError{code: 1}
				}
				if report.Summary.UnverifiedTargets > 0 {
					return exitCodeError{code: 2}
				}
				if receiptErr != nil {
					return fmt.Errorf("verify: persist aggregate assurance evidence: %w", receiptErr)
				}
				return nil
			}
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
					return fmt.Errorf("verify: unsupported target %q (supported: openclaw, claude-code, cline, codex, gemini, antigravity, copilot, policy)", target)
				}
				target = driver.VerifyTarget
			}

			resolvedURL, err := resolveServeURLStrict(serveURL, fmt.Sprintf("http://localhost:%d", defaultServePort))
			if err != nil {
				return fmt.Errorf("verify: resolve serve URL: %w", err)
			}
			report := runBehavioralVerification(cmd.Context(), target, resolvedURL, timeout)
			receiptErr := writeVerificationReceipt(report)
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
			if receiptErr != nil {
				return fmt.Errorf("verify: persist assurance evidence: %w", receiptErr)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&all, "all", false, "Verify policy and every behaviorally verifiable configured integration without invoking a model")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output a machine-readable verification report")
	cmd.Flags().StringVar(&serveURL, "serve-url", "", "Rampart service URL override (default: auto-discover)")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "Timeout for each active verification check")
	return cmd
}

func configuredVerificationTargets(home string) []string {
	targets := []string{"policy"}
	seen := map[string]struct{}{"policy": {}}
	for _, driver := range supportedIntegrationDrivers() {
		if !integrationDriverSupportsPlatform(driver, runtime.GOOS) || driver.Configured == nil || !driver.Configured(home) {
			continue
		}
		target := strings.TrimSpace(driver.VerifyTarget)
		if target == "" {
			target = driver.ID
		}
		if _, exists := seen[target]; exists {
			continue
		}
		seen[target] = struct{}{}
		targets = append(targets, target)
	}
	return targets
}

func runAllBehavioralVerifications(ctx context.Context, serveURL string, timeout time.Duration) (verificationBatchReport, error) {
	report := verificationBatchReport{
		SchemaVersion: verifyAllJSONSchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		SafeCanaries:  true,
		Results:       make([]verificationReport, 0),
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return report, fmt.Errorf("verify all: resolve home: %w", err)
	}
	var receiptErrors []error
	for _, target := range configuredVerificationTargets(home) {
		result := runBehavioralVerification(ctx, target, serveURL, timeout)
		report.Results = append(report.Results, result)
		report.Summary.Targets++
		report.Summary.Checks += result.Summary.Checks
		report.Summary.PassedChecks += result.Summary.Passed
		report.Summary.FailedChecks += result.Summary.Failed
		report.Summary.UnverifiedChecks += result.Summary.Unverified
		if !result.SafeCanaries {
			report.SafeCanaries = false
		}
		switch {
		case result.Summary.Failed > 0:
			report.Summary.FailedTargets++
		case result.Summary.Unverified > 0:
			report.Summary.UnverifiedTargets++
		default:
			report.Summary.PassedTargets++
		}
		if err := writeVerificationReceipt(result); err != nil {
			receiptErrors = append(receiptErrors, fmt.Errorf("%s: %w", target, err))
		}
	}
	return report, errors.Join(receiptErrors...)
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
	} else if target == "claude-code" || target == "cline" || target == "codex" || target == "gemini" || target == "antigravity" || target == "copilot" {
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
		SchemaVersion:  verifyJSONSchemaVersion,
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
		Target:         target,
		SafeCanaries:   true,
		Checks:         make([]verificationCheck, 0),
		policyEndpoint: strings.TrimRight(serveURL, "/"),
	}

	if target != "policy" {
		if driver, ok := findIntegrationDriver(target); ok && driver.VerifyChecks != nil {
			report.Checks = append(report.Checks, driver.VerifyChecks(ctx, timeout)...)
		}
	}

	token, _, tokenErr := resolveTokenForEndpoint(serveURL, "")
	if tokenErr != nil {
		for _, canary := range behavioralCanaries(target) {
			report.Checks = append(report.Checks, verificationCheck{
				ID: canary.ID, Name: canary.Name, Status: verificationUnverified,
				Expected: strings.Join(canary.Expected, " or "), Actual: "unsafe credential endpoint",
				Message: "Rampart refused to send the control token: " + tokenErr.Error(),
				Hint:    "Use a loopback URL, or set RAMPART_TOKEN explicitly for a trusted HTTPS endpoint",
			})
		}
		return summarizeVerification(report)
	}
	if strings.TrimSpace(token) == "" {
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

	client := newRampartHTTPClient(timeout)
	for _, canary := range behavioralCanaries(target) {
		report.Checks = append(report.Checks, runPreflightCanary(ctx, client, strings.TrimRight(serveURL, "/"), token, target, canary))
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
	if !claudeHooksConfiguredForHome(home) {
		return verificationCheck{
			ID: "claude-hook-installation", Name: "Claude Code lifecycle hooks are installed",
			Status: verificationFail, Expected: "current PreToolUse, PostToolUse, and PostToolUseFailure commands", Actual: "missing, stale, or incomplete",
			Message: "Claude Code is not configured to invoke this Rampart binary for every required lifecycle event",
			Hint:    "Run `rampart setup claude-code`, then rerun verification",
		}
	}
	assessment := claudeHookLoadAssessmentForHome(home)
	if assessment.Blocked {
		return verificationCheck{
			ID: "claude-hook-installation", Name: "Claude Code lifecycle hooks are installed and loadable",
			Status: verificationFail, Expected: "user hooks enabled", Actual: "configured but disabled",
			Message: assessment.Reason,
			Hint:    "Remove the disabling setting or have an administrator deploy Rampart as an approved managed hook, then restart Claude Code",
		}
	}
	if assessment.Unverified {
		return verificationCheck{
			ID: "claude-hook-installation", Name: "Claude Code lifecycle hooks are installed and loadable",
			Status: verificationUnverified, Expected: "readable effective hook settings", Actual: "hook activation could not be determined",
			Message: assessment.Reason,
			Hint:    "Run `/status` and `/hooks` inside Claude Code to confirm the active settings source and Rampart hook",
		}
	}
	return verificationCheck{
		ID: "claude-hook-installation", Name: "Claude Code lifecycle hooks are installed and loadable",
		Status: verificationPass, Expected: "all required lifecycle hooks using the current binary", Actual: "configured",
		Message: "Claude Code settings contain the complete current Rampart lifecycle hook set, with no readable setting disabling user hooks",
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
	var firstIssue string
	for _, hookDir := range clineKnownHookDirs(home) {
		if err := validateCurrentClineHookPair(hookDir, runtime.GOOS); err == nil {
			message := fmt.Sprintf("Rampart-managed Cline hooks are present at %s", hookDir)
			if runtime.GOOS == "windows" {
				message += "; Cline activates .ps1 hooks by file presence and requires PowerShell, but physical Windows host E2E remains pending"
			} else {
				message += "; both files are executable, but Cline's Hooks UI can still disable them"
			}
			return verificationCheck{
				ID: "cline-hook-installation", Name: "Cline lifecycle hook files are valid",
				Status: verificationPass, Expected: "direct current Rampart-managed PreToolUse and PostToolUse files", Actual: hookDir,
				Message: message,
				Hint:    "Keep Cline hooks enabled. Cline CLI's legacy --yolo mode disables runtime hooks.",
			}
		} else if firstIssue == "" {
			for _, event := range clineHookEvents {
				if _, statErr := os.Lstat(clineHookPath(hookDir, event, runtime.GOOS)); statErr == nil {
					firstIssue = err.Error()
					break
				}
			}
		}
	}
	if explicit := strings.TrimSpace(os.Getenv("CLINE_HOOKS_DIR")); explicit != "" {
		if expanded, expandErr := expandClineHomePath(explicit, home); expandErr == nil {
			expanded = filepath.Clean(expanded)
			if err := validateCurrentClineHookPair(expanded, runtime.GOOS); err == nil {
				return verificationCheck{
					ID: "cline-hook-installation", Name: "Cline lifecycle hook files are valid",
					Status: verificationUnverified, Expected: "hooks in a directory consumed by the current Cline host", Actual: expanded,
					Message: "Rampart-managed hooks exist in CLINE_HOOKS_DIR, but current upstream Cline advertises this override without consuming it reliably in file-hook discovery",
					Hint:    "Confirm a real Cline process invokes both hooks, or install in a standard user/workspace hook directory",
				}
			}
		}
	}
	actual := "missing"
	message := "No complete Rampart-managed Cline hook pair was found in Cline's current user, CLI, or workspace hook directories"
	if firstIssue != "" {
		actual = firstIssue
		message = "Cline hook files exist but do not match the current owned, platform-native, enabled Rampart installation"
	} else {
		legacyBase := clineUserHooksDir(home)
		preState, _ := inspectClineDestination(filepath.Join(legacyBase, "PreToolUse"), "PreToolUse")
		postState, _ := inspectClineDestination(filepath.Join(legacyBase, "PostToolUse"), "PostToolUse")
		if preState == clineDestinationManagedLegacyDir || postState == clineDestinationManagedLegacyDir {
			actual = "legacy directory layout"
			message = "Rampart's old nested Cline hook layout is present, but current Cline discovers direct hook files"
		}
	}
	return verificationCheck{
		ID: "cline-hook-installation", Name: "Cline lifecycle hook files are valid",
		Status: verificationFail, Expected: "direct current Rampart-managed PreToolUse and PostToolUse files", Actual: actual,
		Message: message,
		Hint:    "Run `rampart setup cline`, keep both hooks enabled in Cline, and do not use Cline CLI's legacy --yolo mode",
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
		payload = `{"clineVersion":"4","hookName":"tool_call","taskId":"rampart-verification","preToolUse":{"toolName":"run_commands","parameters":{"commands":"[\"rm -rf /\"]"}},"tool_call":{"id":"rampart-verification","name":"run_commands","input":{"commands":["rm -rf /"]}}}`
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
	auditRecord, err := latestAuditEvent(auditDir)
	if err != nil {
		return verificationCheck{ID: checkID, Name: checkName, Status: verificationFail, Expected: "deny audit", Actual: "audit unreadable", Message: err.Error()}
	}
	if auditRecord.Agent != agent {
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
	auditRecord, err := latestAuditEvent(auditDir)
	if err != nil {
		return verificationCheck{
			ID: "gemini-native-deny", Name: "Gemini CLI native deny response works",
			Status: verificationFail, Expected: "deny audit", Actual: "audit unreadable", Message: err.Error(),
		}
	}
	if auditRecord.Agent != "gemini-cli" || auditRecord.RunID != "rampart-verification" {
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

func verifyAntigravityPluginInstalled() verificationCheck {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return verificationCheck{
			ID: "antigravity-plugin-installation", Name: "Antigravity policy plugin is installed",
			Status: verificationUnverified, Actual: "home unavailable",
			Message: "Could not locate Antigravity's global plugin directory",
			Hint:    "Run `rampart setup antigravity`, then rerun `rampart verify antigravity`",
		}
	}
	if !antigravityPluginConfiguredForHome(home) {
		return verificationCheck{
			ID: "antigravity-plugin-installation", Name: "Antigravity policy plugin is installed",
			Status: verificationFail, Expected: "managed global PreToolUse plugin using the current binary", Actual: "missing, stale, or incomplete",
			Message: "Antigravity is not configured to invoke this Rampart binary before tool execution",
			Hint:    "Run `rampart setup antigravity`, restart Antigravity, then rerun verification",
		}
	}
	return verificationCheck{
		ID: "antigravity-plugin-installation", Name: "Antigravity policy plugin is installed",
		Status: verificationPass, Expected: "managed global PreToolUse plugin using the current binary", Actual: "configured",
		Message: "Antigravity's global Rampart plugin contains the current native PreToolUse policy hook",
	}
}

func verifyAntigravityHookAdapter(ctx context.Context) verificationCheck {
	auditDir, err := os.MkdirTemp("", "rampart-verify-antigravity-*")
	if err != nil {
		return verificationCheck{
			ID: "antigravity-native-deny", Name: "Antigravity native deny response works",
			Status: verificationUnverified, Actual: "temporary directory unavailable", Message: err.Error(),
		}
	}
	defer os.RemoveAll(auditDir)

	payload := `{
		"toolCall":{"name":"run_command","args":{"CommandLine":"rm -rf /","Cwd":"."}},
		"stepIdx":1,
		"conversationId":"rampart-verification",
		"workspacePaths":["."]
	}`
	var stdout, stderr bytes.Buffer
	hookCmd := NewRootCmd(ctx, &stdout, &stderr)
	hookCmd.SetIn(strings.NewReader(payload))
	hookCmd.SetArgs([]string{"hook", "--format", "antigravity", "--audit-dir", auditDir})
	if err := hookCmd.Execute(); err != nil {
		return verificationCheck{
			ID: "antigravity-native-deny", Name: "Antigravity native deny response works",
			Status: verificationFail, Expected: "structured deny", Actual: "hook error", Message: err.Error(),
		}
	}
	var output map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		return verificationCheck{
			ID: "antigravity-native-deny", Name: "Antigravity native deny response works",
			Status: verificationFail, Expected: "structured deny", Actual: strings.TrimSpace(stdout.String()),
			Message: "Rampart's Antigravity hook response was not valid JSON",
		}
	}
	if output["decision"] != "deny" {
		return verificationCheck{
			ID: "antigravity-native-deny", Name: "Antigravity native deny response works",
			Status: verificationFail, Expected: "decision=deny", Actual: strings.TrimSpace(stdout.String()),
			Message: "The live Rampart hook adapter did not block the destructive canary",
		}
	}
	auditRecord, err := latestAuditEvent(auditDir)
	if err != nil {
		return verificationCheck{
			ID: "antigravity-native-deny", Name: "Antigravity native deny response works",
			Status: verificationFail, Expected: "deny audit", Actual: "audit unreadable", Message: err.Error(),
		}
	}
	if auditRecord.Agent != "antigravity" || auditRecord.RunID != "rampart-verification" {
		return verificationCheck{
			ID: "antigravity-native-deny", Name: "Antigravity native deny response works",
			Status: verificationFail, Expected: "session-correlated deny audit", Actual: "correlation missing",
			Message: "The Antigravity hook audit did not preserve the host conversation identity",
		}
	}
	return verificationCheck{
		ID: "antigravity-native-deny", Name: "Antigravity native deny response works",
		Status: verificationPass, Expected: "structured deny and session-correlated audit", Actual: "deny + audit",
		Message: "The live Rampart hook adapter returned Antigravity's deny schema and preserved conversation identity in audit",
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
	cwd, _ := os.Getwd()
	if disabledAt, disabled := copilotCLIUserHooksDisabled(home, cwd); disabled {
		return verificationCheck{
			ID: "copilot-hook-loading", Name: "Copilot CLI is loading user hooks",
			Status: verificationFail, Expected: "disableAllHooks is false", Actual: "disabled",
			Message: fmt.Sprintf("Copilot CLI user hooks are disabled by %s; administrator policy hooks are not affected", disabledAt),
			Hint:    "Remove `disableAllHooks: true` for this session; a machine policy hook can protect Copilot CLI separately but does not cover VS Code",
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
	auditRecord, err := latestAuditEvent(auditDir)
	if err != nil {
		return verificationCheck{
			ID: "copilot-native-deny", Name: "Copilot CLI / VS Code native deny response works",
			Status: verificationFail, Expected: "deny audit", Actual: "audit unreadable", Message: err.Error(),
		}
	}
	if auditRecord.Agent != "github-copilot" || auditRecord.RunID != "rampart-verification" {
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
			Status: verificationFail, Expected: "current PreToolUse and PostToolUse commands", Actual: "missing, stale, or incomplete",
			Message: "Codex is not configured to invoke this Rampart binary for both lifecycle events",
			Hint:    "Run `rampart setup codex`, review the hooks with `/hooks`, then rerun verification",
		}
	}
	return verificationCheck{
		ID: "codex-hook-installation", Name: "Codex lifecycle hooks are installed",
		Status: verificationPass, Expected: "current PreToolUse and PostToolUse commands", Actual: "configured",
		Message: "The user-level Codex hook configuration contains both current Rampart lifecycle hooks",
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
	auditRecord, err := latestAuditEvent(auditDir)
	if err != nil {
		return verificationCheck{
			ID: "codex-native-deny", Name: "Codex native deny response works",
			Status: verificationFail, Expected: "correlated deny audit", Actual: "audit unreadable",
			Message: err.Error(),
		}
	}
	if auditRecord.Agent != "codex" || auditRecord.ToolCallID != "rampart-verification" {
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

func runPreflightCanary(ctx context.Context, client *http.Client, serveURL, token, target string, canary behavioralCanary) verificationCheck {
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
	if target == "" || target == "policy" {
		check.Hint = "Run `rampart protect` to restore the managed Guard policy, then verify again"
	} else {
		check.Hint = fmt.Sprintf("Run `rampart protect %s` to restore the managed Guard policy, then verify again", target)
	}
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
	configCtx, cancelConfig := context.WithTimeout(ctx, timeout)
	if err := verifyOpenClawManagedConfig(configCtx, bin); err != nil {
		cancelConfig()
		check.Status = verificationFail
		check.Actual = "managed configuration drift"
		check.Message = "OpenClaw will not enforce the complete Rampart-managed approval boundary: " + err.Error()
		check.Hint = "Run `rampart protect openclaw`, restart the gateway, and rerun verification"
		return check
	}
	cancelConfig()
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

func verifyOpenClawManagedConfig(ctx context.Context, openclawBin string) error {
	askValue, err := readOpenClawConfigJSON(ctx, openclawBin, "tools.exec.ask")
	if err != nil {
		return fmt.Errorf("read tools.exec.ask: %w", err)
	}
	ask, ok := askValue.(string)
	if !ok || strings.TrimSpace(ask) != "off" {
		return fmt.Errorf("tools.exec.ask is %v, want off", askValue)
	}

	configValue, err := readOpenClawConfigJSON(ctx, openclawBin, "plugins.entries.rampart.config")
	if err != nil {
		return fmt.Errorf("read Rampart plugin config: %w", err)
	}
	config, ok := configValue.(map[string]any)
	if !ok {
		return fmt.Errorf("invalid Rampart plugin config: expected an object")
	}
	if failOpen, ok := config["failOpen"].(bool); !ok || failOpen {
		return fmt.Errorf("plugins.entries.rampart.config.failOpen is not false")
	}
	if failOpenTools, present := config["failOpenTools"]; present && failOpenTools != nil {
		tools, ok := failOpenTools.([]any)
		if !ok || len(tools) != 0 {
			return fmt.Errorf("plugins.entries.rampart.config.failOpenTools is not empty")
		}
	}
	serveURL, ok := config["serveUrl"].(string)
	if !ok || validateCredentialEndpoint(serveURL, "file") != nil {
		return fmt.Errorf("plugins.entries.rampart.config.serveUrl is not a trusted loopback URL")
	}
	timeoutValue, ok := config["approvalTimeoutMs"].(float64)
	if !ok || timeoutValue != float64(ochardening.DesiredApprovalTimeoutMs) {
		return fmt.Errorf("plugins.entries.rampart.config.approvalTimeoutMs is not %d", ochardening.DesiredApprovalTimeoutMs)
	}
	return nil
}

func readOpenClawConfigJSON(ctx context.Context, openclawBin, key string) (any, error) {
	cmd := osexec.CommandContext(ctx, openclawBin, "config", "get", key, "--json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("openclaw config get %s: %w", key, err)
	}
	var value any
	if err := decodeOpenClawConfigJSON(output, &value); err != nil {
		return nil, err
	}
	return value, nil
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
	report.Summary = verificationSummary{Checks: len(report.Checks)}
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
	report.Assurance = assuranceLevelForReport(report)
	return report
}

func printVerificationReport(w io.Writer, report verificationReport) {
	fmt.Fprintf(w, "Rampart behavioral verification — %s\n\n", report.Target)
	fmt.Fprintln(w, "Safe canaries only: no commands, file reads, messages, or external network requests are executed.")
	fmt.Fprintln(w, "Verification uses the local admin path and does not add events to Rampart's audit log.")
	fmt.Fprintln(w)
	printVerificationResult(w, report)
}

func printVerificationBatchReport(w io.Writer, report verificationBatchReport) {
	fmt.Fprintf(w, "Rampart behavioral verification — configured integrations with safe verifiers (%d targets)\n\n", report.Summary.Targets)
	fmt.Fprintln(w, "Safe canaries only: no models, commands, file reads, messages, or external network requests are invoked.")
	fmt.Fprintln(w, "Verification uses the local admin path and does not add events to Rampart's audit log.")
	fmt.Fprintln(w, "Static-only integrations are not included; use `rampart doctor` for their installation status.")
	for index, result := range report.Results {
		if index > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "\n[%s]\n", result.Target)
		printVerificationResult(w, result)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Aggregate: %d targets passed, %d failed, %d unverified; %d checks total\n",
		report.Summary.PassedTargets,
		report.Summary.FailedTargets,
		report.Summary.UnverifiedTargets,
		report.Summary.Checks,
	)
}

func printVerificationResult(w io.Writer, report verificationReport) {
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
	if report.Assurance != "" {
		fmt.Fprintf(w, "Assurance: %s\n", strings.ToUpper(strings.ReplaceAll(string(report.Assurance), "_", " ")))
	}
}
