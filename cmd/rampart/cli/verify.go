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
		Use:   "verify [openclaw|policy]",
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
			if target != "openclaw" && target != "policy" {
				return fmt.Errorf("verify: unsupported target %q (supported: openclaw, policy)", target)
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
					"rampart_consequence": "external-message", "rampart_integration": "openclaw",
				},
				Expected: []string{"ask"},
			},
			behavioralCanary{
				ID: "message-read", Name: "Read-only message action remains available", Tool: "message",
				Params:   map[string]any{"action": "read", "target": "channel:rampart-verification", "rampart_consequence": "read-only", "rampart_integration": "openclaw"},
				Expected: []string{"allow", "watch"},
			},
		)
		for i := range canaries {
			canaries[i].Agent = "openclaw:rampart-verification"
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

	if target == "openclaw" {
		report.Checks = append(report.Checks, verifyOpenClawPluginLive(ctx, timeout))
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

func runPreflightCanary(ctx context.Context, client *http.Client, serveURL, token string, canary behavioralCanary) verificationCheck {
	agent := canary.Agent
	if agent == "" {
		agent = "rampart-verify"
	}
	body, err := json.Marshal(map[string]any{
		"agent": agent, "session": "rampart-verification", "params": canary.Params,
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
		ID: "openclaw-hook-live", Name: "Live OpenClaw hook enforces canaries",
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
	if err := json.Unmarshal(output, &payload); err != nil {
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
	if verified, _ := pluginResult["ok"].(bool); !verified {
		check.Status = verificationFail
		check.Actual = "canary mismatch"
		check.Message = "The running OpenClaw hook returned an unsafe or unexpected decision"
		check.Hint = "Run `rampart protect openclaw --reinstall`, restart the gateway, and verify again"
		return check
	}

	check.Status = verificationPass
	check.Actual = "live and enforced"
	check.Message = "The running before_tool_call path blocked, approved, and allowed the expected safe canaries"
	return check
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
	fmt.Fprintln(w, "The policy evaluations may appear as rampart-verification events in Rampart's audit log.")
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
