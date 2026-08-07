// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peg/rampart/internal/engine"
)

func TestFailClosedUnsupportedNativeHookAction(t *testing.T) {
	for _, action := range []engine.Action{
		engine.ActionAllow,
		engine.ActionWatch,
		engine.ActionDeny,
		engine.ActionAsk,
		engine.ActionRequireApproval,
	} {
		decision := failClosedUnsupportedNativeHookAction(engine.Decision{Action: action, Message: "original"})
		if decision.Action != action || decision.Message != "original" {
			t.Fatalf("supported action %s changed to %#v", action, decision)
		}
	}

	for _, action := range []engine.Action{engine.ActionWebhook, engine.Action(999)} {
		decision := failClosedUnsupportedNativeHookAction(engine.Decision{Action: action})
		if decision.Action != engine.ActionDeny || !strings.Contains(decision.Message, "refusing tool call") {
			t.Fatalf("unsupported action %s did not fail closed: %#v", action, decision)
		}
	}
}

func TestHookDecisionRankKeepsUnknownActionForFailClosedNormalization(t *testing.T) {
	if got := hookDecisionRank(engine.Action(999)); got <= hookDecisionRank(engine.ActionDeny) {
		t.Fatalf("unknown action rank = %d, deny rank = %d", got, hookDecisionRank(engine.ActionDeny))
	}
}

func TestNativeHookWebhookPolicyReturnsStructuredDeny(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	policyPath := filepath.Join(home, "webhook-policy.yaml")
	policy := `version: "1"
policies:
  - name: external-decision
    match:
      tool: ["exec"]
    rules:
      - action: webhook
        webhook:
          url: "http://127.0.0.1:1/decision"
          fail_open: false
`
	if err := os.WriteFile(policyPath, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	payload := `{"hook_event_name":"PreToolUse","session_id":"s","tool_use_id":"tool-1","tool_name":"Bash","tool_input":{"command":"pwd"}}`
	stdout, stderr, err := runHookWithStdin(
		t,
		&rootOptions{configPath: policyPath},
		payload,
		"--mode", "enforce",
		"--audit-dir", filepath.Join(home, "audit"),
	)
	if err != nil {
		t.Fatalf("hook returned an ordinary host error: %v (stderr=%q)", err, stderr)
	}
	var output hookOutput
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("output = %q: %v", stdout, err)
	}
	if output.HookSpecificOutput == nil || output.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("output = %#v, want structured deny", output)
	}
	if !strings.Contains(output.HookSpecificOutput.PermissionDecisionReason, "do not execute webhook") {
		t.Fatalf("deny reason = %q", output.HookSpecificOutput.PermissionDecisionReason)
	}
}

func TestNativeHookWaitsForConfiguredNotification(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	received := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	notificationMutex.Lock()
	lastNotificationTime = time.Time{}
	notificationMutex.Unlock()

	policyPath := filepath.Join(home, "notify-policy.yaml")
	policy := `version: "1"
default_action: allow
notify:
  url: "` + server.URL + `"
  platform: webhook
  on: [deny]
policies:
  - name: block-test
    match:
      tool: exec
    rules:
      - action: deny
        when:
          command_matches: ["blocked-command"]
`
	if err := os.WriteFile(policyPath, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	payload := `{"hook_event_name":"PreToolUse","session_id":"s","tool_use_id":"tool-1","tool_name":"Bash","tool_input":{"command":"blocked-command"}}`
	_, stderr, err := runHookWithStdin(t, &rootOptions{configPath: policyPath}, payload,
		"--mode", "enforce", "--audit-dir", filepath.Join(home, "audit"))
	if err != nil {
		t.Fatalf("hook error: %v (stderr=%q)", err, stderr)
	}
	select {
	case <-received:
	default:
		t.Fatal("hook returned before sending its configured notification")
	}
}

func TestClineUnknownPreToolReturnsStructuredCancel(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	payload := `{"clineVersion":"3.17.0","hookName":"PreToolUse","taskId":"task-1","preToolUse":{"tool":"future_remote_mutator","parameters":{}}}`
	var stdout, stderr string
	var hookErr error
	captureStderr(t, func() {
		stdout, stderr, hookErr = runHookWithStdin(
			t,
			&rootOptions{},
			payload,
			"--mode", "enforce",
			"--format", "cline",
			"--audit-dir", filepath.Join(home, "audit"),
		)
	})
	if hookErr != nil {
		t.Fatalf("hook returned an ordinary host error: %v (stderr=%q)", hookErr, stderr)
	}
	var output clineHookOutput
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("output = %q: %v", stdout, err)
	}
	if !output.Cancel || !strings.Contains(output.ErrorMessage, "unsupported Cline tool") {
		t.Fatalf("output = %#v, want structured cancel", output)
	}
}

func TestClaudeMalformedKnownPreToolReturnsStructuredDeny(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	payload := `{"hook_event_name":"PreToolUse","session_id":"s","tool_use_id":"tool-1","tool_name":"Bash","tool_input":{}}`
	stdout, stderr, hookErr := runHookWithStdin(
		t,
		&rootOptions{},
		payload,
		"--mode", "enforce",
		"--audit-dir", filepath.Join(home, "audit"),
	)
	if hookErr != nil {
		t.Fatalf("hook returned an ordinary host error: %v (stderr=%q)", hookErr, stderr)
	}
	var output hookOutput
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("output = %q: %v", stdout, err)
	}
	if output.HookSpecificOutput == nil || output.HookSpecificOutput.PermissionDecision != "deny" ||
		!strings.Contains(output.HookSpecificOutput.PermissionDecisionReason, "requires") {
		t.Fatalf("output = %#v, want structured malformed-input deny", output)
	}
}

func TestClineMalformedKnownPreToolReturnsStructuredCancel(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	payload := `{"clineVersion":"3.17.0","hookName":"PreToolUse","taskId":"task-1","preToolUse":{"tool":"execute_command","parameters":{}}}`
	var stdout, stderr string
	var hookErr error
	captureStderr(t, func() {
		stdout, stderr, hookErr = runHookWithStdin(
			t,
			&rootOptions{},
			payload,
			"--mode", "enforce",
			"--format", "cline",
			"--audit-dir", filepath.Join(home, "audit"),
		)
	})
	if hookErr != nil {
		t.Fatalf("hook returned an ordinary host error: %v (stderr=%q)", hookErr, stderr)
	}
	var output clineHookOutput
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("output = %q: %v", stdout, err)
	}
	if !output.Cancel || !strings.Contains(output.ErrorMessage, "requires") {
		t.Fatalf("output = %#v, want structured malformed-input cancel", output)
	}
}

func TestClaudeUnknownPostToolBlocksAndRedactsResponse(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	payload := `{"hook_event_name":"PostToolUse","session_id":"s","tool_use_id":"tool-1","tool_name":"FutureReader","tool_input":{},"tool_response":{"content":{"text":"do not expose"}}}`
	stdout, stderr, err := runHookWithStdin(
		t,
		&rootOptions{},
		payload,
		"--mode", "enforce",
		"--audit-dir", filepath.Join(home, "audit"),
	)
	if err != nil {
		t.Fatalf("hook returned an ordinary host error: %v (stderr=%q)", err, stderr)
	}
	var output hookOutput
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("output = %q: %v", stdout, err)
	}
	if output.Decision != "block" || !strings.Contains(output.Reason, "unsupported host tool response") {
		t.Fatalf("output = %#v, want post-tool block", output)
	}
	if output.HookSpecificOutput == nil {
		t.Fatalf("output = %#v, want redacted tool output", output)
	}
	redacted, _ := output.HookSpecificOutput.UpdatedToolOutput.(map[string]any)
	content, _ := redacted["content"].(map[string]any)
	if content["text"] != redactedToolOutput {
		t.Fatalf("updated tool output = %#v, want nested redaction", output.HookSpecificOutput.UpdatedToolOutput)
	}
}

func TestClaudeStringPostToolResponsePolicyBlocksAndRedacts(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	policyPath := filepath.Join(home, "response-policy.yaml")
	policy := `version: "1"
default_action: allow
policies:
  - name: block-response-secret
    match:
      tool: exec
    rules:
      - action: deny
        when:
          response_matches: ["secret-[0-9]+"]
        message: "protected response"
`
	if err := os.WriteFile(policyPath, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	payload := `{"hook_event_name":"PostToolUse","session_id":"s","tool_use_id":"tool-1","tool_name":"Bash","tool_input":{"command":"printf secret"},"tool_response":"output contains secret-42"}`
	stdout, stderr, err := runHookWithStdin(
		t,
		&rootOptions{configPath: policyPath},
		payload,
		"--mode", "enforce",
		"--audit-dir", filepath.Join(home, "audit"),
	)
	if err != nil {
		t.Fatalf("hook returned an ordinary host error: %v (stderr=%q)", err, stderr)
	}
	var output hookOutput
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("output = %q: %v", stdout, err)
	}
	if output.Decision != "block" || !strings.Contains(output.Reason, "protected response") {
		t.Fatalf("output = %#v, want response-policy block", output)
	}
	if output.HookSpecificOutput == nil || output.HookSpecificOutput.UpdatedToolOutput != redactedToolOutput {
		t.Fatalf("updated tool output = %#v, want scalar redaction", output.HookSpecificOutput)
	}
}

func TestHookLoadsProjectPolicyFromHostWorkingDirectory(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	repo := filepath.Join(home, "host-project")
	if err := os.MkdirAll(filepath.Join(repo, ".rampart"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("git", "init", repo).Run(); err != nil {
		t.Skipf("git unavailable: %v", err)
	}
	basePolicy := filepath.Join(home, "base.yaml")
	if err := os.WriteFile(basePolicy, []byte("version: \"1\"\ndefault_action: allow\npolicies: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	projectPolicy := `version: "1"
default_action: allow
policies:
  - name: repository-restriction
    match:
      tool: exec
    rules:
      - action: deny
        when:
          command_matches: ["project-only-command"]
        message: "blocked by host repository policy"
`
	if err := os.WriteFile(filepath.Join(repo, ".rampart", "policy.yaml"), []byte(projectPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	payload, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse",
		"session_id":      "host-project-session",
		"tool_use_id":     "tool-1",
		"cwd":             repo,
		"tool_name":       "Bash",
		"tool_input":      map[string]any{"command": "project-only-command"},
	})
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr, hookErr := runHookWithStdin(
		t,
		&rootOptions{configPath: basePolicy},
		string(payload),
		"--mode", "enforce",
		"--audit-dir", filepath.Join(home, "audit"),
	)
	if hookErr != nil {
		t.Fatalf("hook returned an ordinary host error: %v (stderr=%q)", hookErr, stderr)
	}
	var output hookOutput
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("output = %q: %v", stdout, err)
	}
	if output.HookSpecificOutput == nil || output.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("output = %#v, want project-policy deny", output)
	}
	if !strings.Contains(output.HookSpecificOutput.PermissionDecisionReason, "blocked by host repository policy") {
		t.Fatalf("deny reason = %q", output.HookSpecificOutput.PermissionDecisionReason)
	}
}

func TestHookResolvesRelativePathFromHostWorkingDirectory(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	workDir := filepath.Join(home, "workspace", "nested")
	protectedDir := filepath.Join(home, "protected")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(protectedDir, 0o700); err != nil {
		t.Fatal(err)
	}

	policyPath := filepath.Join(home, "cwd-policy.yaml")
	policy := fmt.Sprintf(`version: "1"
default_action: allow
policies:
  - name: protected-host-path
    match:
      tool: read
    rules:
      - action: deny
        when:
          path_matches: [%q]
        message: "blocked after host cwd resolution"
`, filepath.ToSlash(filepath.Join(protectedDir, "**")))
	if err := os.WriteFile(policyPath, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}

	payload, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse",
		"session_id":      "host-cwd-session",
		"tool_use_id":     "tool-cwd-1",
		"cwd":             workDir,
		"tool_name":       "Read",
		"tool_input":      map[string]any{"file_path": "../../protected/credential.txt"},
	})
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr, hookErr := runHookWithStdin(
		t,
		&rootOptions{configPath: policyPath},
		string(payload),
		"--mode", "enforce",
		"--audit-dir", filepath.Join(home, "audit"),
	)
	if hookErr != nil {
		t.Fatalf("hook returned an ordinary host error: %v (stderr=%q)", hookErr, stderr)
	}
	var output hookOutput
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("output = %q: %v", stdout, err)
	}
	if output.HookSpecificOutput == nil || output.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("output = %#v, want host-CWD-relative path deny", output)
	}
	if !strings.Contains(output.HookSpecificOutput.PermissionDecisionReason, "blocked after host cwd resolution") {
		t.Fatalf("deny reason = %q", output.HookSpecificOutput.PermissionDecisionReason)
	}
}

func TestClaudePostToolParseFailureUsesPostToolBlockProtocol(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	payload := `{"hook_event_name":"PostToolUse","session_id":"s","tool_use_id":"invalid/id","tool_name":"Bash","tool_input":{"command":"pwd"},"tool_response":{"stdout":"sensitive"}}`
	stdout, stderr, err := runHookWithStdin(
		t,
		&rootOptions{},
		payload,
		"--mode", "enforce",
		"--audit-dir", filepath.Join(home, "audit"),
	)
	if err != nil {
		t.Fatalf("hook returned an ordinary host error: %v (stderr=%q)", err, stderr)
	}
	var output hookOutput
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("output = %q: %v", stdout, err)
	}
	if output.Decision != "block" || output.HookSpecificOutput == nil {
		t.Fatalf("output = %#v, want post-tool block with redaction", output)
	}
}

func TestClaudePostToolPolicyLoadFailureUsesPostToolBlockProtocol(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	badPolicy := filepath.Join(home, "bad.yaml")
	if err := os.WriteFile(badPolicy, []byte("version: \"1\"\nunknown_field: true\npolicies: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	payload := `{"hook_event_name":"PostToolUse","session_id":"s","tool_use_id":"tool-1","tool_name":"Bash","tool_input":{"command":"pwd"},"tool_response":{"stdout":"sensitive"}}`
	stdout, stderr, err := runHookWithStdin(
		t,
		&rootOptions{configPath: badPolicy},
		payload,
		"--mode", "enforce",
		"--audit-dir", filepath.Join(home, "audit"),
	)
	if err != nil {
		t.Fatalf("hook returned an ordinary host error: %v (stderr=%q)", err, stderr)
	}
	var output hookOutput
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("output = %q: %v", stdout, err)
	}
	if output.Decision != "block" || output.HookSpecificOutput == nil {
		t.Fatalf("output = %#v, want post-tool block with redaction", output)
	}
}
