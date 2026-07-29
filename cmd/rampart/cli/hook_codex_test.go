// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peg/rampart/internal/engine"
	"github.com/spf13/cobra"
)

func TestParseCodexInput(t *testing.T) {
	tests := []struct {
		name      string
		payload   string
		wantTool  string
		wantResp  string
		wantPaths []string
	}{
		{
			name: "unified exec",
			payload: `{
				"session_id":"session-1",
				"turn_id":"turn-1",
				"cwd":"/tmp/project",
				"hook_event_name":"PreToolUse",
				"tool_name":"Bash",
				"tool_use_id":"call_1",
				"tool_input":{"command":"git status"}
			}`,
			wantTool: "exec",
		},
		{
			name: "code execution alias",
			payload: `{
				"session_id":"session-1",
				"hook_event_name":"PreToolUse",
				"tool_name":"code_execution",
				"tool_use_id":"call_code",
				"tool_input":{"code":"print('ok')"}
			}`,
			wantTool: "exec",
		},
		{
			name: "apply patch",
			payload: `{
				"session_id":"session-1",
				"cwd":"/tmp/project",
				"hook_event_name":"PreToolUse",
				"tool_name":"apply_patch",
				"tool_use_id":"call-2",
				"tool_input":{"command":"*** Begin Patch\n*** Add File: test.txt\n+x\n*** End Patch"}
			}`,
			wantTool:  "write",
			wantPaths: []string{"test.txt"},
		},
		{
			name: "mcp",
			payload: `{
				"session_id":"session-1",
				"cwd":"/tmp/project",
				"hook_event_name":"PreToolUse",
				"tool_name":"mcp__github__create_issue",
				"tool_use_id":"call_3",
				"tool_input":{"title":"test"}
			}`,
			wantTool: "mcp",
		},
		{
			name: "read",
			payload: `{
				"session_id":"session-1",
				"cwd":"/tmp/project",
				"hook_event_name":"PreToolUse",
				"tool_name":"Read",
				"tool_use_id":"call_read",
				"tool_input":{"path":"README.md"}
			}`,
			wantTool: "read",
		},
		{
			name: "browser",
			payload: `{
				"session_id":"session-1",
				"cwd":"/tmp/project",
				"hook_event_name":"PreToolUse",
				"tool_name":"browser_navigate",
				"tool_use_id":"call_browser",
				"tool_input":{"url":"https://example.com"}
			}`,
			wantTool: "fetch",
		},
		{
			name: "post tool response object",
			payload: `{
				"session_id":"session-1",
				"cwd":"/tmp/project",
				"hook_event_name":"PostToolUse",
				"tool_name":"Bash",
				"tool_use_id":"call_4",
				"tool_input":{"command":"printf ok"},
				"tool_response":{"stdout":"ok","stderr":""}
			}`,
			wantTool: "exec",
			wantResp: "ok",
		},
		{
			name: "post tool response scalar",
			payload: `{
				"session_id":"session-1",
				"cwd":"/tmp/project",
				"hook_event_name":"PostToolUse",
				"tool_name":"test_tool",
				"tool_use_id":"call_5",
				"tool_input":{},
				"tool_response":"done"
			}`,
			wantTool: "unknown",
			wantResp: "done",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := parseCodexInput(strings.NewReader(testCase.payload))
			if err != nil {
				t.Fatal(err)
			}
			if got.Tool != testCase.wantTool {
				t.Fatalf("tool = %q, want %q", got.Tool, testCase.wantTool)
			}
			if got.Agent != "codex" {
				t.Fatalf("agent = %q, want codex", got.Agent)
			}
			if got.RunID != "session-1" || got.SessionID != "session-1" {
				t.Fatalf("session identity not preserved: %+v", got)
			}
			if got.Response != testCase.wantResp {
				t.Fatalf("response = %q, want %q", got.Response, testCase.wantResp)
			}
			if strings.Join(got.PolicyPaths, "\x00") != strings.Join(testCase.wantPaths, "\x00") {
				t.Fatalf("policy paths = %#v, want %#v", got.PolicyPaths, testCase.wantPaths)
			}
		})
	}
}

func TestCodexMultiFilePatchEvaluatesEveryTarget(t *testing.T) {
	parsed, err := parseCodexInput(strings.NewReader(`{
		"session_id":"session-1",
		"hook_event_name":"PreToolUse",
		"tool_name":"apply_patch",
		"tool_use_id":"call_1",
		"tool_input":{"command":"*** Begin Patch\n*** Add File: safe.txt\n+safe\n*** Update File: secrets/.env\n@@\n-old\n+new\n*** Move to: archive/.env\n*** End Patch"}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{"safe.txt", "secrets/.env", "archive/.env"}
	if strings.Join(parsed.PolicyPaths, "\x00") != strings.Join(wantPaths, "\x00") {
		t.Fatalf("policy paths = %#v, want %#v", parsed.PolicyPaths, wantPaths)
	}

	store := engine.NewMemoryStore([]byte(`
version: "1"
default_action: allow
policies:
  - name: protect-env
    match:
      agent: codex
      tool: write
    rules:
      - action: deny
        when:
          path_matches:
            - "**/.env"
        message: protected environment file
`), "codex-test")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng, err := engine.New(store, logger)
	if err != nil {
		t.Fatal(err)
	}
	call := engine.ToolCall{
		Agent:  parsed.Agent,
		Tool:   parsed.Tool,
		Params: parsed.Params,
		Input:  parsed.Params,
	}
	selectedCall, decision := evaluateHookCall(eng, call, parsed.PolicyPaths)
	if decision.Action != engine.ActionDeny {
		t.Fatalf("decision = %s, want deny", decision.Action)
	}
	if selectedCall.Path() != "secrets/.env" {
		t.Fatalf("deciding path = %q, want secrets/.env", selectedCall.Path())
	}
}

func TestEvaluateHookCallClaimsOnceBeforeLaterBatchDeny(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(`
version: "1"
default_action: deny
policies:
  - name: batch-policy
    match:
      agent: codex
      tool: write
    rules:
      - action: allow
        when:
          path_matches: ["safe.txt"]
        once: true
      - action: deny
        when:
          path_matches: ["**/.env"]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng, err := engine.New(engine.NewFileStore(policyPath), logger)
	if err != nil {
		t.Fatal(err)
	}
	call := engine.ToolCall{
		Agent:  "codex",
		Tool:   "write",
		Params: map[string]any{},
		Input:  map[string]any{},
	}

	_, decision := evaluateHookCall(eng, call, []string{"safe.txt", "secrets/.env"})
	if decision.Action != engine.ActionDeny {
		t.Fatalf("decision = %s, want deny", decision.Action)
	}
	data, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "safe.txt") {
		t.Fatal("one-time allowance was not claimed before the later batch denial")
	}
}

func TestParseCodexInputRejectsOversizedPatch(t *testing.T) {
	var patch strings.Builder
	patch.WriteString("*** Begin Patch\n")
	for index := 0; index <= maxCodexPatchPaths; index++ {
		patch.WriteString("*** Add File: file-")
		patch.WriteString(fmt.Sprint(index))
		patch.WriteString(".txt\n+x\n")
	}
	patch.WriteString("*** End Patch")
	payload, err := json.Marshal(map[string]any{
		"session_id": "session-1", "hook_event_name": "PreToolUse",
		"tool_name": "apply_patch", "tool_use_id": "call-1",
		"tool_input": map[string]any{"command": patch.String()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseCodexInput(bytes.NewReader(payload)); err == nil || !strings.Contains(err.Error(), "split") {
		t.Fatalf("oversized patch error = %v, want split guidance", err)
	}
}

func TestParseCodexInputRejectsUnsafeOrUnsupportedPayloads(t *testing.T) {
	tests := []string{
		`{"session_id":"session","hook_event_name":"SessionStart","tool_name":"Bash","tool_use_id":"call","tool_input":{}}`,
		`{"session_id":"session","hook_event_name":"PreToolUse","tool_name":"","tool_use_id":"call","tool_input":{}}`,
		`{"session_id":"session","hook_event_name":"PreToolUse","tool_name":"future_mutating_tool","tool_use_id":"call","tool_input":{}}`,
		`{"session_id":"","hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":"call","tool_input":{}}`,
		`{"session_id":"session","hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":"","tool_input":{}}`,
		`{"session_id":"session","hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":"call/unsafe","tool_input":{}}`,
	}
	for _, payload := range tests {
		if _, err := parseCodexInput(strings.NewReader(payload)); err == nil {
			t.Fatalf("expected payload to be rejected: %s", payload)
		}
	}
}

func TestParseCodexInputRejectsMalformedKnownPreTools(t *testing.T) {
	tests := []struct {
		name      string
		toolName  string
		toolInput string
	}{
		{name: "missing exec command", toolName: "Bash", toolInput: `{}`},
		{name: "non-string exec command", toolName: "shell", toolInput: `{"command":42}`},
		{name: "missing write path", toolName: "write_file", toolInput: `{}`},
		{name: "missing read path", toolName: "Read", toolInput: `{}`},
		{name: "missing fetch URL", toolName: "browser_navigate", toolInput: `{}`},
		{name: "missing patch", toolName: "apply_patch", toolInput: `{"command":" "}`},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			payload := `{"session_id":"session","hook_event_name":"PreToolUse","tool_name":"` + testCase.toolName + `","tool_use_id":"call","tool_input":` + testCase.toolInput + `}`
			if _, err := parseCodexInput(strings.NewReader(payload)); err == nil || !strings.Contains(err.Error(), "requires") {
				t.Fatalf("error = %v, want required-field rejection", err)
			}
		})
	}
}

func TestParseCodexPostToolKeepsScanningMalformedKnownInput(t *testing.T) {
	payload := `{"session_id":"session","hook_event_name":"PostToolUse","tool_name":"apply_patch","tool_use_id":"call","tool_input":{},"tool_response":{"output":"scan me"}}`
	result, err := parseCodexInput(strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if result.Response != "scan me" {
		t.Fatalf("response = %q, want scan me", result.Response)
	}
}

func TestCodexMalformedKnownPreToolUseEmitsStructuredDeny(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	var stdout bytes.Buffer
	root := NewRootCmd(context.Background(), &stdout, io.Discard)
	root.SetIn(strings.NewReader(`{"session_id":"session","hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":"call","tool_input":{}}`))
	root.SetArgs([]string{"hook", "--format", "codex", "--audit-dir", filepath.Join(home, "audit")})
	if err := root.Execute(); err != nil {
		t.Fatalf("hook command returned an ordinary host error instead of a structured denial: %v", err)
	}

	var output map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("decode output %q: %v", stdout.String(), err)
	}
	specific, ok := output["hookSpecificOutput"].(map[string]any)
	if !ok || specific["permissionDecision"] != "deny" {
		t.Fatalf("malformed known Codex tool must deny in enforce mode: %#v", output)
	}
}

func TestCodexUnknownPreToolUseFailsClosed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CODEX_HOME", "")
	policyPath := filepath.Join(home, "rampart.yaml")
	if err := os.WriteFile(policyPath, []byte("version: \"1\"\ndefault_action: allow\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	auditDir := filepath.Join(home, "audit")
	payload := `{
		"session_id":"session",
		"hook_event_name":"PreToolUse",
		"tool_name":"future_mutating_tool",
		"tool_use_id":"call",
		"tool_input":{"target":"outside-workspace"}
	}`

	var stdout bytes.Buffer
	root := NewRootCmd(context.Background(), &stdout, io.Discard)
	root.SetIn(strings.NewReader(payload))
	root.SetArgs([]string{
		"--config", policyPath,
		"hook", "--format", "codex", "--audit-dir", auditDir,
	})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}

	var output map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("decode output %q: %v", stdout.String(), err)
	}
	specific, ok := output["hookSpecificOutput"].(map[string]any)
	if !ok || specific["permissionDecision"] != "deny" {
		t.Fatalf("unknown Codex tool must deny in enforce mode: %#v", output)
	}
	reason, _ := specific["permissionDecisionReason"].(string)
	if !strings.Contains(reason, "unsupported Codex tool_name") {
		t.Fatalf("deny reason = %q, want compatibility guidance", reason)
	}
}

func TestOutputHookResultCodexPreservesNativePermissions(t *testing.T) {
	t.Run("allow emits empty object", func(t *testing.T) {
		output := runCodexHookOutput(t, hookAllow, false)
		if len(output) != 0 {
			t.Fatalf("allow output = %#v, want empty JSON object", output)
		}
	})

	t.Run("deny uses supported pre tool schema", func(t *testing.T) {
		output := runCodexHookOutput(t, hookDeny, false)
		specific, ok := output["hookSpecificOutput"].(map[string]any)
		if !ok {
			t.Fatalf("missing hookSpecificOutput: %#v", output)
		}
		if specific["hookEventName"] != "PreToolUse" ||
			specific["permissionDecision"] != "deny" {
			t.Fatalf("unexpected deny output: %#v", output)
		}
	})

	t.Run("ask fails closed instead of emitting unsupported ask", func(t *testing.T) {
		output := runCodexHookOutput(t, hookAsk, false)
		specific := output["hookSpecificOutput"].(map[string]any)
		if specific["permissionDecision"] != "deny" {
			t.Fatalf("ask output must deny when unresolved: %#v", output)
		}
	})

	t.Run("post tool block uses supported top level schema", func(t *testing.T) {
		output := runCodexHookOutput(t, hookBlock, true)
		if output["decision"] != "block" {
			t.Fatalf("post block output = %#v", output)
		}
	})
}

func TestResolveCodexApprovalPreservesExactToolIdentity(t *testing.T) {
	var request createApprovalRequest
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/healthz":
			writeTestRampartHealth(w)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/approvals":
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "codex-approval-1", "status": "pending"})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/approvals/codex-approval-1":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "approved"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var stdout bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.SetOut(&stdout)
	call := engine.ToolCall{
		Tool:       "exec",
		Agent:      "codex",
		RunID:      "session-1",
		ToolCallID: "call-1",
		Params:     map[string]any{"command": "git push origin main"},
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	if err := resolveExternalHookApproval(cmd, "codex", call, "approval required", server.URL, "token", false, logger); err != nil {
		t.Fatal(err)
	}
	var output map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	if len(output) != 0 {
		t.Fatalf("approved output = %#v, want empty object preserving Codex permissions; requests=%v logs=%s", output, requests, logs.String())
	}
	if request.RunID != "session-1" || request.ToolCallID != "call-1" {
		t.Fatalf("approval identity = run %q call %q", request.RunID, request.ToolCallID)
	}
}

func runCodexHookOutput(t *testing.T, decision hookDecisionType, post bool) map[string]any {
	t.Helper()
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := outputHookResult(cmd, "codex", decision, post, "test reason", "test command"); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("decode output %q: %v", out.String(), err)
	}
	return decoded
}
