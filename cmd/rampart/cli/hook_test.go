package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestParseClaudeCodeInput_Mappings(t *testing.T) {
	tests := []struct {
		name      string
		toolName  string
		wantTool  string
		withInput bool
	}{
		{name: "Bash", toolName: "Bash", wantTool: "exec", withInput: true},
		{name: "Read", toolName: "Read", wantTool: "read", withInput: true},
		{name: "ReadFile", toolName: "ReadFile", wantTool: "read", withInput: false},
		{name: "Write", toolName: "Write", wantTool: "write", withInput: true},
		{name: "WriteFile", toolName: "WriteFile", wantTool: "write", withInput: false},
		{name: "EditFile", toolName: "EditFile", wantTool: "write", withInput: false},
		{name: "WebFetch", toolName: "WebFetch", wantTool: "fetch", withInput: true},
		{name: "Fetch", toolName: "Fetch", wantTool: "fetch", withInput: false},
		{name: "Default", toolName: "UnknownTool", wantTool: "exec", withInput: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := map[string]any{"tool_name": tt.toolName}
			if tt.withInput {
				payload["tool_input"] = map[string]any{"command": "echo hi"}
			}

			data, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("marshal input: %v", err)
			}

			tool, params, agent, err := parseClaudeCodeInput(strings.NewReader(string(data)), testLogger())
			if err != nil {
				t.Fatalf("parseClaudeCodeInput error: %v", err)
			}
			if tool != tt.wantTool {
				t.Fatalf("tool = %q, want %q", tool, tt.wantTool)
			}
			if agent != "claude-code" {
				t.Fatalf("agent = %q, want claude-code", agent)
			}
			if params == nil {
				t.Fatal("params is nil")
			}
		})
	}
}

func TestParseClaudeCodeInput_InvalidJSON(t *testing.T) {
	_, _, _, err := parseClaudeCodeInput(strings.NewReader("{"), testLogger())
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseClineInput_Mappings(t *testing.T) {
	tests := []struct {
		name      string
		toolName  string
		wantTool  string
		usePost   bool
		withParam bool
	}{
		{name: "execute_command", toolName: "execute_command", wantTool: "exec", withParam: true},
		{name: "read_file", toolName: "read_file", wantTool: "read", withParam: true},
		{name: "write_to_file", toolName: "write_to_file", wantTool: "write", withParam: true},
		{name: "search_files", toolName: "search_files", wantTool: "read", withParam: false},
		{name: "list_files", toolName: "list_files", wantTool: "read", withParam: false},
		{name: "list_code_definition_names", toolName: "list_code_definition_names", wantTool: "read", withParam: false},
		{name: "browser_action", toolName: "browser_action", wantTool: "fetch", withParam: true},
		{name: "use_mcp_tool", toolName: "use_mcp_tool", wantTool: "mcp", withParam: false},
		{name: "access_mcp_resource", toolName: "access_mcp_resource", wantTool: "mcp", withParam: false},
		{name: "ask_followup_question", toolName: "ask_followup_question", wantTool: "interact", withParam: false},
		{name: "attempt_completion", toolName: "attempt_completion", wantTool: "interact", withParam: false},
		{name: "new_task", toolName: "new_task", wantTool: "interact", withParam: false},
		{name: "fetch_instructions", toolName: "fetch_instructions", wantTool: "interact", withParam: false},
		{name: "plan_mode_respond", toolName: "plan_mode_respond", wantTool: "interact", withParam: false},
		{name: "default", toolName: "unknown", wantTool: "exec", withParam: false},
		{name: "post_tool_use", toolName: "read_file", wantTool: "read", usePost: true, withParam: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			toolUse := map[string]any{"toolName": tt.toolName}
			if tt.withParam {
				toolUse["parameters"] = map[string]any{"path": "/tmp/file"}
			}

			payload := map[string]any{
				"clineVersion": "1.0",
				"hookName":     "PreToolUse",
				"timestamp":    "2026-01-01T00:00:00Z",
				"taskId":       "task-1",
			}
			if tt.usePost {
				payload["postToolUse"] = toolUse
			} else {
				payload["preToolUse"] = toolUse
			}

			data, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("marshal input: %v", err)
			}

			tool, params, agent, err := parseClineInput(strings.NewReader(string(data)), testLogger())
			if err != nil {
				t.Fatalf("parseClineInput error: %v", err)
			}
			if tool != tt.wantTool {
				t.Fatalf("tool = %q, want %q", tool, tt.wantTool)
			}
			if agent != "cline" {
				t.Fatalf("agent = %q, want cline", agent)
			}
			if params == nil {
				t.Fatal("params is nil")
			}
		})
	}
}

func TestParseClineInput_Errors(t *testing.T) {
	_, _, _, err := parseClineInput(strings.NewReader("{"), testLogger())
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}

	data := `{"clineVersion":"1.0","hookName":"PreToolUse","timestamp":"2026-01-01T00:00:00Z","taskId":"task-1"}`
	_, _, _, err = parseClineInput(strings.NewReader(data), testLogger())
	if err == nil {
		t.Fatal("expected error when no preToolUse/postToolUse present")
	}
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	defer func() {
		os.Stderr = oldStderr
	}()

	fn()
	_ = w.Close()

	var b bytes.Buffer
	_, _ = io.Copy(&b, r)
	_ = r.Close()
	return b.String()
}

func TestOutputHookResult_ClaudeCode(t *testing.T) {
	cmd := &cobra.Command{}
	out := &bytes.Buffer{}
	cmd.SetOut(out)

	err := outputHookResult(cmd, "claude-code", hookAllow, "", "")
	if err != nil {
		t.Fatalf("allow outputHookResult error: %v", err)
	}

	var allow hookOutput
	if err := json.Unmarshal(out.Bytes(), &allow); err != nil {
		t.Fatalf("unmarshal allow output: %v", err)
	}
	if allow.HookSpecificOutput.HookEventName != "PreToolUse" {
		t.Fatalf("HookEventName = %q", allow.HookSpecificOutput.HookEventName)
	}
	if allow.HookSpecificOutput.PermissionDecision != "" {
		t.Fatalf("expected empty PermissionDecision for allow, got %q", allow.HookSpecificOutput.PermissionDecision)
	}

	out.Reset()
	stderr := captureStderr(t, func() {
		err = outputHookResult(cmd, "claude-code", hookDeny, "blocked by policy", "rm -rf /")
	})
	if err != nil {
		t.Fatalf("deny outputHookResult error: %v", err)
	}
	if !strings.Contains(stderr, "Rampart blocked: rm -rf /") {
		t.Fatalf("stderr missing deny message: %q", stderr)
	}

	var deny hookOutput
	if err := json.Unmarshal(out.Bytes(), &deny); err != nil {
		t.Fatalf("unmarshal deny output: %v", err)
	}
	if deny.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("PermissionDecision = %q, want deny", deny.HookSpecificOutput.PermissionDecision)
	}
	if deny.HookSpecificOutput.PermissionDecisionReason != "Rampart: blocked by policy" {
		t.Fatalf("PermissionDecisionReason = %q", deny.HookSpecificOutput.PermissionDecisionReason)
	}
}

func TestOutputHookResult_Cline(t *testing.T) {
	cmd := &cobra.Command{}
	out := &bytes.Buffer{}
	cmd.SetOut(out)

	err := outputHookResult(cmd, "cline", hookAllow, "approval required", "echo hi")
	if err != nil {
		t.Fatalf("allow outputHookResult error: %v", err)
	}

	var allow clineHookOutput
	if err := json.Unmarshal(out.Bytes(), &allow); err != nil {
		t.Fatalf("unmarshal allow output: %v", err)
	}
	if allow.Cancel {
		t.Fatal("Cancel should be false for allow")
	}
	if allow.ErrorMessage != "" {
		t.Fatalf("expected empty ErrorMessage for allow, got %q", allow.ErrorMessage)
	}

	out.Reset()
	stderr := captureStderr(t, func() {
		err = outputHookResult(cmd, "cline", hookDeny, "requires approval", "kubectl delete")
	})
	if err != nil {
		t.Fatalf("deny outputHookResult error: %v", err)
	}
	if !strings.Contains(stderr, "Rampart blocked: kubectl delete") {
		t.Fatalf("stderr missing deny message: %q", stderr)
	}

	var deny clineHookOutput
	if err := json.Unmarshal(out.Bytes(), &deny); err != nil {
		t.Fatalf("unmarshal deny output: %v", err)
	}
	if !deny.Cancel {
		t.Fatal("Cancel should be true for deny")
	}
	if deny.ErrorMessage != "Blocked by Rampart: requires approval" {
		t.Fatalf("ErrorMessage = %q", deny.ErrorMessage)
	}
}

func TestOutputHookResult_ClaudeCode_Ask(t *testing.T) {
	cmd := &cobra.Command{}
	out := &bytes.Buffer{}
	cmd.SetOut(out)

	stderr := captureStderr(t, func() {
		err := outputHookResult(cmd, "claude-code", hookAsk, "deployment needs approval", "kubectl apply -f deploy.yaml")
		if err != nil {
			t.Fatalf("ask outputHookResult error: %v", err)
		}
	})

	// Stderr should show approval message, not deny message
	if !strings.Contains(stderr, "approval required") {
		t.Fatalf("stderr missing approval message: %q", stderr)
	}
	if strings.Contains(stderr, "blocked") {
		t.Fatalf("stderr should not say 'blocked' for ask: %q", stderr)
	}

	var ask hookOutput
	if err := json.Unmarshal(out.Bytes(), &ask); err != nil {
		t.Fatalf("unmarshal ask output: %v", err)
	}
	if ask.HookSpecificOutput.PermissionDecision != "ask" {
		t.Fatalf("PermissionDecision = %q, want ask", ask.HookSpecificOutput.PermissionDecision)
	}
	if ask.HookSpecificOutput.PermissionDecisionReason != "Rampart: deployment needs approval" {
		t.Fatalf("PermissionDecisionReason = %q", ask.HookSpecificOutput.PermissionDecisionReason)
	}
	if ask.HookSpecificOutput.HookEventName != "PreToolUse" {
		t.Fatalf("HookEventName = %q", ask.HookSpecificOutput.HookEventName)
	}
}

func TestOutputHookResult_Cline_Ask(t *testing.T) {
	cmd := &cobra.Command{}
	out := &bytes.Buffer{}
	cmd.SetOut(out)

	stderr := captureStderr(t, func() {
		err := outputHookResult(cmd, "cline", hookAsk, "deployment needs approval", "kubectl apply -f deploy.yaml")
		if err != nil {
			t.Fatalf("ask outputHookResult error: %v", err)
		}
	})

	if !strings.Contains(stderr, "approval required") {
		t.Fatalf("stderr missing approval message: %q", stderr)
	}

	var ask clineHookOutput
	if err := json.Unmarshal(out.Bytes(), &ask); err != nil {
		t.Fatalf("unmarshal ask output: %v", err)
	}
	// Cline has no "ask" — require_approval cancels the operation
	if !ask.Cancel {
		t.Fatal("Cancel should be true for require_approval in Cline")
	}
	if !strings.Contains(ask.ErrorMessage, "approval required") {
		t.Fatalf("ErrorMessage = %q, should mention approval required", ask.ErrorMessage)
	}
}
