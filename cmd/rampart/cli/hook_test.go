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

			parsed, err := parseClaudeCodeInput(strings.NewReader(string(data)), testLogger())
			if err != nil {
				t.Fatalf("parseClaudeCodeInput error: %v", err)
			}
			if parsed.Tool != tt.wantTool {
				t.Fatalf("tool = %q, want %q", parsed.Tool, tt.wantTool)
			}
			if parsed.Agent != "claude-code" {
				t.Fatalf("agent = %q, want claude-code", parsed.Agent)
			}
			if parsed.Params == nil {
				t.Fatal("params is nil")
			}
			if parsed.Response != "" {
				t.Fatalf("expected empty response for PreToolUse, got %q", parsed.Response)
			}
		})
	}
}

func TestParseClaudeCodeInput_InvalidJSON(t *testing.T) {
	_, err := parseClaudeCodeInput(strings.NewReader("{"), testLogger())
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseClaudeCodeInput_PostToolUse(t *testing.T) {
	tests := []struct {
		name         string
		toolResult   map[string]any
		wantResponse string
	}{
		{
			name:         "stdout only",
			toolResult:   map[string]any{"stdout": "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE"},
			wantResponse: "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE",
		},
		{
			name:         "stdout and stderr",
			toolResult:   map[string]any{"stdout": "output", "stderr": "warning"},
			wantResponse: "output\nwarning",
		},
		{
			name:         "content field",
			toolResult:   map[string]any{"content": "-----BEGIN PRIVATE KEY-----\nMIIE..."},
			wantResponse: "-----BEGIN PRIVATE KEY-----\nMIIE...",
		},
		{
			name:         "empty result",
			toolResult:   map[string]any{},
			wantResponse: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := map[string]any{
				"tool_name":  "Bash",
				"tool_input": map[string]any{"command": "env"},
			}
			if tt.toolResult != nil {
				payload["tool_result"] = tt.toolResult
			}

			data, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			parsed, err := parseClaudeCodeInput(strings.NewReader(string(data)), testLogger())
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if parsed.Response != tt.wantResponse {
				t.Fatalf("response = %q, want %q", parsed.Response, tt.wantResponse)
			}
		})
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

			parsed, err := parseClineInput(strings.NewReader(string(data)), testLogger())
			if err != nil {
				t.Fatalf("parseClineInput error: %v", err)
			}
			if parsed.Tool != tt.wantTool {
				t.Fatalf("tool = %q, want %q", parsed.Tool, tt.wantTool)
			}
			if parsed.Agent != "cline" {
				t.Fatalf("agent = %q, want cline", parsed.Agent)
			}
			if parsed.Params == nil {
				t.Fatal("params is nil")
			}
		})
	}
}

func TestParseClineInput_Errors(t *testing.T) {
	_, err := parseClineInput(strings.NewReader("{"), testLogger())
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}

	data := `{"clineVersion":"1.0","hookName":"PreToolUse","timestamp":"2026-01-01T00:00:00Z","taskId":"task-1"}`
	_, err = parseClineInput(strings.NewReader(data), testLogger())
	if err == nil {
		t.Fatal("expected error when no preToolUse/postToolUse present")
	}
}

func TestParseClineInput_PostToolUseResponse(t *testing.T) {
	payload := map[string]any{
		"clineVersion": "1.0",
		"hookName":     "PostToolUse",
		"timestamp":    "2026-01-01T00:00:00Z",
		"taskId":       "task-1",
		"postToolUse": map[string]any{
			"toolName":   "execute_command",
			"parameters": map[string]any{"output": "secret_api_key=sk-1234567890abcdefghij"},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	parsed, err := parseClineInput(strings.NewReader(string(data)), testLogger())
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if parsed.Response != "secret_api_key=sk-1234567890abcdefghij" {
		t.Fatalf("response = %q, want %q", parsed.Response, "secret_api_key=sk-1234567890abcdefghij")
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

func TestOutputHookResult_ClaudeCode_Block(t *testing.T) {
	cmd := &cobra.Command{}
	out := &bytes.Buffer{}
	cmd.SetOut(out)

	stderr := captureStderr(t, func() {
		err := outputHookResult(cmd, "claude-code", hookBlock, "Response contains potential credentials", "env")
		if err != nil {
			t.Fatalf("block outputHookResult error: %v", err)
		}
	})

	if !strings.Contains(stderr, "Rampart blocked") {
		t.Fatalf("stderr missing block message: %q", stderr)
	}

	var block hookOutput
	if err := json.Unmarshal(out.Bytes(), &block); err != nil {
		t.Fatalf("unmarshal block output: %v", err)
	}
	if block.HookSpecificOutput.HookEventName != "PostToolUse" {
		t.Fatalf("HookEventName = %q, want PostToolUse", block.HookSpecificOutput.HookEventName)
	}
	if block.HookSpecificOutput.PermissionDecision != "block" {
		t.Fatalf("PermissionDecision = %q, want block", block.HookSpecificOutput.PermissionDecision)
	}
	if !strings.Contains(block.HookSpecificOutput.PermissionDecisionReason, "credentials") {
		t.Fatalf("PermissionDecisionReason = %q", block.HookSpecificOutput.PermissionDecisionReason)
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

func TestOutputHookResult_Cline_Block(t *testing.T) {
	cmd := &cobra.Command{}
	out := &bytes.Buffer{}
	cmd.SetOut(out)

	captureStderr(t, func() {
		err := outputHookResult(cmd, "cline", hookBlock, "credential leak", "cat .env")
		if err != nil {
			t.Fatalf("block outputHookResult error: %v", err)
		}
	})

	var block clineHookOutput
	if err := json.Unmarshal(out.Bytes(), &block); err != nil {
		t.Fatalf("unmarshal block output: %v", err)
	}
	if !block.Cancel {
		t.Fatal("Cancel should be true for block")
	}
	if !strings.Contains(block.ErrorMessage, "Blocked by Rampart") {
		t.Fatalf("ErrorMessage = %q", block.ErrorMessage)
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
	if !ask.Cancel {
		t.Fatal("Cancel should be true for require_approval in Cline")
	}
	if !strings.Contains(ask.ErrorMessage, "approval required") {
		t.Fatalf("ErrorMessage = %q, should mention approval required", ask.ErrorMessage)
	}
}

func TestExtractToolResponse(t *testing.T) {
	tests := []struct {
		name   string
		result *hookToolResult
		want   string
	}{
		{"stdout only", &hookToolResult{Stdout: "hello"}, "hello"},
		{"stderr only", &hookToolResult{Stderr: "error"}, "error"},
		{"content only", &hookToolResult{Content: "data"}, "data"},
		{"all fields", &hookToolResult{Stdout: "out", Stderr: "err", Content: "content"}, "out\nerr\ncontent"},
		{"empty", &hookToolResult{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractToolResponse(tt.result)
			if got != tt.want {
				t.Fatalf("extractToolResponse = %q, want %q", got, tt.want)
			}
		})
	}
}
