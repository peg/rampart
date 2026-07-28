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

// TestDeriveGitContext_EnvVar verifies RAMPART_SESSION overrides git session detection.
func TestDeriveGitContext_EnvVar(t *testing.T) {
	t.Setenv("RAMPART_SESSION", "my-pipeline")
	ctx := deriveGitContext()
	if ctx.session != "my-pipeline" {
		t.Errorf("expected 'my-pipeline', got %q", ctx.session)
	}
}

// TestDeriveGitContext_NoGit verifies that a non-git directory returns empty context.
func TestDeriveGitContext_NoGit(t *testing.T) {
	t.Setenv("RAMPART_SESSION", "")

	// Change to a temp dir that has no git repo.
	tmp := t.TempDir()
	orig, _ := os.Getwd()
	os.Chdir(tmp)
	defer os.Chdir(orig)

	ctx := deriveGitContext()
	if ctx.session != "" {
		t.Errorf("expected empty session outside git repo, got %q", ctx.session)
	}
	if ctx.root != "" {
		t.Errorf("expected empty root outside git repo, got %q", ctx.root)
	}
}

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
		{name: "Edit", toolName: "Edit", wantTool: "write", withInput: true},
		{name: "EditFile", toolName: "EditFile", wantTool: "write", withInput: false},
		{name: "WebFetch", toolName: "WebFetch", wantTool: "fetch", withInput: true},
		{name: "Fetch", toolName: "Fetch", wantTool: "fetch", withInput: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := map[string]any{"hook_event_name": "PreToolUse", "tool_name": tt.toolName}
			if tt.withInput {
				payload["tool_input"] = map[string]any{"command": "echo hi"}
			}

			data, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("marshal input: %v", err)
			}

			result, err := parseClaudeCodeInput(strings.NewReader(string(data)), testLogger())
			if err != nil {
				t.Fatalf("parseClaudeCodeInput error: %v", err)
			}
			if result.Tool != tt.wantTool {
				t.Fatalf("tool = %q, want %q", result.Tool, tt.wantTool)
			}
			if result.Agent != "claude-code" {
				t.Fatalf("agent = %q, want claude-code", result.Agent)
			}
			if result.Params == nil {
				t.Fatal("params is nil")
			}
		})
	}
}

func TestParseClaudeCodeInput_UnknownPreToolFailsClosed(t *testing.T) {
	input := `{
		"hook_event_name":"PreToolUse",
		"tool_name":"FutureMutatingTool",
		"tool_input":{"target":"outside"},
		"tool_use_id":"toolu_future_1"
	}`
	_, err := parseClaudeCodeInput(strings.NewReader(input), testLogger())
	if err == nil || !strings.Contains(err.Error(), "unsupported Claude Code tool_name") {
		t.Fatalf("expected unsupported-tool error, got %v", err)
	}
}

func TestParseClaudeCodeInput_InvalidJSON(t *testing.T) {
	_, err := parseClaudeCodeInput(strings.NewReader("{"), testLogger())
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseClaudeCodeInput_RejectsUnknownEvent(t *testing.T) {
	input := `{"hook_event_name":"SessionStart","tool_name":"Bash","tool_input":{}}`
	_, err := parseClaudeCodeInput(strings.NewReader(input), testLogger())
	if err == nil || !strings.Contains(err.Error(), "unsupported Claude Code hook_event_name") {
		t.Fatalf("expected unsupported-event error, got %v", err)
	}
}

func TestExtractToolResponseIncludesNestedStringsDeterministically(t *testing.T) {
	response := map[string]any{
		"metadata": "tail",
		"content": []any{
			map[string]any{"text": "nested secret"},
			"second",
		},
		"stdout": "first",
	}
	if got, want := extractToolResponse(response), "first\nnested secret\nsecond\ntail"; got != want {
		t.Fatalf("response = %q, want %q", got, want)
	}
}

func TestParseClaudeCodeInput_MonitorWebSocketUsesNetworkPolicy(t *testing.T) {
	input := `{
		"hook_event_name":"PreToolUse",
		"tool_name":"Monitor",
		"tool_input":{"ws":{"url":"wss://events.example.com/feed"},"timeout_ms":1000},
		"tool_use_id":"toolu_monitor_1"
	}`
	result, err := parseClaudeCodeInput(strings.NewReader(input), testLogger())
	if err != nil {
		t.Fatalf("parseClaudeCodeInput error: %v", err)
	}
	if result.Tool != "fetch" {
		t.Fatalf("tool = %q, want fetch", result.Tool)
	}
	if result.Params["url"] != "wss://events.example.com/feed" {
		t.Fatalf("url = %#v", result.Params["url"])
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
		{name: "new_task", toolName: "new_task", wantTool: "agent", withParam: false},
		{name: "fetch_instructions", toolName: "fetch_instructions", wantTool: "interact", withParam: false},
		{name: "plan_mode_respond", toolName: "plan_mode_respond", wantTool: "interact", withParam: false},
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
				payload["hookName"] = "PostToolUse"
				payload["postToolUse"] = toolUse
			} else {
				payload["preToolUse"] = toolUse
			}

			data, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("marshal input: %v", err)
			}

			result, err := parseClineInput(strings.NewReader(string(data)), testLogger())
			if err != nil {
				t.Fatalf("parseClineInput error: %v", err)
			}
			if result.Tool != tt.wantTool {
				t.Fatalf("tool = %q, want %q", result.Tool, tt.wantTool)
			}
			if result.Agent != "cline" {
				t.Fatalf("agent = %q, want cline", result.Agent)
			}
			if result.Params == nil {
				t.Fatal("params is nil")
			}
		})
	}
}

func TestParseClineInput_CurrentAndLegacyToolFields(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload string
	}{
		{
			name:    "current toolName field",
			payload: `{"clineVersion":"3.17.0","hookName":"PreToolUse","taskId":"task-current","preToolUse":{"toolName":"execute_command","parameters":{"command":"pwd"}}}`,
		},
		{
			name:    "compatibility tool field",
			payload: `{"clineVersion":"1.0","hookName":"PreToolUse","taskId":"task-legacy","preToolUse":{"tool":"execute_command","parameters":{"command":"pwd"}}}`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := parseClineInput(strings.NewReader(test.payload), testLogger())
			if err != nil {
				t.Fatal(err)
			}
			if result.Tool != "exec" || result.HookEventName != "PreToolUse" || result.SessionID == "" {
				t.Fatalf("result = %#v", result)
			}
		})
	}
}

func TestParseClineInput_CurrentCLIToolCallEnvelope(t *testing.T) {
	payload := `{"clineVersion":"4.0.0","hookName":"tool_call","taskId":"task-cli","preToolUse":{"toolName":"run_commands","parameters":{"commands":"[\"pwd\",\"rm -rf /\"]"}},"tool_call":{"id":"call_123","name":"run_commands","input":{"commands":["pwd","rm -rf /"]}}}`
	result, err := parseClineInput(strings.NewReader(payload), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if result.Tool != "exec" || result.HookEventName != "PreToolUse" || result.ToolUseID != "call_123" {
		t.Fatalf("result = %#v", result)
	}
	if got := result.Params["command"]; got != "pwd && rm -rf /" {
		t.Fatalf("normalized command = %#v", got)
	}
}

func TestParseClineInput_CurrentCLIToolResultEnvelope(t *testing.T) {
	payload := `{"clineVersion":"4.0.0","hookName":"tool_result","taskId":"task-cli","postToolUse":{"toolName":"read_files","parameters":{"files":"[{\"path\":\"README.md\"}]"},"success":true},"tool_result":{"id":"call_123","name":"read_files","input":{"files":[{"path":"README.md"}]},"output":{"content":"credential-shaped output"}}}`
	result, err := parseClineInput(strings.NewReader(payload), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if result.Tool != "read" || result.HookEventName != "PostToolUse" || result.ToolUseID != "call_123" {
		t.Fatalf("result = %#v", result)
	}
	if result.Response != `{"content":"credential-shaped output"}` {
		t.Fatalf("response = %q", result.Response)
	}
}

func TestParseClineInput_CurrentCLIBatchedFilePaths(t *testing.T) {
	payload := `{"hookName":"tool_call","taskId":"task-cli","preToolUse":{"toolName":"read_files","parameters":{}},"tool_call":{"id":"call_paths","name":"read_files","input":{"files":[{"path":"safe.txt"},{"path":".env"}]}}}`
	result, err := parseClineInput(strings.NewReader(payload), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(result.PolicyPaths, "\x00"), "safe.txt\x00.env"; got != want {
		t.Fatalf("policy paths = %#v, want %#v", result.PolicyPaths, want)
	}
}

func TestParseClineInput_CurrentCLIApplyPatchPaths(t *testing.T) {
	payload := `{"hookName":"tool_call","taskId":"task-cli","preToolUse":{"toolName":"apply_patch","parameters":{}},"tool_call":{"id":"call_patch","name":"apply_patch","input":{"input":"*** Begin Patch\n*** Update File: safe.txt\n@@\n-old\n+new\n*** Delete File: .env\n*** End Patch"}}}`
	result, err := parseClineInput(strings.NewReader(payload), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if result.Tool != "write" || strings.Join(result.PolicyPaths, "\x00") != "safe.txt\x00.env" {
		t.Fatalf("result = %#v", result)
	}
}

func TestParseClineInput_CurrentCLIMultiURLFailsClosed(t *testing.T) {
	payload := `{"hookName":"tool_call","taskId":"task-cli","preToolUse":{"toolName":"fetch_web_content","parameters":{}},"tool_call":{"id":"call_web","name":"fetch_web_content","input":{"requests":[{"url":"https://example.com","prompt":"read"},{"url":"https://other.example","prompt":"read"}]}}}`
	if _, err := parseClineInput(strings.NewReader(payload), testLogger()); err == nil || !strings.Contains(err.Error(), "multiple URLs") {
		t.Fatalf("expected multi-URL rejection, got %v", err)
	}
}

func TestMapClineToolCurrentEditorAndCLISurfaces(t *testing.T) {
	for name, want := range map[string]string{
		"execute_command": "exec", "run_commands": "exec", "bash": "exec",
		"read_file": "read", "read_files": "read", "search_codebase": "read",
		"replace_in_file": "write", "editor": "write", "apply_patch": "write",
		"fetch_web_content": "fetch", "spawn_agent": "agent", "ask_question": "interact",
		"team_send_message": "message", "filesystem__delete_file": "mcp",
	} {
		if got := mapClineTool(name); got != want {
			t.Fatalf("mapClineTool(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestParseClineInput_CurrentPostResult(t *testing.T) {
	payload := `{"clineVersion":"3.17.0","hookName":"PostToolUse","taskId":"task-1","postToolUse":{"tool":"read_file","parameters":{"path":"README.md"},"result":"credential-shaped output","success":true,"durationMs":12}}`
	result, err := parseClineInput(strings.NewReader(payload), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if result.HookEventName != "PostToolUse" || result.Response != "credential-shaped output" {
		t.Fatalf("result = %#v", result)
	}
}

func TestParseClineInput_FailsClosedForUnknownPreTool(t *testing.T) {
	payload := `{"clineVersion":"3.17.0","hookName":"PreToolUse","taskId":"task-1","preToolUse":{"tool":"future_remote_mutator","parameters":{}}}`
	_, err := parseClineInput(strings.NewReader(payload), testLogger())
	if err == nil || !strings.Contains(err.Error(), "unsupported Cline tool") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseClineInput_ValidatesHookIdentity(t *testing.T) {
	for _, payload := range []string{
		`{"hookName":"PostToolUse","taskId":"task-1","preToolUse":{"tool":"read_file","parameters":{}}}`,
		`{"hookName":"PreToolUse","taskId":"task-1","postToolUse":{"tool":"read_file","parameters":{},"result":"ok"}}`,
		`{"hookName":"PreToolUse","taskId":"task-1","preToolUse":{"tool":"read_file"},"postToolUse":{"tool":"read_file"}}`,
		`{"hookName":"PreToolUse","taskId":"task-1","preToolUse":{"tool":"read_file","toolName":"execute_command"}}`,
	} {
		if _, err := parseClineInput(strings.NewReader(payload), testLogger()); err == nil {
			t.Fatalf("expected identity error for %s", payload)
		}
	}
}

func TestParseClineInput_ClassifiesWrappedMCPTool(t *testing.T) {
	payload := `{"clineVersion":"3.17.0","hookName":"PreToolUse","taskId":"task-1","preToolUse":{"tool":"use_mcp_tool","parameters":{"server_name":"filesystem","tool_name":"delete_file","arguments":{"path":"important.txt"}}}}`
	result, err := parseClineInput(strings.NewReader(payload), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if result.Tool != "mcp-destructive" {
		t.Fatalf("tool = %q, want mcp-destructive", result.Tool)
	}
}

func TestParseClineInput_ClassifiesCurrentCLIMCPToolName(t *testing.T) {
	payload := `{"hookName":"tool_call","taskId":"task-cli","preToolUse":{"toolName":"filesystem__delete_file","parameters":{}},"tool_call":{"id":"call_mcp","name":"filesystem__delete_file","input":{"path":"important.txt"}}}`
	result, err := parseClineInput(strings.NewReader(payload), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if result.Tool != "mcp-destructive" {
		t.Fatalf("tool = %q, want mcp-destructive", result.Tool)
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
	t.Run("PreToolUse allow sends explicit permissionDecision", func(t *testing.T) {
		cmd := &cobra.Command{}
		out := &bytes.Buffer{}
		cmd.SetOut(out)

		err := outputHookResult(cmd, "claude-code", hookAllow, false, "", "")
		if err != nil {
			t.Fatalf("allow outputHookResult error: %v", err)
		}

		var allow hookOutput
		if err := json.Unmarshal(out.Bytes(), &allow); err != nil {
			t.Fatalf("unmarshal allow output: %v", err)
		}
		if allow.HookSpecificOutput == nil {
			t.Fatal("expected non-nil HookSpecificOutput for PreToolUse allow")
		}
		if allow.HookSpecificOutput.HookEventName != "PreToolUse" {
			t.Fatalf("HookEventName = %q, want PreToolUse", allow.HookSpecificOutput.HookEventName)
		}
		if allow.HookSpecificOutput.PermissionDecision != "allow" {
			t.Fatalf("PermissionDecision = %q, want allow", allow.HookSpecificOutput.PermissionDecision)
		}
		if allow.Decision != "" {
			t.Fatalf("expected empty top-level Decision for PreToolUse allow, got %q", allow.Decision)
		}
	})

	t.Run("PostToolUse allow sends empty JSON", func(t *testing.T) {
		cmd := &cobra.Command{}
		out := &bytes.Buffer{}
		cmd.SetOut(out)

		err := outputHookResult(cmd, "claude-code", hookAllow, true, "", "")
		if err != nil {
			t.Fatalf("allow outputHookResult error: %v", err)
		}

		var allow hookOutput
		if err := json.Unmarshal(out.Bytes(), &allow); err != nil {
			t.Fatalf("unmarshal allow output: %v", err)
		}
		if allow.HookSpecificOutput != nil {
			t.Fatalf("expected nil HookSpecificOutput for PostToolUse allow, got %+v", allow.HookSpecificOutput)
		}
		if allow.Decision != "" {
			t.Fatalf("expected empty Decision for PostToolUse allow, got %q", allow.Decision)
		}
	})

	t.Run("PostToolUse block replaces structured output", func(t *testing.T) {
		cmd := &cobra.Command{}
		out := &bytes.Buffer{}
		cmd.SetOut(out)
		response := map[string]any{
			"stdout":      "AKIA1234567890ABCDEF",
			"stderr":      "",
			"interrupted": false,
			"nested":      []any{"secret", map[string]any{"detail": "token"}},
		}

		err := outputHookResultWithResponse(
			cmd,
			"claude-code",
			hookBlock,
			true,
			"credential response blocked",
			"printenv",
			redactClaudeToolOutput(response),
		)
		if err != nil {
			t.Fatalf("block outputHookResultWithResponse error: %v", err)
		}

		var blocked hookOutput
		if err := json.Unmarshal(out.Bytes(), &blocked); err != nil {
			t.Fatalf("unmarshal block output: %v", err)
		}
		if blocked.Decision != "block" {
			t.Fatalf("Decision = %q, want block", blocked.Decision)
		}
		if blocked.HookSpecificOutput == nil {
			t.Fatal("expected updatedToolOutput for PostToolUse block")
		}
		updated, ok := blocked.HookSpecificOutput.UpdatedToolOutput.(map[string]any)
		if !ok {
			t.Fatalf("updatedToolOutput = %#v, want object", blocked.HookSpecificOutput.UpdatedToolOutput)
		}
		if updated["stdout"] != redactedToolOutput || updated["stderr"] != redactedToolOutput {
			t.Fatalf("string fields were not redacted: %#v", updated)
		}
		if updated["interrupted"] != false {
			t.Fatalf("non-string field changed: %#v", updated)
		}
		encoded, err := json.Marshal(updated)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(encoded, []byte("AKIA")) || bytes.Contains(encoded, []byte("secret")) {
			t.Fatalf("updated output leaked original strings: %s", encoded)
		}
	})

	t.Run("deny", func(t *testing.T) {
		cmd := &cobra.Command{}
		out := &bytes.Buffer{}
		cmd.SetOut(out)

		var err error
		stderr := captureStderr(t, func() {
			err = outputHookResult(cmd, "claude-code", hookDeny, false, "blocked by policy", "rm -rf /")
		})
		if err != nil {
			t.Fatalf("deny outputHookResult error: %v", err)
		}
		if stderr != "" {
			t.Fatalf("stderr should be empty for Claude Code deny (Claude treats stderr as hook error), got: %q", stderr)
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
	})
}

func TestOutputHookResult_Cline(t *testing.T) {
	cmd := &cobra.Command{}
	out := &bytes.Buffer{}
	cmd.SetOut(out)

	err := outputHookResult(cmd, "cline", hookAllow, false, "approval required", "echo hi")
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
		err = outputHookResult(cmd, "cline", hookDeny, false, "requires approval", "kubectl delete")
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
		err := outputHookResult(cmd, "claude-code", hookAsk, false, "deployment needs approval", "kubectl apply -f deploy.yaml")
		if err != nil {
			t.Fatalf("ask outputHookResult error: %v", err)
		}
	})

	// Stderr should be EMPTY for ask — Claude Code interprets any stderr as a hook error.
	// The reason is conveyed via PermissionDecisionReason in the JSON response.
	if stderr != "" {
		t.Fatalf("stderr should be empty for ask (Claude Code treats stderr as error), got: %q", stderr)
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

// TestPostToolUseFailure_ShortCircuit verifies that a PostToolUseFailure hook event
// produces an additionalContext response without policy evaluation.
func TestPostToolUseFailure_ShortCircuit(t *testing.T) {
	t.Run("parseClaudeCodeInput extracts HookEventName", func(t *testing.T) {
		input := map[string]any{
			"hook_event_name": "PostToolUseFailure",
			"tool_name":       "Bash",
			"tool_input":      map[string]any{"command": "rm -rf /"},
			"session_id":      "sess-abc",
		}
		data, _ := json.Marshal(input)
		result, err := parseClaudeCodeInput(strings.NewReader(string(data)), testLogger())
		if err != nil {
			t.Fatalf("parseClaudeCodeInput error: %v", err)
		}
		if result.HookEventName != "PostToolUseFailure" {
			t.Fatalf("HookEventName = %q, want PostToolUseFailure", result.HookEventName)
		}
		if result.Tool != "exec" {
			t.Fatalf("Tool = %q, want exec", result.Tool)
		}
	})

	t.Run("PostToolUseFailure output contains additionalContext", func(t *testing.T) {
		// Simulate what the hook RunE short-circuit produces.
		cmd := &cobra.Command{}
		out := &bytes.Buffer{}
		cmd.SetOut(out)

		msg := "This tool call was blocked by a Rampart policy rule. " +
			"This is a deliberate security constraint — do not attempt " +
			"alternative approaches or workarounds. " +
			"Tell the user the operation was blocked by policy and stop."
		hookOut := hookOutput{
			HookSpecificOutput: &hookDecision{
				HookEventName:     "PostToolUseFailure",
				AdditionalContext: msg,
			},
		}
		if err := json.NewEncoder(cmd.OutOrStdout()).Encode(hookOut); err != nil {
			t.Fatalf("encode hookOutput: %v", err)
		}

		var got hookOutput
		if err := json.Unmarshal(out.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal output: %v", err)
		}
		if got.HookSpecificOutput == nil {
			t.Fatal("expected non-nil hookSpecificOutput")
		}
		if got.HookSpecificOutput.HookEventName != "PostToolUseFailure" {
			t.Fatalf("hookEventName = %q, want PostToolUseFailure", got.HookSpecificOutput.HookEventName)
		}
		if got.HookSpecificOutput.AdditionalContext == "" {
			t.Fatal("additionalContext must not be empty")
		}
		if !strings.Contains(got.HookSpecificOutput.AdditionalContext, "blocked by a Rampart policy rule") {
			t.Fatalf("additionalContext = %q, want to contain 'blocked by a Rampart policy rule'", got.HookSpecificOutput.AdditionalContext)
		}
		if !strings.Contains(got.HookSpecificOutput.AdditionalContext, "do not attempt") {
			t.Fatalf("additionalContext = %q, should contain 'do not attempt'", got.HookSpecificOutput.AdditionalContext)
		}
		// Ensure no PermissionDecision field — this is not a PreToolUse response
		if got.HookSpecificOutput.PermissionDecision != "" {
			t.Fatalf("PermissionDecision should be empty for PostToolUseFailure, got %q", got.HookSpecificOutput.PermissionDecision)
		}
		// Ensure top-level decision is empty (PostToolUseFailure uses hookSpecificOutput)
		if got.Decision != "" {
			t.Fatalf("top-level Decision should be empty, got %q", got.Decision)
		}
	})
}

func TestMapClaudeCodeTool(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Bash", "exec"},
		{"Read", "read"},
		{"ReadFile", "read"},
		{"Glob", "read"},
		{"Grep", "read"},
		{"LSP", "read"},
		{"Write", "write"},
		{"WriteFile", "write"},
		{"Edit", "write"},
		{"EditFile", "write"},
		{"NotebookEdit", "write"},
		{"EnterWorktree", "write"},
		{"PowerShell", "exec"},
		{"Monitor", "exec"},
		{"WebFetch", "fetch"},
		{"WebSearch", "fetch"},
		{"Fetch", "fetch"},
		{"web_search", "fetch"},
		{"web_fetch", "fetch"},
		{"memory", "memory"},
		{"code_execution", "exec"},
		{"tool_search", "read"},
		{"ToolSearch", "read"},
		{"mcp__github__create_issue", "mcp"},
		{"ListMcpResourcesTool", "read"},
		{"Agent", "agent"},
		{"Workflow", "agent"},
		{"CronCreate", "process"},
		{"CronList", "read"},
		{"Artifact", "message"},
		{"PushNotification", "message"},
		{"RemoteTrigger", "agent"},
		{"ReportFindings", "interact"},
		{"ScheduleWakeup", "process"},
		{"SendMessage", "message"},
		{"SendUserFile", "message"},
		{"ShareOnboardingGuide", "message"},
		{"TaskCreate", "process"},
		{"TaskGet", "read"},
		{"TaskList", "read"},
		{"TaskOutput", "read"},
		{"TaskStop", "process"},
		{"TaskUpdate", "process"},
		{"TodoWrite", "process"},
		{"AskUserQuestion", "interact"},
		{"SomethingUnknown", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := mapClaudeCodeTool(tt.input)
			if got != tt.want {
				t.Errorf("mapClaudeCodeTool(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestOutputHookResult_Cline_Ask(t *testing.T) {
	cmd := &cobra.Command{}
	out := &bytes.Buffer{}
	cmd.SetOut(out)

	stderr := captureStderr(t, func() {
		err := outputHookResult(cmd, "cline", hookAsk, false, "deployment needs approval", "kubectl apply -f deploy.yaml")
		if err != nil {
			t.Fatalf("ask outputHookResult error: %v", err)
		}
	})

	// Stderr should be empty for ask — consistent with Claude Code behavior.
	// Cline has no native ask, so it just cancels; the reason is in ErrorMessage.
	if stderr != "" {
		t.Fatalf("stderr should be empty for ask, got: %q", stderr)
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
