// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestParseCopilotInputCoversCLIAndVSCodeTools(t *testing.T) {
	tests := []struct {
		name, toolName, input, wantTool, wantKey, wantValue string
	}{
		{name: "cli shell", toolName: "Bash", input: `{"command":"rm -rf /"}`, wantTool: "exec", wantKey: "command", wantValue: "rm -rf /"},
		{name: "vscode terminal", toolName: "runTerminalCommand", input: `{"command":"git push origin main"}`, wantTool: "exec", wantKey: "command", wantValue: "git push origin main"},
		{name: "cli write", toolName: "Write", input: `{"file_path":"/tmp/out"}`, wantTool: "write", wantKey: "path", wantValue: "/tmp/out"},
		{name: "vscode edit", toolName: "replace_string_in_file", input: `{"filePath":"/tmp/out"}`, wantTool: "write", wantKey: "path", wantValue: "/tmp/out"},
		{name: "web", toolName: "WebFetch", input: `{"url":"https://example.com"}`, wantTool: "fetch", wantKey: "url", wantValue: "https://example.com"},
		{name: "mcp", toolName: "mcp_github_create_issue", input: `{"title":"test"}`, wantTool: "mcp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := `{"session_id":"copilot-session","hook_event_name":"PreToolUse","tool_use_id":"tool-1","tool_name":"` + tt.toolName + `","tool_input":` + tt.input + `}`
			result, err := parseCopilotInput(strings.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			if result.Tool != tt.wantTool || result.Agent != "github-copilot" || result.RunID != "copilot-session" {
				t.Fatalf("result = %#v", result)
			}
			if tt.wantKey != "" && result.Params[tt.wantKey] != tt.wantValue {
				t.Fatalf("%s = %#v, want %q", tt.wantKey, result.Params[tt.wantKey], tt.wantValue)
			}
		})
	}
}

func TestParseCopilotInputFailsClosedForUnknownPreTool(t *testing.T) {
	_, err := parseCopilotInput(strings.NewReader(`{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"future_remote_mutator","tool_input":{}}`))
	if err == nil || !strings.Contains(err.Error(), "unsupported Copilot tool_name") {
		t.Fatalf("error = %v", err)
	}
}

func TestCopilotUnknownPreToolEmitsDualHostStructuredDeny(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(context.Background(), &stdout, &stderr)
	cmd.SetIn(strings.NewReader(`{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"future_remote_mutator","tool_input":{}}`))
	cmd.SetArgs([]string{"hook", "--format", "copilot", "--audit-dir", filepath.Join(home, "audit")})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("hook command returned an ordinary host error instead of a structured denial: %v", err)
	}
	var output map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("structured output = %q: %v", stdout.String(), err)
	}
	if output["permissionDecision"] != "deny" {
		t.Fatalf("CLI decision = %#v, want deny", output["permissionDecision"])
	}
	specific, _ := output["hookSpecificOutput"].(map[string]any)
	if specific["permissionDecision"] != "deny" {
		t.Fatalf("VS Code decision = %#v, want deny", specific["permissionDecision"])
	}
}

func TestParseCopilotInputEvaluatesEveryWritePath(t *testing.T) {
	payload := `{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"editFiles","tool_input":{"files":[{"filePath":"safe.txt"},{"filePath":".env"}]}}`
	result, err := parseCopilotInput(strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.PolicyPaths) != 2 || result.PolicyPaths[0] != "safe.txt" || result.PolicyPaths[1] != ".env" {
		t.Fatalf("PolicyPaths = %#v", result.PolicyPaths)
	}
}

func TestParseCopilotInputRejectsOversizedWriteBatch(t *testing.T) {
	files := make([]any, maxCodexPatchPaths+1)
	for i := range files {
		files[i] = map[string]any{"filePath": filepath.Join("src", "file-"+strconv.Itoa(i))}
	}
	payload, err := json.Marshal(map[string]any{
		"session_id":      "s",
		"hook_event_name": "PreToolUse",
		"tool_name":       "editFiles",
		"tool_input":      map[string]any{"files": files},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = parseCopilotInput(bytes.NewReader(payload))
	if err == nil || !strings.Contains(err.Error(), "more than 100 paths") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseCopilotInputClassifiesDestructiveMCPTool(t *testing.T) {
	payload := `{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"mcp_filesystem_delete_file","tool_input":{"path":"important.txt"}}`
	result, err := parseCopilotInput(strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if result.Tool != "mcp-destructive" {
		t.Fatalf("tool = %q, want mcp-destructive", result.Tool)
	}
}

func TestOutputCopilotHookResultIsDualHostAndPreservesNativePermissions(t *testing.T) {
	for _, test := range []struct {
		decision hookDecisionType
		want     string
	}{
		{decision: hookAllow, want: ""},
		{decision: hookDeny, want: "deny"},
		{decision: hookAsk, want: "ask"},
	} {
		var output bytes.Buffer
		if err := outputCopilotHookResult(&output, test.decision, "test reason"); err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
			t.Fatal(err)
		}
		if got, _ := decoded["permissionDecision"].(string); got != test.want {
			t.Fatalf("decision %v output = %s, want %q", test.decision, output.String(), test.want)
		}
		if test.want != "" {
			specific := decoded["hookSpecificOutput"].(map[string]any)
			if specific["permissionDecision"] != test.want || specific["hookEventName"] != "PreToolUse" {
				t.Fatalf("VS Code decision = %#v", specific)
			}
		}
	}
}

func TestOutputCopilotPostBlockCoversBothHosts(t *testing.T) {
	var output bytes.Buffer
	if err := outputCopilotHookResult(&output, hookBlock, "response policy"); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["decision"] != "block" || decoded["modifiedResult"] == nil || decoded["hookSpecificOutput"] == nil {
		t.Fatalf("post block = %s", output.String())
	}
}
