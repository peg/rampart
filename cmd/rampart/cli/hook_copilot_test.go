// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"encoding/json"
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
