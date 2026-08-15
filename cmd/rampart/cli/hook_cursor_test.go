// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseCursorInputNormalizesCurrentToolShapes(t *testing.T) {
	tests := []struct {
		name, toolName, input, cwd, wantTool, wantKey, wantValue string
	}{
		{name: "shell", toolName: "Shell", input: `{"command":"git status"}`, wantTool: "exec", wantKey: "command", wantValue: "git status"},
		{name: "read", toolName: "Read", input: `{"file_path":"README.md"}`, wantTool: "read", wantKey: "path", wantValue: "README.md"},
		{name: "grep workspace", toolName: "Grep", input: `{"pattern":"TODO"}`, cwd: "/workspace", wantTool: "read", wantKey: "path", wantValue: "/workspace"},
		{name: "write", toolName: "Write", input: `{"filePath":"main.go"}`, wantTool: "write", wantKey: "path", wantValue: "main.go"},
		{name: "mcp", toolName: "MCP:github_create_issue", input: `{"title":"test"}`, wantTool: "mcp"},
		{name: "task", toolName: "Task", input: `{"prompt":"review"}`, wantTool: "agent"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			payload := `{"conversation_id":"conversation-1","generation_id":"generation-1","hook_event_name":"preToolUse","cwd":"` + testCase.cwd + `","tool_name":"` + testCase.toolName + `","tool_use_id":"tool-1","tool_input":` + testCase.input + `}`
			result, err := parseCursorInput(strings.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			if result.Tool != testCase.wantTool || result.Agent != "cursor" || result.RunID != "conversation-1" || result.ToolUseID != "tool-1" {
				t.Fatalf("result = %#v", result)
			}
			if testCase.wantKey != "" && result.Params[testCase.wantKey] != testCase.wantValue {
				t.Fatalf("%s = %#v, want %q", testCase.wantKey, result.Params[testCase.wantKey], testCase.wantValue)
			}
		})
	}
}

func TestParseCursorInputFailsClosedForUnknownAndAmbiguousTools(t *testing.T) {
	for _, payload := range []string{
		`{"hook_event_name":"preToolUse","tool_name":"FutureMutator","tool_input":{}}`,
		`{"hook_event_name":"preToolUse","tool_name":"Shell","tool_input":{}}`,
		`{"hook_event_name":"preToolUse","tool_name":"Shell","tool_input":{"command":"safe","cmd":"different"}}`,
		`{"hook_event_name":"preToolUse","tool_name":"Write","tool_input":{}}`,
		`{"hook_event_name":"postToolUse","tool_name":"Shell","tool_input":{"command":"safe"}}`,
	} {
		if _, err := parseCursorInput(strings.NewReader(payload)); err == nil {
			t.Fatalf("payload unexpectedly accepted: %s", payload)
		}
	}
}

func TestParseCursorInputEvaluatesEveryWritePath(t *testing.T) {
	payload := `{"conversation_id":"c","hook_event_name":"preToolUse","tool_name":"Write","tool_use_id":"t","tool_input":{"files":[{"filePath":"safe.txt"},{"file_path":".env"}]}}`
	result, err := parseCursorInput(strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.PolicyPaths) != 2 || result.PolicyPaths[0] != "safe.txt" || result.PolicyPaths[1] != ".env" {
		t.Fatalf("PolicyPaths = %#v", result.PolicyPaths)
	}
}

func TestOutputCursorHookResultPreservesNativePermissionsAndFailsClosed(t *testing.T) {
	for _, testCase := range []struct {
		decision hookDecisionType
		want     string
	}{
		{decision: hookAllow, want: ""},
		{decision: hookDeny, want: "deny"},
		{decision: hookAsk, want: "deny"},
	} {
		var output bytes.Buffer
		if err := outputCursorHookResult(&output, testCase.decision, "test reason"); err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded["permission"] != testCase.want && !(testCase.want == "" && decoded["permission"] == nil) {
			t.Fatalf("decision %v output = %s", testCase.decision, output.String())
		}
	}
}

func TestCursorMalformedToolEmitsProtocolDeny(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(context.Background(), &stdout, &stderr)
	cmd.SetIn(strings.NewReader(`{"conversation_id":"c","hook_event_name":"preToolUse","tool_name":"Shell","tool_input":{}}`))
	cmd.SetArgs([]string{"hook", "--format", "cursor", "--audit-dir", filepath.Join(home, "audit")})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("hook returned an ordinary error instead of Cursor's deny response: %v", err)
	}
	var output map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil || output["permission"] != "deny" {
		t.Fatalf("structured output = %q, error = %v", stdout.String(), err)
	}
}
