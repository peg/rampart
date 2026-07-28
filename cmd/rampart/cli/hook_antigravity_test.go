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

func TestParseAntigravityInputNormalizesDocumentedTools(t *testing.T) {
	tests := []struct {
		name     string
		toolName string
		args     string
		wantTool string
		wantKey  string
		wantVal  string
	}{
		{name: "command", toolName: "run_command", args: `{"CommandLine":"rm -rf /","Cwd":"."}`, wantTool: "exec", wantKey: "command", wantVal: "rm -rf /"},
		{name: "write", toolName: "write_to_file", args: `{"TargetFile":"/tmp/output","CodeContent":"safe"}`, wantTool: "write", wantKey: "path", wantVal: "/tmp/output"},
		{name: "read", toolName: "view_file", args: `{"AbsolutePath":"/tmp/input"}`, wantTool: "read", wantKey: "path", wantVal: "/tmp/input"},
		{name: "search path", toolName: "grep_search", args: `{"SearchPath":"/tmp/project","Query":"needle"}`, wantTool: "read", wantKey: "path", wantVal: "/tmp/project"},
		{name: "fetch", toolName: "read_url_content", args: `{"Url":"https://example.com"}`, wantTool: "fetch", wantKey: "url", wantVal: "https://example.com"},
		{name: "web search", toolName: "search_web", args: `{"query":"rampart security"}`, wantTool: "fetch", wantKey: "url", wantVal: "rampart security"},
		{name: "mcp", toolName: "mcp_github_create_issue", args: `{"title":"x"}`, wantTool: "mcp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := `{"toolCall":{"name":"` + tt.toolName + `","args":` + tt.args + `},"stepIdx":2,"conversationId":"agy-session"}`
			result, err := parseAntigravityInput(strings.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			if result.Tool != tt.wantTool || result.Agent != "antigravity" || result.RunID != "agy-session" || result.HookEventName != "PreToolUse" {
				t.Fatalf("result = %#v", result)
			}
			if tt.wantKey != "" && result.Params[tt.wantKey] != tt.wantVal {
				t.Fatalf("%s = %#v, want %q", tt.wantKey, result.Params[tt.wantKey], tt.wantVal)
			}
		})
	}
}

func TestMapAntigravityToolCoversDocumentedSurface(t *testing.T) {
	tools := []string{
		"view_file", "write_to_file", "replace_file_content", "multi_replace_file_content", "list_dir", "find_by_name",
		"grep_search", "search_web", "read_url_content", "run_command", "manage_task", "schedule", "list_permissions", "ask_permission",
		"invoke_subagent", "define_subagent", "send_message", "manage_subagents", "ask_question", "generate_image",
	}
	for _, tool := range tools {
		if got := mapAntigravityTool(tool); got == "unknown" {
			t.Errorf("documented Antigravity tool %q is not classified", tool)
		}
	}
}

func TestAntigravityUnknownToolEmitsStructuredDeny(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	var stdout, stderr bytes.Buffer
	cmd := NewRootCmd(context.Background(), &stdout, &stderr)
	cmd.SetIn(strings.NewReader(`{"toolCall":{"name":"future_mutator","args":{}},"conversationId":"s"}`))
	cmd.SetArgs([]string{"hook", "--format", "antigravity", "--audit-dir", filepath.Join(home, "audit")})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("hook command returned an ordinary host error instead of a structured denial: %v", err)
	}
	var output map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("structured output = %q: %v", stdout.String(), err)
	}
	if output["decision"] != "deny" {
		t.Fatalf("decision = %#v, want deny", output["decision"])
	}
}

func TestParseAntigravityInputRejectsOversizedWriteBatch(t *testing.T) {
	paths := make([]any, maxCodexPatchPaths+1)
	for i := range paths {
		paths[i] = filepath.Join("src", "file-"+strconv.Itoa(i))
	}
	payload, err := json.Marshal(map[string]any{
		"toolCall": map[string]any{
			"name": "multi_replace_file_content",
			"args": map[string]any{"TargetFiles": paths},
		},
		"conversationId": "s",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = parseAntigravityInput(bytes.NewReader(payload))
	if err == nil || !strings.Contains(err.Error(), "more than 100 paths") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseAntigravityInputClassifiesDestructiveMCPTool(t *testing.T) {
	payload := `{"toolCall":{"name":"mcp_filesystem_delete_file","args":{"path":"important.txt"}},"conversationId":"s"}`
	result, err := parseAntigravityInput(strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if result.Tool != "mcp-destructive" {
		t.Fatalf("tool = %q, want mcp-destructive", result.Tool)
	}
}

func TestOutputAntigravityHookResultUsesForceAsk(t *testing.T) {
	for _, test := range []struct {
		decision hookDecisionType
		want     string
	}{
		{decision: hookAllow, want: "allow"},
		{decision: hookDeny, want: "deny"},
		{decision: hookAsk, want: "force_ask"},
		{decision: hookBlock, want: "deny"},
	} {
		var output bytes.Buffer
		if err := outputAntigravityHookResult(&output, test.decision, "test reason"); err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
			t.Fatal(err)
		}
		if got := decoded["decision"]; got != test.want {
			t.Fatalf("decision %v output = %s, want %q", test.decision, output.String(), test.want)
		}
	}
}
