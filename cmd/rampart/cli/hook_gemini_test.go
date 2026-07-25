// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseGeminiInputNormalizesDocumentedTools(t *testing.T) {
	tests := []struct {
		name     string
		toolName string
		input    string
		wantTool string
		wantKey  string
		wantVal  string
	}{
		{name: "shell", toolName: "run_shell_command", input: `{"command":"rm -rf /"}`, wantTool: "exec", wantKey: "command", wantVal: "rm -rf /"},
		{name: "write", toolName: "write_file", input: `{"file_path":"/tmp/output","content":"safe"}`, wantTool: "write", wantKey: "path", wantVal: "/tmp/output"},
		{name: "fetch", toolName: "web_fetch", input: `{"prompt":"Fetch https://example.com"}`, wantTool: "fetch", wantKey: "url", wantVal: "Fetch https://example.com"},
		{name: "mcp", toolName: "mcp_github_create_issue", input: `{"title":"x"}`, wantTool: "mcp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := `{"session_id":"gemini-session","hook_event_name":"BeforeTool","tool_name":"` + tt.toolName + `","tool_input":` + tt.input + `}`
			result, err := parseGeminiInput(strings.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			if result.Tool != tt.wantTool || result.Agent != "gemini-cli" || result.RunID != "gemini-session" {
				t.Fatalf("result = %#v", result)
			}
			if tt.wantKey != "" && result.Params[tt.wantKey] != tt.wantVal {
				t.Fatalf("%s = %#v, want %q", tt.wantKey, result.Params[tt.wantKey], tt.wantVal)
			}
		})
	}
}

func TestParseGeminiInputFailsClosedForUnknownBeforeTool(t *testing.T) {
	_, err := parseGeminiInput(strings.NewReader(`{"session_id":"s","hook_event_name":"BeforeTool","tool_name":"future_mutator","tool_input":{}}`))
	if err == nil || !strings.Contains(err.Error(), "unsupported Gemini tool_name") {
		t.Fatalf("error = %v", err)
	}
}

func TestMapGeminiToolCoversCurrentDocumentedSurface(t *testing.T) {
	tools := []string{
		"run_shell_command",
		"glob", "grep_search", "list_directory", "read_file", "read_many_files", "replace", "write_file",
		"ask_user", "write_todos",
		"tracker_create_task", "tracker_update_task", "tracker_get_task", "tracker_list_tasks", "tracker_add_dependency", "tracker_visualize",
		"list_mcp_resources", "read_mcp_resource",
		"activate_skill", "get_internal_docs",
		"enter_plan_mode", "exit_plan_mode",
		"complete_task", "update_topic",
		"google_web_search", "web_fetch",
	}
	for _, tool := range tools {
		if got := mapGeminiTool(tool); got == "unknown" {
			t.Errorf("current documented Gemini tool %q is not classified", tool)
		}
	}
	if got := mapGeminiTool("mcp_github_create_issue"); got != "mcp" {
		t.Fatalf("MCP tool classification = %q, want mcp", got)
	}
}

func TestOutputGeminiHookResultPreservesHostPermissionsAndFailsClosed(t *testing.T) {
	for _, test := range []struct {
		decision hookDecisionType
		want     string
	}{
		{decision: hookAllow, want: ""},
		{decision: hookDeny, want: "deny"},
		{decision: hookAsk, want: "deny"},
		{decision: hookBlock, want: "deny"},
	} {
		var output bytes.Buffer
		if err := outputGeminiHookResult(&output, test.decision, "test reason"); err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
			t.Fatal(err)
		}
		if got, _ := decoded["decision"].(string); got != test.want {
			t.Fatalf("decision %v output = %s, want %q", test.decision, output.String(), test.want)
		}
	}
}
