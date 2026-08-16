// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import "testing"

func TestClassifyNativeMCPTool(t *testing.T) {
	for _, test := range []struct {
		name     string
		hostTool string
		params   map[string]any
		want     string
	}{
		{name: "Claude encoded destructive", hostTool: "mcp__filesystem__delete_file", want: "mcp-destructive"},
		{name: "Cursor encoded destructive", hostTool: "MCP:filesystem_delete_file", want: "mcp-destructive"},
		{name: "prefixed destructive", hostTool: "mcp_filesystem_delete_file", want: "mcp-destructive"},
		{name: "wrapped destructive", hostTool: "use_mcp_tool", params: map[string]any{"tool_name": "delete_file"}, want: "mcp-destructive"},
		{name: "wrapped command", hostTool: "use_mcp_tool", params: map[string]any{"toolName": "execute_command"}, want: "exec"},
		{name: "wrapped read", hostTool: "use_mcp_tool", params: map[string]any{"mcp_tool": "read_file"}, want: "read"},
		{name: "unclassified MCP", hostTool: "mcp_github_create_issue", want: "mcp"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyNativeMCPTool(test.hostTool, test.params); got != test.want {
				t.Fatalf("classification = %q, want %q", got, test.want)
			}
		})
	}
}

func TestNativeHookMCPMappersUseCentralClassifier(t *testing.T) {
	toolName := "mcp_filesystem_delete_file"
	if got := mapCopilotTool(toolName); got != "mcp-destructive" {
		t.Fatalf("Copilot = %q", got)
	}
	if got := mapAntigravityTool(toolName); got != "mcp-destructive" {
		t.Fatalf("Antigravity = %q", got)
	}
	if got := mapGeminiTool(toolName); got != "mcp-destructive" {
		t.Fatalf("Gemini = %q", got)
	}
	if got := mapClaudeCodeTool("mcp__filesystem__delete_file"); got != "mcp-destructive" {
		t.Fatalf("Claude = %q", got)
	}
	if got := mapCodexTool("mcp__filesystem__delete_file"); got != "mcp-destructive" {
		t.Fatalf("Codex = %q", got)
	}
	if got := mapCursorTool("MCP:filesystem_delete_file", map[string]any{"path": "important.txt"}); got != "mcp-destructive" {
		t.Fatalf("Cursor = %q", got)
	}
}
