// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"strings"
	"testing"
)

func parseHookAliasTestPayload(adapter, payload string) (*hookParseResult, error) {
	reader := strings.NewReader(payload)
	switch adapter {
	case "claude-code":
		return parseClaudeCodeInput(reader, testLogger())
	case "codex":
		return parseCodexInput(reader)
	case "copilot":
		return parseCopilotInput(reader)
	case "antigravity":
		return parseAntigravityInput(reader)
	case "gemini":
		return parseGeminiInput(reader)
	default:
		panic("unknown test adapter: " + adapter)
	}
}

func TestNativeHookAdaptersRejectAmbiguousSecurityAliases(t *testing.T) {
	tests := []struct {
		name      string
		adapter   string
		payload   string
		wantError string
	}{
		{
			name:      "Claude path conflict",
			adapter:   "claude-code",
			payload:   `{"hook_event_name":"PreToolUse","tool_name":"LSP","tool_input":{"path":"/safe/source.go","filePath":"/protected/source.go"}}`,
			wantError: "conflicting file path aliases",
		},
		{
			name:      "Claude command conflict",
			adapter:   "claude-code",
			payload:   `{"hook_event_name":"PreToolUse","tool_name":"code_execution","tool_input":{"command":"echo safe","code":"rm -rf /"}}`,
			wantError: "conflicting command or code aliases",
		},
		{
			name:      "Codex path conflict",
			adapter:   "codex",
			payload:   `{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Read","tool_use_id":"call-1","tool_input":{"path":"/safe/source.go","filePath":"/protected/source.go"}}`,
			wantError: "conflicting file path aliases",
		},
		{
			name:      "Codex command conflict",
			adapter:   "codex",
			payload:   `{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"shell","tool_use_id":"call-1","tool_input":{"command":"echo safe","script":"rm -rf /"}}`,
			wantError: "conflicting command aliases",
		},
		{
			name:      "Copilot path conflict",
			adapter:   "copilot",
			payload:   `{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"path":"/safe/source.go","filePath":"/protected/source.go"}}`,
			wantError: "conflicting file path aliases",
		},
		{
			name:      "Copilot command conflict",
			adapter:   "copilot",
			payload:   `{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo safe","terminalCommand":"rm -rf /"}}`,
			wantError: "conflicting command aliases",
		},
		{
			name:      "Antigravity path conflict",
			adapter:   "antigravity",
			payload:   `{"toolCall":{"name":"view_file","args":{"path":"/safe/source.go","AbsolutePath":"/protected/source.go"}},"conversationId":"s"}`,
			wantError: "conflicting file path aliases",
		},
		{
			name:      "Antigravity command conflict",
			adapter:   "antigravity",
			payload:   `{"toolCall":{"name":"run_command","args":{"command":"echo safe","CommandLine":"rm -rf /"}},"conversationId":"s"}`,
			wantError: "conflicting command aliases",
		},
		{
			name:      "Gemini path conflict",
			adapter:   "gemini",
			payload:   `{"session_id":"s","hook_event_name":"BeforeTool","tool_name":"read_file","tool_input":{"path":"/safe/source.go","file_path":"/protected/source.go"}}`,
			wantError: "conflicting file path aliases",
		},
		{
			name:      "Claude type confusion",
			adapter:   "claude-code",
			payload:   `{"hook_event_name":"PreToolUse","tool_name":"LSP","tool_input":{"path":"/safe/source.go","filePath":42}}`,
			wantError: "requires file path alias",
		},
		{
			name:      "Codex type confusion",
			adapter:   "codex",
			payload:   `{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"shell","tool_use_id":"call-1","tool_input":{"command":"echo safe","script":[]}}`,
			wantError: "requires command alias",
		},
		{
			name:      "Copilot type confusion",
			adapter:   "copilot",
			payload:   `{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"path":"/safe/source.go","filePath":{}}}`,
			wantError: "requires file path alias",
		},
		{
			name:      "Antigravity type confusion",
			adapter:   "antigravity",
			payload:   `{"toolCall":{"name":"run_command","args":{"command":"echo safe","CommandLine":42}},"conversationId":"s"}`,
			wantError: "requires command alias",
		},
		{
			name:      "Gemini type confusion",
			adapter:   "gemini",
			payload:   `{"session_id":"s","hook_event_name":"BeforeTool","tool_name":"read_file","tool_input":{"path":"/safe/source.go","file_path":42}}`,
			wantError: "requires file path alias",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := parseHookAliasTestPayload(testCase.adapter, testCase.payload)
			if err == nil || !strings.Contains(err.Error(), testCase.wantError) {
				t.Fatalf("error = %v, want %q", err, testCase.wantError)
			}
		})
	}
}

func TestNativeHookAdaptersCanonicalizeEquivalentAliasesWithoutDroppingMetadata(t *testing.T) {
	tests := []struct {
		name      string
		adapter   string
		payload   string
		canonical string
		want      string
	}{
		{
			name:      "Claude",
			adapter:   "claude-code",
			payload:   `{"hook_event_name":"PreToolUse","tool_name":"LSP","tool_input":{"path":" /project/source.go ","filePath":"/project/source.go","trace":"keep"}}`,
			canonical: "path",
			want:      "/project/source.go",
		},
		{
			name:      "Codex",
			adapter:   "codex",
			payload:   `{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"shell","tool_use_id":"call-1","tool_input":{"command":" echo safe ","script":"echo safe","trace":"keep"}}`,
			canonical: "command",
			want:      "echo safe",
		},
		{
			name:      "Copilot",
			adapter:   "copilot",
			payload:   `{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"path":" /project/source.go ","filePath":"/project/source.go","trace":"keep"}}`,
			canonical: "path",
			want:      "/project/source.go",
		},
		{
			name:      "Antigravity",
			adapter:   "antigravity",
			payload:   `{"toolCall":{"name":"view_file","args":{"path":" /project/source.go ","AbsolutePath":"/project/source.go","trace":"keep"}},"conversationId":"s"}`,
			canonical: "path",
			want:      "/project/source.go",
		},
		{
			name:      "Gemini",
			adapter:   "gemini",
			payload:   `{"session_id":"s","hook_event_name":"BeforeTool","tool_name":"read_file","tool_input":{"path":" /project/source.go ","file_path":"/project/source.go","trace":"keep"}}`,
			canonical: "path",
			want:      "/project/source.go",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			parsed, err := parseHookAliasTestPayload(testCase.adapter, testCase.payload)
			if err != nil {
				t.Fatal(err)
			}
			if got := parsed.Params[testCase.canonical]; got != testCase.want {
				t.Fatalf("%s = %#v, want %q", testCase.canonical, got, testCase.want)
			}
			if got := parsed.Params["trace"]; got != "keep" {
				t.Fatalf("benign metadata changed: trace = %#v", got)
			}
		})
	}
}
