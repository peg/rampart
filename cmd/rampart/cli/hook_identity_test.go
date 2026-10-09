// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNativeHookMappingsPreservePathAndDirectoryBytes(t *testing.T) {
	const directory = " workspace "
	const path = " notes.txt "
	tests := []struct {
		adapter string
		payload string
		paths   bool
	}{
		{"claude-code", `{"session_id":"s","cwd":" workspace ","hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":" notes.txt "}}`, false},
		{"codex", `{"session_id":"s","cwd":" workspace ","tool_use_id":"call-1","hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":" notes.txt "}}`, false},
		{"copilot", `{"session_id":"s","cwd":" workspace ","hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"filePath":" notes.txt "}}`, true},
		{"cursor", `{"conversation_id":"s","cwd":" workspace ","tool_use_id":"call-1","hook_event_name":"preToolUse","tool_name":"Write","tool_input":{"file_path":" notes.txt "}}`, true},
		{"cline", `{"hookName":"PreToolUse","taskId":"s","workspaceRoots":[" "," workspace "],"preToolUse":{"tool":"write_to_file","parameters":{"path":" notes.txt "}}}`, true},
		{"antigravity", `{"conversationId":"s","workspacePaths":[" "," workspace "],"toolCall":{"name":"write_to_file","args":{"TargetFile":" notes.txt "}}}`, true},
		{"gemini", `{"session_id":"s","cwd":" workspace ","hook_event_name":"BeforeTool","tool_name":"read_many_files","tool_input":{"include":[" notes.txt "]}}`, true},
	}
	for _, tc := range tests {
		t.Run(tc.adapter, func(t *testing.T) {
			parsed, err := parseHookAliasTestPayload(tc.adapter, tc.payload)
			require.NoError(t, err)
			require.Equal(t, directory, parsed.WorkDir)
			require.Equal(t, path, parsed.Params["path"])
			if tc.paths {
				require.Equal(t, []string{path}, parsed.PolicyPaths)
			}
		})
	}
}

func TestCursorWorkspaceSearchPreservesDirectoryBytes(t *testing.T) {
	parsed, err := parseCursorInput(strings.NewReader(`{"conversation_id":"s","cwd":" workspace ","tool_use_id":"call-1","hook_event_name":"preToolUse","tool_name":"Grep","tool_input":{"pattern":"note"}}`))
	require.NoError(t, err)
	require.Equal(t, " workspace ", parsed.Params["path"])
}

func TestHookAliasesDoNotConflateWhitespace(t *testing.T) {
	params := map[string]any{"path": " notes.txt ", "file_path": "notes.txt"}
	_, _, err := normalizeHookStringAliases(params, "path", "hook", "path", "file_path")
	require.ErrorContains(t, err, "conflicting path aliases")
	require.Equal(t, " notes.txt ", params["path"])
}
