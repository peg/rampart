// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNativeHookDenialPresentationIsRedacted(t *testing.T) {
	const policy = `version: "1"
policies:
  - name: "review --token=synthetic-policy"
    match:
      tool: exec
    rules:
      - action: deny
        message: "review --token=synthetic-reason"
`
	tests := []struct {
		format, payload, denial string
	}{
		{"claude-code", `{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo note --token=synthetic-action"}}`, `"permissionDecision":"deny"`},
		{"codex", `{"session_id":"s","tool_use_id":"call-1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo note --token=synthetic-action"}}`, `"permissionDecision":"deny"`},
		{"copilot", `{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo note --token=synthetic-action"}}`, `"permissionDecision":"deny"`},
		{"cursor", `{"conversation_id":"s","tool_use_id":"call-1","hook_event_name":"preToolUse","tool_name":"Shell","tool_input":{"command":"echo note --token=synthetic-action"}}`, `"permission":"deny"`},
		{"cline", `{"hookName":"PreToolUse","taskId":"s","preToolUse":{"tool":"execute_command","parameters":{"command":"echo note --token=synthetic-action"}}}`, `"cancel":true`},
		{"gemini", `{"session_id":"s","hook_event_name":"BeforeTool","tool_name":"run_shell_command","tool_input":{"command":"echo note --token=synthetic-action"}}`, `"decision":"deny"`},
		{"antigravity", `{"conversationId":"s","toolCall":{"name":"run_command","args":{"CommandLine":"echo note --token=synthetic-action"}}}`, `"decision":"deny"`},
	}
	for _, tc := range tests {
		t.Run(tc.format, func(t *testing.T) {
			home := t.TempDir()
			testSetHome(t, home)
			policyPath := filepath.Join(home, "policy.yaml")
			require.NoError(t, os.WriteFile(policyPath, []byte(policy), 0o600))
			stdout, stderr, err := runHookWithStdin(t, &rootOptions{configPath: policyPath}, tc.payload,
				"--format", tc.format, "--mode", "enforce", "--audit-dir", filepath.Join(home, "audit"))
			require.NoError(t, err)
			require.Contains(t, stdout, tc.denial)
			for _, secret := range []string{"synthetic-policy", "synthetic-reason", "synthetic-action"} {
				require.NotContains(t, stdout+stderr, secret)
			}
			require.Contains(t, stdout, "[REDACTED]")
			require.NotContains(t, stdout+stderr, "rampart allow")
		})
	}
}
