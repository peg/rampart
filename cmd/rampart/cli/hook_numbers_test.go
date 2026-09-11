// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNativeHookArgumentNumbersRemainExact(t *testing.T) {
	const args = `{"command":"echo numeric-canary","sequence":9007199254740993,"nested":[0.1234567890123456789,1e400]}`
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, tc := range []struct {
		name    string
		payload string
		parse   func(io.Reader) (*hookParseResult, error)
	}{
		{"claude-code", fmt.Sprintf(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":%s}`, args), func(r io.Reader) (*hookParseResult, error) { return parseClaudeCodeInput(r, logger) }},
		{"codex", fmt.Sprintf(`{"session_id":"numeric-session","tool_use_id":"numeric-call","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":%s}`, args), parseCodexInput},
		{"cline", fmt.Sprintf(`{"hookName":"PreToolUse","preToolUse":{"toolName":"execute_command","parameters":%s}}`, args), func(r io.Reader) (*hookParseResult, error) { return parseClineInput(r, logger) }},
		{"cline-record", fmt.Sprintf(`{"hookName":"tool_call","preToolUse":{"toolName":"execute_command"},"tool_call":{"id":"numeric-call","name":"execute_command","input":%s}}`, args), func(r io.Reader) (*hookParseResult, error) { return parseClineInput(r, logger) }},
		{"gemini", fmt.Sprintf(`{"hook_event_name":"BeforeTool","tool_name":"run_shell_command","tool_input":%s}`, args), parseGeminiInput},
		{"antigravity", fmt.Sprintf(`{"stepIdx":7,"toolCall":{"name":"run_command","args":%s}}`, args), parseAntigravityInput},
		{"copilot", fmt.Sprintf(`{"hook_event_name":"PreToolUse","tool_name":"bash","tool_input":%s}`, args), parseCopilotInput},
		{"cursor", fmt.Sprintf(`{"hook_event_name":"preToolUse","tool_name":"Shell","tool_input":%s}`, args), parseCursorInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tc.parse(strings.NewReader(tc.payload))
			require.NoError(t, err)
			require.Equal(t, "exec", result.Tool)
			require.Equal(t, json.Number("9007199254740993"), result.Params["sequence"])
			require.Equal(t, []any{json.Number("0.1234567890123456789"), json.Number("1e400")}, result.Params["nested"])
		})
	}
}

func TestNativeHookTypedIntegerStillRejectsInvalidValues(t *testing.T) {
	for _, value := range []string{"1.5", "1e400", `"7"`} {
		_, err := parseAntigravityInput(strings.NewReader(fmt.Sprintf(`{"stepIdx":%s,"toolCall":{"name":"run_command","args":{"command":"echo numeric-canary"}}}`, value)))
		require.Error(t, err)
	}
}
