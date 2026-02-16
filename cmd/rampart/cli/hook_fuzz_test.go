package cli

import (
	"bytes"
	"log/slog"
	"os"
	"strings"
	"testing"
)

func FuzzParseClaudeCodeInput(f *testing.F) {
	// Add seed corpus with realistic Claude Code hook input
	f.Add(`{
		"tool_name": "Bash", 
		"tool_input": {
			"command": "echo hello world"
		}
	}`)

	f.Add(`{
		"tool_name": "ReadFile",
		"tool_input": {
			"path": "/etc/passwd"
		}
	}`)

	f.Add(`{
		"tool_name": "WriteFile", 
		"tool_input": {
			"path": "/tmp/test.txt",
			"content": "dangerous content rm -rf /"
		}
	}`)

	f.Add(`{
		"tool_name": "WebFetch",
		"tool_input": {
			"url": "https://malicious.com/payload"
		}
	}`)

	// Edge cases
	f.Add(`{}`)
	f.Add(`{"tool_name": ""}`)
	f.Add(`{"tool_name": "Bash"}`) // missing tool_input
	f.Add(`{"tool_input": {"command": "test"}}`) // missing tool_name
	f.Add(`invalid json`)
	f.Add(`null`)
	f.Add(`"string instead of object"`)
	f.Add(`{"tool_name": null, "tool_input": null}`)

	f.Fuzz(func(t *testing.T, data string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic in parseClaudeCodeInput: %v", r)
			}
		}()

		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
		reader := strings.NewReader(data)

		// Should never panic, even with malformed JSON
		result, err := parseClaudeCodeInput(reader, logger)
		_, _ = result, err
		// We don't care if it fails, just that it doesn't panic
	})
}

func FuzzParseClineInput(f *testing.F) {
	// Add seed corpus with realistic Cline hook input
	f.Add(`{
		"clineVersion": "1.0.0",
		"hookName": "preToolUse", 
		"timestamp": "2024-01-01T00:00:00Z",
		"taskId": "task123",
		"workspaceRoots": ["/home/user/project"],
		"preToolUse": {
			"toolName": "execute_command",
			"parameters": {
				"command": "rm -rf dangerous"
			}
		}
	}`)

	f.Add(`{
		"clineVersion": "1.0.0",
		"hookName": "postToolUse",
		"timestamp": "2024-01-01T00:00:00Z", 
		"taskId": "task456",
		"workspaceRoots": [],
		"postToolUse": {
			"toolName": "read_file",
			"parameters": {
				"path": "/etc/shadow"
			}
		}
	}`)

	f.Add(`{
		"clineVersion": "1.0.0",
		"hookName": "preToolUse",
		"preToolUse": {
			"toolName": "browser_action", 
			"parameters": {
				"url": "https://webhook.site/evil",
				"action": "navigate"
			}
		}
	}`)

	// Edge cases
	f.Add(`{}`)
	f.Add(`{"clineVersion": "1.0.0"}`) // missing tool use
	f.Add(`{"preToolUse": null, "postToolUse": null}`)
	f.Add(`{"preToolUse": {"toolName": ""}}`) // empty tool name
	f.Add(`{"preToolUse": {"parameters": null}}`) // missing tool name
	f.Add(`invalid cline json`)
	f.Add(`["array", "instead", "of", "object"]`)
	f.Add(`42`)

	f.Fuzz(func(t *testing.T, data string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic in parseClineInput: %v", r)
			}
		}()

		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
		reader := strings.NewReader(data)

		// Should never panic, even with malformed JSON
		result, err := parseClineInput(reader, logger)
		_, _ = result, err
		// We don't care if it fails, just that it doesn't panic
	})
}

func FuzzMapTools(f *testing.F) {
	// Test tool mapping functions with random input
	f.Add("Bash")
	f.Add("ReadFile")
	f.Add("execute_command")
	f.Add("read_file")
	f.Add("")
	f.Add("UnknownTool")
	f.Add("\x00\x01invalid")
	f.Add("very_long_tool_name_that_might_cause_issues")

	f.Fuzz(func(t *testing.T, toolName string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic in tool mapping: %v", r)
			}
		}()

		// Test Claude Code tool mapping
		mapped := mapClaudeCodeTool(toolName)
		_ = mapped

		// Test Cline tool mapping  
		mapped = mapClineTool(toolName)
		_ = mapped
	})
}

func FuzzHookInputStructures(f *testing.F) {
	// Test with various JSON structures that might break unmarshaling
	f.Add(`{"tool_name": {"nested": "object"}, "tool_input": "string"}`)
	f.Add(`{"tool_name": 12345, "tool_input": [1,2,3]}`)
	f.Add(`{"tool_name": true, "tool_input": false}`)
	f.Add(`{"preToolUse": {"toolName": 42, "parameters": "not an object"}}`)
	f.Add(`{"postToolUse": [1,2,3]}`)

	// Very nested structures
	f.Add(`{"tool_input": {"a": {"b": {"c": {"d": {"e": "deep"}}}}}}`)

	// Large JSON
	largeJson := `{"tool_name": "test", "tool_input": {"data": "`
	for i := 0; i < 1000; i++ {
		largeJson += "x"
	}
	largeJson += `"}}`
	f.Add(largeJson)

	f.Fuzz(func(t *testing.T, jsonData string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic with JSON structure: %v", r)
			}
		}()

		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
		
		// Test both parsers with the same data to see how they handle unexpected structures
		reader1 := bytes.NewReader([]byte(jsonData))
		parseClaudeCodeInput(reader1, logger)

		reader2 := bytes.NewReader([]byte(jsonData))
		parseClineInput(reader2, logger)
	})
}