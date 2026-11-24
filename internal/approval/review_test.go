// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package approval

import (
	"testing"

	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/internal/notify"
)

func TestSummarizeCall(t *testing.T) {
	for _, tc := range []struct {
		name string
		call engine.ToolCall
		want string
	}{
		{"command", engine.ToolCall{Tool: "exec", Params: map[string]any{"command": "deploy --password=hunter2"}}, "deploy [REDACTED]"},
		{"path", engine.ToolCall{Tool: "read", Params: map[string]any{"file_path": "/tmp/in.txt"}}, "/tmp/in.txt"},
		{"url", engine.ToolCall{Tool: "fetch", Params: map[string]any{"url": "https://example.com/x"}}, "https://example.com/x"},
		{"mcp tool only", engine.ToolCall{Tool: "mcp", Params: map[string]any{"mcp_tool": " delete_repo "}}, "delete_repo"},
		{"mcp tool and command", engine.ToolCall{Tool: "mcp-dangerous", Params: map[string]any{"mcp_tool": "run_task", "command": "make"}}, "run_task — make"},
		{"mcp tool and redacted target", engine.ToolCall{Tool: "mcp", Params: map[string]any{"mcp_tool": "open", "url": "https://x.test/?token=abc"}}, "open — https://x.test/?token=[REDACTED]"},
		{"redacted mcp tool", engine.ToolCall{Tool: "mcp", Params: map[string]any{"mcp_tool": "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}, "[REDACTED]"},
		// Notifiers sanitize the joined text again; a tool named like a
		// credential key must not cause the target to be redacted.
		{"credential-like tool name", engine.ToolCall{Tool: "mcp", Params: map[string]any{"mcp_tool": "token", "path": "/tmp/x"}}, "token — /tmp/x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := SummarizeCall(tc.call).String()
			if got != tc.want {
				t.Fatalf("SummarizeCall().String() = %q, want %q", got, tc.want)
			}
			if again := notify.SanitizeCommand(got); again != got {
				t.Fatalf("summary is not stable under output sanitization: %q -> %q", got, again)
			}
		})
	}
}
