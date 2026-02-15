package engine

import (
	"log/slog"
	"os"
	"testing"
	"time"
)

func FuzzEvaluate(f *testing.F) {
	// Add seed corpus with realistic ToolCall examples
	f.Add("exec", "admin-bot", "rm -rf /tmp/test", "")
	f.Add("read", "user-agent", "", "/etc/passwd")
	f.Add("fetch", "web-crawler", "", "https://malicious-site.com/payload")
	f.Add("write", "file-manager", "", "/home/user/.ssh/authorized_keys")
	f.Add("", "", "", "")
	f.Add("unknown-tool", "weird-agent", "malicious command with \x00 nulls", "/invalid/\xff/path")

	f.Fuzz(func(t *testing.T, tool, agent, command, path string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic in Engine.Evaluate: %v", r)
			}
		}()

		// Create a fixed policy configuration for consistent testing
		policyYAML := []byte(`
version: "1"  
default_action: "deny"
policies:
  - name: "allow-safe"
    priority: 10
    match:
      agent: "*"
      tool: ["exec", "read", "write", "fetch"]
    rules:
      - action: "allow" 
        when:
          command_matches: ["echo *", "ls *", "cat *"]
        message: "Safe command allowed"
      - action: "deny"
        when:
          command_matches: ["rm -rf *", "dd if=*", "curl *malicious*"]
        message: "Dangerous command blocked"
      - action: "require_approval"
        when:
          path_matches: ["/etc/*", "**/.ssh/**"]
        message: "Sensitive path requires approval"
      - action: "log"
        when:
          url_matches: ["https://*"]
        message: "External URL logged"

  - name: "agent-specific"
    priority: 5
    match:
      agent: "admin-*"
    rules:
      - action: "allow"
        when:
          default: true
        message: "Admin agent allowed"

  - name: "response-filter"
    match:
      agent: "*"
    rules:
      - action: "deny"
        when:
          response_matches: [".*password.*", ".*secret.*", ".*key.*"]
        message: "Sensitive response content blocked"
`)

		// Create temporary policy file
		tmpFile, err := os.CreateTemp("", "engine-fuzz-*.yaml")
		if err != nil {
			t.Skip("Failed to create temp policy file")
		}
		defer os.Remove(tmpFile.Name())
		defer tmpFile.Close()

		if _, err := tmpFile.Write(policyYAML); err != nil {
			t.Skip("Failed to write policy file")
		}
		tmpFile.Close()

		// Create engine
		store := NewFileStore(tmpFile.Name())
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
		engine, err := New(store, logger)
		if err != nil {
			t.Skip("Failed to create engine")
		}

		// Create random ToolCall
		call := ToolCall{
			ID:        "fuzz-call",
			Agent:     agent,
			Session:   "fuzz-session",
			Tool:      tool,
			Timestamp: time.Now().UTC(),
			Params: map[string]any{
				"command": command,
				"path":    path,
				"url":     "https://example.com/" + tool,
				"domain":  "example.com",
			},
		}

		// Test main evaluation - should never panic
		decision := engine.Evaluate(call)
		_ = decision

		// Test response evaluation with various response content  
		responses := []string{
			"",
			"normal response content",
			"error: password authentication failed",
			"secret key: abc123",
			string([]byte{0, 1, 2, 255, 254, 253}), // binary content
			"very long response " + string(make([]byte, 10000)),
		}

		for _, response := range responses {
			respDecision := engine.EvaluateResponse(call, response)
			_ = respDecision
		}

		// Test engine methods
		_ = engine.PolicyCount()

		// Test reload with potentially broken config
		_ = engine.Reload()
	})
}

func FuzzEngineWithMalformedPolicy(f *testing.F) {
	// Test engine behavior with various broken policy configurations
	f.Add([]byte(`version: "1"`))
	f.Add([]byte(`invalid yaml {`))
	f.Add([]byte(`
version: "1"
policies:
  - name: ""
    rules: []
`))
	f.Add([]byte(""))
	f.Add([]byte("\x00\x01\x02"))

	f.Fuzz(func(t *testing.T, policyData []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic with malformed policy: %v", r)
			}
		}()

		tmpFile, err := os.CreateTemp("", "malformed-policy-*.yaml")
		if err != nil {
			t.Skip("Failed to create temp file")
		}
		defer os.Remove(tmpFile.Name())
		defer tmpFile.Close()

		if _, err := tmpFile.Write(policyData); err != nil {
			t.Skip("Failed to write temp file")
		}
		tmpFile.Close()

		store := NewFileStore(tmpFile.Name())
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

		// Creating engine with malformed policy should not panic
		engine, err := New(store, logger)
		if err != nil {
			return // Expected for malformed policies
		}

		// Even if engine creation succeeded, evaluation should not panic
		call := ToolCall{
			ID:        "test-call",
			Agent:     "test-agent", 
			Session:   "test-session",
			Tool:      "exec",
			Timestamp: time.Now().UTC(),
			Params:    map[string]any{"command": "echo test"},
		}

		decision := engine.Evaluate(call)
		_ = decision
	})
}