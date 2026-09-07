package proxy

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/peg/rampart/internal/engine"
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
	f.Add(`{}`)                                                  // empty object
	f.Add(`{"agent": ""}`)                                       // empty agent
	f.Add(`{"params": null}`)                                    // null params
	f.Add(`{"agent": null, "session": null, "params": null}`)    // all null
	f.Add(`{"params": {"nested": {"very": {"deep": "value"}}}}`) // deeply nested params

	// Invalid JSON
	f.Add(`invalid json`)
	f.Add(`{"unclosed": object`)
	f.Add(`null`)
	f.Add(`"string instead of object"`)
	f.Add(`[1, 2, 3]`) // array instead of object
	f.Add(`42`)        // number instead of object
	f.Add(`{"agent": 12345, "session": true, "params": "not an object"}`)
	f.Add(`{"agent": {"nested": "object"}, "params": [1,2,3]}`)
	f.Add(`{"params": {"command": null, "path": false, "url": 123}}`)
	f.Add(`{"params": {"a": {"b": {"c": {"d": {"e": {"f": {"g": "deep"}}}}}}}}`)
	f.Add(`[{"agent": "test"}, {"agent": "test2"}]`)
	f.Add(`{"agent": "\u0000\u0001\u0002", "params": {"command": "\xff\xfe\xfd"}}`)
	f.Add(`{} {}`) // trailing JSON must be rejected by the HTTP decoder

	// Large payloads
	largeParams := `{"agent": "test", "params": {"data": "`
	for i := 0; i < 5000; i++ {
		largeParams += "x"
	}
	largeParams += `"}}`
	f.Add(largeParams)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := engine.NewMemoryStore([]byte("version: \"1\"\ndefault_action: deny\n"), "fuzz:http-request")
	if _, err := engine.New(store, logger); err != nil {
		f.Fatalf("invalid fixed HTTP policy: %v", err)
	}
	f.Fuzz(func(t *testing.T, jsonData string) {
		// Use the real decoder, request preparation, and policy handler with
		// isolated in-memory state. The deny policy cannot execute a tool.
		eng, err := engine.New(store, logger)
		if err != nil {
			t.Fatalf("create engine: %v", err)
		}
		srv := New(eng, &mockSink{}, WithMode("enforce"), WithToken("fuzz-token"), WithLogger(logger))
		defer func() {
			if err := srv.Shutdown(context.Background()); err != nil {
				t.Errorf("shutdown fuzz server: %v", err)
			}
		}()
		req := httptest.NewRequest(http.MethodPost, "/v1/tool/exec", strings.NewReader(jsonData))
		req.Header.Set("Authorization", "Bearer fuzz-token")
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		srv.handler().ServeHTTP(recorder, req)

		var response struct {
			Allowed  *bool  `json:"allowed"`
			Decision string `json:"decision"`
			Error    string `json:"error"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("invalid handler response: %v", err)
		}
		switch recorder.Code {
		case http.StatusBadRequest:
			if response.Error == "" {
				t.Fatal("invalid request was not explained")
			}
		case http.StatusForbidden:
			if response.Allowed == nil || *response.Allowed || response.Decision != "deny" {
				t.Fatal("fixed deny policy did not return a denial")
			}
		default:
			t.Fatalf("unexpected status for deny-only handler: %d", recorder.Code)
		}
	})
}

func FuzzEnrichParams(f *testing.F) {
	// Add seed corpus for parameter enrichment
	f.Add("exec", `{"command": "curl https://evil.com"}`)
	f.Add("fetch", `{"url": "https://webhook.site/abc123"}`)
	f.Add("read", `{"path": "/etc/passwd"}`)
	f.Add("write", `{"path": "/tmp/test", "content": "data"}`)
	f.Add("exec", `{"command_b64": "Y3VybCBodHRwczovL2V2aWwuY29t"}`) // base64 encoded
	f.Add("", `{}`)                                                  // empty params

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
	f.Add("ZWNobyBoZWxsbw==") // "echo hello"
	f.Add("cm0gLXJmIC8=")     // "rm -rf /"
	f.Add("")                 // empty
	f.Add("invalid_base64")   // invalid
	f.Add("////")             // valid base64, garbage binary

	f.Fuzz(func(t *testing.T, b64 string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic in decodeBase64Command: %v", r)
			}
		}()

		params := map[string]any{"command_b64": b64}
		result, ok := decodeBase64Command(params)
		_, _ = result, ok
	})
}
