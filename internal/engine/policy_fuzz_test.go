package engine

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func FuzzParsePolicy(f *testing.F) {
	// Add seed corpus with real-world policy examples
	f.Add([]byte(`
version: "1"
default_action: "deny"
policies:
  - name: "basic-allow"
    match:
      agent: "*"
      tool: ["exec", "read"]
    rules:
      - action: "allow"
        when:
          command_matches: ["echo *"]
`))

	f.Add([]byte(`
version: "1"
default_action: "allow"
policies:
  - name: "complex-policy"
    priority: 50
    enabled: true
    match:
      agent: "test-*"
      tool: ["exec", "fetch", "write"]
    rules:
      - action: "deny"
        when:
          command_matches: ["rm -rf *", "dd if=*"]
          path_not_matches: ["/tmp/*"]
        message: "Dangerous command blocked"
      - action: "require_approval" 
        when:
          url_matches: ["https://webhook.site/*"]
        message: "External webhook requires approval"
        webhook:
          url: "https://example.com/hook"
          timeout: "10s"
          fail_open: true
      - action: "allow"
        when:
          default: true
notify:
  url: "https://slack.example.com/webhook"
  platform: "slack"
  on: ["deny", "log"]
`))

	f.Add([]byte(`{invalid yaml content`))
	f.Add([]byte(""))
	f.Add([]byte("\x00\x01\x02malformed\xff\xfe"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Create a temporary file with the fuzzed YAML data
		tmpFile, err := os.CreateTemp("", "policy-fuzz-*.yaml")
		if err != nil {
			t.Skip("Failed to create temp file")
		}
		defer os.Remove(tmpFile.Name())
		defer tmpFile.Close()

		if _, err := tmpFile.Write(data); err != nil {
			t.Skip("Failed to write temp file")
		}
		tmpFile.Close()

		store := NewFileStore(tmpFile.Name())
		
		// This should never panic, even with malformed input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic occurred: %v", r)
			}
		}()

		// Try to load the policy - should handle any YAML gracefully
		_, err = store.Load()
		// We don't care if it fails, just that it doesn't panic
		_ = err

		// Also test direct YAML unmarshaling
		var cfg Config
		err = yaml.Unmarshal(data, &cfg)
		_ = err // Don't care about errors, just no panics

		// Test validation on potentially malformed config
		if err == nil {
			_ = cfg.validate()
		}
	})
}