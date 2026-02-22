package engine

import (
	"testing"
	"time"
)

func FuzzMatchCondition(f *testing.F) {
	// Add seed corpus with various condition and ToolCall combinations
	f.Add("exec", "test-agent", "ssh root@example.com", "/etc/passwd", "https://evil.com", "evil.com")
	f.Add("read", "admin", "cat secret.txt", "/home/user/.ssh/id_rsa", "", "")
	f.Add("fetch", "bot-*", "curl webhook.site", "", "https://webhook.site/abc123", "webhook.site")
	f.Add("write", "user", "rm -rf /", "/tmp/dangerous", "", "")
	f.Add("", "", "", "", "", "")

	f.Fuzz(func(t *testing.T, tool, agent, command, path, url, domain string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic in matchCondition: %v", r)
			}
		}()

		// Create random ToolCall
		call := ToolCall{
			ID:        "fuzz-" + tool,
			Agent:     agent,
			Session:   "fuzz-session",
			Tool:      tool,
			Timestamp: time.Now().UTC(),
			Params: map[string]any{
				"command": command,
				"path":    path,
				"url":     url,
				"domain":  domain,
			},
		}

		// Test various condition combinations
		conditions := []Condition{
			{Default: true},
			{CommandMatches: []string{command, "test*", "*" + command + "*"}},
			{CommandNotMatches: []string{command, "forbidden*"}},
			{PathMatches: []string{path, "/etc/*", "**/*.key"}},
			{PathNotMatches: []string{path, "/safe/*"}},
			{URLMatches: []string{url, "https://*", "**evil**"}},
			{DomainMatches: []string{domain, "*.com", "malicious*"}},
			{ResponseMatches: []string{"error", ".*secret.*", "password.*"}},
			{ResponseNotMatches: []string{"safe", "allowed"}},
			{
				// Complex condition with multiple fields
				CommandMatches:  []string{"ssh *", "wget *"},
				PathNotMatches:  []string{"/safe/*"},
				URLMatches:      []string{"https://*"},
				ResponseMatches: []string{".*"},
			},
		}

		for _, cond := range conditions {
			// Test matchCondition - should never panic
			result := matchCondition(cond, call, nil)
			_ = result

			// Test ExplainCondition - should never panic
			matched, explanation := ExplainCondition(cond, call)
			_, _ = matched, explanation

			// Test condition methods
			_ = cond.IsEmpty()
		}

		// Test MatchGlob with various patterns
		patterns := []string{"", "*", "**", tool, "*" + tool + "*", tool + "**", "***", "\\", "\x00"}
		for _, pattern := range patterns {
			result := MatchGlob(pattern, command)
			_ = result
			result = MatchGlob(pattern, path)
			_ = result
			result = MatchGlob(pattern, url)
			_ = result
		}
	})
}

func FuzzMatchGlob(f *testing.F) {
	// Add seed corpus for glob matching edge cases
	f.Add("*", "anything")
	f.Add("", "")
	f.Add("**", "deep/nested/path")
	f.Add("git *", "git push origin main")
	f.Add("rm -rf *", "rm -rf /")
	f.Add("/etc/**", "/etc/passwd")
	f.Add("*curl*webhook*", "curl https://webhook.site/abc")
	f.Add("***", "test")

	f.Fuzz(func(t *testing.T, pattern, name string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic in MatchGlob(%q, %q): %v", pattern, name, r)
			}
		}()

		result := MatchGlob(pattern, name)
		_ = result // We don't care about the result, just that it doesn't panic
	})
}
