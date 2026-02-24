package cli

import (
	"strings"
	"testing"
)

func TestFormatDenyMessage_NoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	msg := formatDenyMessage("rm -rf /", "destructive command", nil)
	if !strings.Contains(msg, "Rampart blocked: rm -rf /") {
		t.Fatalf("missing command in deny message: %q", msg)
	}
	if !strings.Contains(msg, "Reason: destructive command") {
		t.Fatalf("missing reason in deny message: %q", msg)
	}
	if strings.Contains(msg, "\033[") {
		t.Fatalf("expected no ANSI color escapes with NO_COLOR set: %q", msg)
	}
}

func TestFormatDenyMessage_WithSuggestions(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	suggestions := []string{
		`rampart allow "npm install lodash"`,
		`rampart allow "npm install *"`,
	}
	msg := formatDenyMessage("npm install lodash", "package installation blocked", suggestions)
	if !strings.Contains(msg, "Rampart blocked: npm install lodash") {
		t.Fatalf("missing command in deny message: %q", msg)
	}
	if !strings.Contains(msg, "To allow:") {
		t.Fatalf("missing 'To allow:' section: %q", msg)
	}
	if !strings.Contains(msg, `rampart allow "npm install lodash"`) {
		t.Fatalf("missing exact suggestion: %q", msg)
	}
	if !strings.Contains(msg, `rampart allow "npm install *"`) {
		t.Fatalf("missing wildcard suggestion: %q", msg)
	}
}

func TestFormatDenyMessage_NoSuggestions(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	msg := formatDenyMessage("cat /etc/shadow", "sensitive file access blocked", []string{})
	if !strings.Contains(msg, "Rampart blocked:") {
		t.Fatalf("missing blocked line: %q", msg)
	}
	if strings.Contains(msg, "To allow:") {
		t.Fatalf("should not show 'To allow:' with empty suggestions: %q", msg)
	}
}
