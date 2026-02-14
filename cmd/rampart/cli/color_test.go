package cli

import (
	"strings"
	"testing"
)

func TestFormatDenyMessage_NoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	msg := formatDenyMessage("rm -rf /", "destructive command")
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
