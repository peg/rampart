package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/peg/rampart/internal/audit"
)

func TestComputeAuditStatsAndFormatAuditStats(t *testing.T) {
	events := []audit.Event{
		{Tool: "exec", Agent: "zeta", Decision: audit.EventDecision{Action: "allow"}, Timestamp: time.Now().UTC()},
		{Tool: "read", Agent: "alpha", Decision: audit.EventDecision{Action: "deny"}, Timestamp: time.Now().UTC()},
		{Tool: "exec", Agent: "alpha", Decision: audit.EventDecision{Action: "watch"}, Timestamp: time.Now().UTC()},
	}

	stats := computeAuditStats(events)
	if stats.Total != 3 {
		t.Fatalf("Total = %d, want 3", stats.Total)
	}
	if stats.ByDecision["allow"] != 1 || stats.ByDecision["deny"] != 1 || stats.ByDecision["watch"] != 1 {
		t.Fatalf("unexpected ByDecision counts: %#v", stats.ByDecision)
	}
	if stats.ByTool["exec"] != 2 || stats.ByTool["read"] != 1 {
		t.Fatalf("unexpected ByTool counts: %#v", stats.ByTool)
	}
	if stats.ByAgent["alpha"] != 2 || stats.ByAgent["zeta"] != 1 {
		t.Fatalf("unexpected ByAgent counts: %#v", stats.ByAgent)
	}

	plain := formatAuditStats(stats, "last 24h", true)
	if !strings.Contains(plain, "Audit Stats (last 24h)") {
		t.Fatalf("missing title: %q", plain)
	}
	if !strings.Contains(plain, "Total events:  3") {
		t.Fatalf("missing total: %q", plain)
	}
	if !strings.Contains(plain, "33.3%") {
		t.Fatalf("missing percentage formatting: %q", plain)
	}

	toolExecIdx := strings.Index(plain, "exec")
	toolReadIdx := strings.Index(plain, "read")
	if toolExecIdx < 0 || toolReadIdx < 0 || toolExecIdx > toolReadIdx {
		t.Fatalf("expected sorted tools in output; output=%q", plain)
	}

	agentAlphaIdx := strings.Index(plain, "alpha")
	agentZetaIdx := strings.Index(plain, "zeta")
	if agentAlphaIdx < 0 || agentZetaIdx < 0 || agentAlphaIdx > agentZetaIdx {
		t.Fatalf("expected sorted agents in output; output=%q", plain)
	}

	colored := formatAuditStats(stats, "last 24h", false)
	if !strings.Contains(colored, colorGreen+"allow"+colorReset) {
		t.Fatalf("missing colored allow label: %q", colored)
	}
	if !strings.Contains(colored, colorRed+"deny"+colorReset) {
		t.Fatalf("missing colored deny label: %q", colored)
	}
	if !strings.Contains(colored, colorYel+"watch"+colorReset) {
		t.Fatalf("missing colored log label: %q", colored)
	}
}

func TestFormatAuditStats_ZeroTotal(t *testing.T) {
	stats := computeAuditStats(nil)
	out := formatAuditStats(stats, "all time", true)
	if !strings.Contains(out, "Total events:  0") {
		t.Fatalf("missing zero total: %q", out)
	}
	if !strings.Contains(out, "0.0%") {
		t.Fatalf("expected 0.0%% percentages with zero total: %q", out)
	}
}
