package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/peg/rampart/internal/audit"
)

func TestFileSize(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.jsonl")
	os.WriteFile(f, []byte("hello world\n"), 0o644)

	size, err := fileSize(f)
	if err != nil {
		t.Fatal(err)
	}
	if size != 12 {
		t.Errorf("size = %d, want 12", size)
	}

	_, err = fileSize(filepath.Join(dir, "nonexistent"))
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestReadAuditEventsFromOffset(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "audit.jsonl")

	events := []audit.Event{
		{ID: "1", Tool: "exec", Decision: audit.EventDecision{Action: "allow"}},
		{ID: "2", Tool: "read", Decision: audit.EventDecision{Action: "deny"}},
	}

	var data []byte
	for _, e := range events {
		line, _ := json.Marshal(e)
		data = append(data, line...)
		data = append(data, '\n')
	}
	os.WriteFile(f, data, 0o644)

	got, newOffset, err := readAuditEventsFromOffset(f, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("got %d events, want 2", len(got))
	}
	if newOffset <= 0 {
		t.Errorf("offset should be > 0, got %d", newOffset)
	}

	// Reading from end should return no events
	got2, _, err := readAuditEventsFromOffset(f, newOffset)
	if err != nil {
		t.Fatal(err)
	}
	if len(got2) != 0 {
		t.Errorf("got %d events from end, want 0", len(got2))
	}
}

func TestRenderAuditEventLine(t *testing.T) {
	e := audit.Event{
		Tool: "exec",
		Request: map[string]any{"command": "ls -la"},
		Decision: audit.EventDecision{
			Action:          "deny",
			MatchedPolicies: []string{"block-rm"},
		},
	}

	// No color
	line := renderAuditEventLine(e, true)
	if line == "" {
		t.Fatal("empty line")
	}

	// With color
	colorLine := renderAuditEventLine(e, false)
	if colorLine == "" {
		t.Fatal("empty color line")
	}

	// Allow
	e.Decision.Action = "allow"
	e.Decision.MatchedPolicies = nil
	allowLine := renderAuditEventLine(e, true)
	if allowLine == "" {
		t.Fatal("empty allow line")
	}

	// Log
	e.Decision.Action = "log"
	logLine := renderAuditEventLine(e, true)
	if logLine == "" {
		t.Fatal("empty log line")
	}
}
