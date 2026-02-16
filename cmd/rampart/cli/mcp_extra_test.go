package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/peg/rampart/internal/audit"
)

func TestResolveMCPPolicyPath_ExistingFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rampart.yaml")
	os.WriteFile(p, []byte("version: 1\n"), 0o644)

	got, cleanup, err := resolveMCPPolicyPath(p)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got != p {
		t.Errorf("got %q, want %q", got, p)
	}
}

func TestResolveMCPPolicyPath_Fallback(t *testing.T) {
	got, cleanup, err := resolveMCPPolicyPath("/nonexistent/rampart.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got == "" {
		t.Fatal("expected temp file path")
	}
	data, _ := os.ReadFile(got)
	if len(data) == 0 {
		t.Fatal("expected non-empty policy")
	}
}

func TestResolveTestPolicyPath_ExistingFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rampart.yaml")
	os.WriteFile(p, []byte("version: 1\n"), 0o644)

	got, cleanup, err := resolveTestPolicyPath(p)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got != p {
		t.Errorf("got %q, want %q", got, p)
	}
}

func TestResolveTestPolicyPath_Fallback(t *testing.T) {
	got, cleanup, err := resolveTestPolicyPath("/nonexistent/rampart.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got == "" {
		t.Fatal("expected temp file path")
	}
}

func TestAppendSink(t *testing.T) {
	dir := t.TempDir()
	f, err := os.CreateTemp(dir, "audit-*.jsonl")
	if err != nil {
		t.Fatal(err)
	}

	sink := &appendSink{file: f}

	event := audit.Event{
		ID:   "test-1",
		Tool: "exec",
		Decision: audit.EventDecision{
			Action:  "allow",
			Message: "test",
		},
	}
	if err := sink.Write(event); err != nil {
		t.Fatal(err)
	}
	if err := sink.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(f.Name())
	if len(data) == 0 {
		t.Fatal("expected non-empty audit file")
	}
}
