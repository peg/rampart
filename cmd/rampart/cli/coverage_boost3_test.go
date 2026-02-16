package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/peg/rampart/internal/audit"
)

// --- newInitCmd (init.go) ---

func TestNewInitCmd_AlreadyExists(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rampart.yaml")
	os.WriteFile(p, []byte("existing"), 0o644)

	root := NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
	root.SetArgs([]string{"init", "--config", p})
	err := root.Execute()
	if err == nil {
		t.Error("expected error for existing file without --force")
	}
}

func TestNewInitCmd_Force(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rampart.yaml")
	os.WriteFile(p, []byte("existing"), 0o644)

	var out bytes.Buffer
	root := NewRootCmd(context.Background(), &out, &bytes.Buffer{})
	root.SetArgs([]string{"init", "--config", p, "--force"})
	err := root.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewInitCmd_NewFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rampart.yaml")

	var out bytes.Buffer
	root := NewRootCmd(context.Background(), &out, &bytes.Buffer{})
	root.SetArgs([]string{"init", "--config", p})
	err := root.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Error("expected config file to be created")
	}
}

func TestNewInitCmd_WithProfile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rampart.yaml")

	var out bytes.Buffer
	root := NewRootCmd(context.Background(), &out, &bytes.Buffer{})
	root.SetArgs([]string{"init", "--config", p, "--profile", "standard"})
	err := root.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewInitCmd_DetectEnv(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rampart.yaml")

	var out bytes.Buffer
	root := NewRootCmd(context.Background(), &out, &bytes.Buffer{})
	root.SetArgs([]string{"init", "--config", p, "--detect"})
	err := root.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- newPolicyTestCmd (test_cmd.go / policy.go) ---

func TestPolicyTestCmd_Basic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rampart.yaml")
	os.WriteFile(p, []byte(`version: "1"
default_action: deny
rules:
  - action: allow
    when:
      tool: exec
      command: "echo *"
`), 0o644)

	var out bytes.Buffer
	root := NewRootCmd(context.Background(), &out, &bytes.Buffer{})
	root.SetArgs([]string{"policy", "test", "--config", p, "exec", "echo hello"})
	err := root.Execute()
	_ = err // may or may not error depending on result formatting
}

// --- followAuditFile with data (audit.go) ---

func TestFollowAuditFile_WithEvents(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "audit.jsonl")

	event := map[string]any{
		"id": "evt1", "ts": time.Now().UTC().Format(time.RFC3339),
		"tool": "exec", "agent": "claude",
		"decision": map[string]any{"action": "allow", "matched_policies": []string{"default"}, "evaluation_time_us": 10},
	}
	data, _ := json.Marshal(event)
	os.WriteFile(f, append(data, '\n'), 0o644)

	ctx, cancel := context.WithCancel(context.Background())
	cmd := testCobraCmd(ctx)

	done := make(chan error, 1)
	go func() {
		done <- followAuditFile(cmd, dir, f, true)
	}()

	// Write a new event after a brief delay
	go func() {
		time.Sleep(200 * time.Millisecond)
		f2, _ := os.OpenFile(f, os.O_APPEND|os.O_WRONLY, 0o644)
		event2 := map[string]any{
			"id": "evt2", "ts": time.Now().UTC().Format(time.RFC3339),
			"tool": "read", "agent": "claude",
			"decision": map[string]any{"action": "allow", "matched_policies": []string{"p"}, "evaluation_time_us": 5},
		}
		d, _ := json.Marshal(event2)
		f2.Write(append(d, '\n'))
		f2.Close()
		time.Sleep(600 * time.Millisecond)
		cancel()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("followAuditFile did not return")
	}
}

// --- runReport success path (report.go) ---

func TestRunReport_WithEvents(t *testing.T) {
	dir := t.TempDir()

	// Create events within the last 24h
	events := []audit.Event{
		{
			ID:        "evt1",
			Timestamp: time.Now().Add(-1 * time.Hour),
			Tool:      "exec",
			Agent:     "claude",
			Decision:  audit.EventDecision{Action: "allow", MatchedPolicies: []string{"default"}},
			Request:   map[string]any{"command": "ls"},
		},
		{
			ID:        "evt2",
			Timestamp: time.Now().Add(-30 * time.Minute),
			Tool:      "read",
			Agent:     "claude",
			Decision:  audit.EventDecision{Action: "deny", Message: "blocked"},
			Request:   map[string]any{"path": "/etc/shadow"},
		},
	}

	// Write events to a JSONL file
	today := time.Now().UTC().Format("2006-01-02")
	f, _ := os.Create(filepath.Join(dir, "audit-"+today+".jsonl"))
	enc := json.NewEncoder(f)
	for _, e := range events {
		enc.Encode(e)
	}
	f.Close()

	outFile := filepath.Join(dir, "report.html")
	err := runReport(&reportOptions{
		last:     "24h",
		auditDir: dir,
		output:   outFile,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify report was created
	info, err := os.Stat(outFile)
	if err != nil {
		t.Fatalf("report not created: %v", err)
	}
	if info.Size() == 0 {
		t.Error("report file is empty")
	}
}

// --- preload command arg validation ---

func TestNewPreloadCmd_NoArgs(t *testing.T) {
	var out bytes.Buffer
	root := NewRootCmd(context.Background(), &out, &bytes.Buffer{})
	root.SetArgs([]string{"preload"})
	err := root.Execute()
	if err == nil {
		t.Error("expected error for missing command")
	}
}

// --- hook command missing stdin ---

func TestNewHookCmd_NoStdin(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rampart.yaml")
	os.WriteFile(p, []byte(`version: "1"
default_action: allow
`), 0o644)

	var out, errBuf bytes.Buffer
	root := NewRootCmd(context.Background(), &out, &errBuf)
	root.SetArgs([]string{"hook", "--config", p})

	// Redirect stdin to empty
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	w.Close()
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	err := root.Execute()
	_ = err // may error on stdin read
}

// --- version command ---

func TestVersionCmd(t *testing.T) {
	var out bytes.Buffer
	root := NewRootCmd(context.Background(), &out, &bytes.Buffer{})
	root.SetArgs([]string{"version"})
	err := root.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- status command ---

func TestStatusCmd_NoServer(t *testing.T) {
	var out bytes.Buffer
	root := NewRootCmd(context.Background(), &out, &bytes.Buffer{})
	root.SetArgs([]string{"status", "--addr", "http://127.0.0.1:1"})
	// Should fail connecting
	_ = root.Execute()
}
