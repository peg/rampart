package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/peg/rampart/internal/audit"
)

// --- newInitCmd (init.go) ---

func TestNewInitCmd_AlreadyExists(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)
	p := filepath.Join(dir, "rampart.yaml")
	os.WriteFile(p, []byte("existing"), 0o644)

	stdout := &bytes.Buffer{}
	root := NewRootCmd(context.Background(), stdout, &bytes.Buffer{})
	root.SetArgs([]string{"init", "--config", p})
	err := root.Execute()
	// Should succeed now - init creates policies even if config exists
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	// Config should be unchanged
	data, _ := os.ReadFile(p)
	if string(data) != "existing" {
		t.Errorf("config was modified, expected 'existing' got %q", string(data))
	}
}

func TestNewInitCmd_WithProfile(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)
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
	testSetHome(t, dir)
	p := filepath.Join(dir, "rampart.yaml")

	var out bytes.Buffer
	root := NewRootCmd(context.Background(), &out, &bytes.Buffer{})
	root.SetArgs([]string{"init", "--config", p, "--detect"})
	err := root.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- policy test command alias ---

func TestPolicyTestCmd_Basic(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)
	p := filepath.Join(dir, "rampart.yaml")
	if err := os.WriteFile(p, []byte(`version: "1"
default_action: deny
policies:
  - name: allow-echo
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["echo *"]
`), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	root := NewRootCmd(context.Background(), &out, &bytes.Buffer{})
	root.SetArgs([]string{"policy", "test", "--config", p, "--tool", "exec", "--json", "echo hello"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	var got bareCmdJSONResult
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("decode decision: %v; output: %s", err, &out)
	}
	if got.Command != "echo hello" || got.Action != "allow" || len(got.MatchedPolicies) != 1 || got.MatchedPolicies[0] != "allow-echo" {
		t.Fatalf("unexpected alias decision: %+v", got)
	}
}

// --- followAuditFile with data (audit.go) ---

func TestFollowAuditFile_WithEvents(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "audit.jsonl")
		file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		enc := json.NewEncoder(file)
		event := audit.Event{
			ID: "existing", Timestamp: time.Now().UTC(), Tool: "exec",
			Request:  map[string]any{"command": "echo existing"},
			Decision: audit.EventDecision{Action: "allow"},
		}
		if err := enc.Encode(event); err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cmd := testCobraCmd(ctx)
		var out bytes.Buffer
		cmd.SetOut(&out)
		done := make(chan error, 1)
		go func() { done <- followAuditFile(cmd, dir, path, true) }()
		// Wait until the follower has captured the initial offset and is polling.
		synctest.Wait()
		event.ID = "appended"
		event.Request = map[string]any{"command": "echo appended"}
		if err := enc.Encode(event); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * tailPollInterval)
		synctest.Wait()
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("follow failed: %v", err)
		}
		if got := out.String(); strings.Count(got, "echo appended") != 1 || strings.Contains(got, "echo existing") {
			t.Fatalf("expected only the appended event once, got %q", got)
		}
	})
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
	testSetHome(t, dir)
	t.Chdir(dir)
	t.Setenv("RAMPART_TOKEN", "")
	p := filepath.Join(dir, "rampart.yaml")
	if err := os.WriteFile(p, []byte(`version: "1"
default_action: allow
`), 0o600); err != nil {
		t.Fatal(err)
	}
	auditDir := filepath.Join(dir, "audit")

	var out, errBuf bytes.Buffer
	root := NewRootCmd(context.Background(), &out, &errBuf)
	root.SetIn(strings.NewReader(""))
	root.SetArgs([]string{"hook", "--config", p, "--mode", "enforce", "--audit-dir", auditDir, "--serve-url", "http://127.0.0.1:1"})
	if err := root.Execute(); err != nil {
		t.Fatalf("clean EOF returned an error: %v", err)
	}
	var got hookOutput
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("decode clean EOF response: %v; output: %s", err, &out)
	}
	if got.Decision != "" || got.HookSpecificOutput == nil || got.HookSpecificOutput.HookEventName != "PreToolUse" || got.HookSpecificOutput.PermissionDecision != "allow" {
		t.Fatalf("unexpected clean EOF response: %+v", got)
	}
	if errBuf.Len() != 0 {
		t.Fatalf("clean EOF wrote stderr: %s", &errBuf)
	}
	files, err := listAuditFiles(auditDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		events, err := readAuditEvents(file)
		if err != nil {
			t.Fatal(err)
		}
		if len(events) != 0 {
			t.Fatalf("clean EOF must not record a policy decision, got %d events", len(events))
		}
	}
}
