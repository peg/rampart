package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/peg/rampart/internal/audit"
	"github.com/spf13/cobra"
)

// --- parseSinceDuration (audit_helpers.go) ---

func TestParseSinceDuration(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
		desc    string
	}{
		{"", false, "empty"},
		{"1h", false, "1h"},
		{"2d", false, "2 days"},
		{"1d12h", false, "1 day 12 hours"},
		{"3d", false, "3 days"},
		{"d", true, "bare d"},
		{"xd", true, "invalid day value"},
		{"notaduration", true, "invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			_, err := parseSinceDuration(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSinceDuration(%q) err=%v, wantErr=%v", tt.input, err, tt.wantErr)
			}
		})
	}
}

// --- matchesAuditFilters (audit_helpers.go) ---

func TestMatchesAuditFilters(t *testing.T) {
	evt := audit.Event{Tool: "exec", Agent: "claude", Decision: audit.EventDecision{Action: "allow"}}
	tests := []struct {
		tool, agent, decision string
		want                  bool
	}{
		{"", "", "", true},
		{"exec", "", "", true},
		{"read", "", "", false},
		{"", "claude", "", true},
		{"", "other", "", false},
		{"", "", "allow", true},
		{"", "", "deny", false},
		{"exec", "claude", "allow", true},
	}
	for _, tt := range tests {
		if got := matchesAuditFilters(evt, tt.tool, tt.agent, tt.decision); got != tt.want {
			t.Errorf("matchesAuditFilters(tool=%q,agent=%q,dec=%q) = %v, want %v", tt.tool, tt.agent, tt.decision, got, tt.want)
		}
	}
}

// --- eventMatchesQuery (audit_helpers.go) ---

func TestEventMatchesQuery(t *testing.T) {
	evt := audit.Event{
		Tool:     "exec",
		Agent:    "claude",
		Decision: audit.EventDecision{Action: "allow", Message: "policy matched"},
		Request:  map[string]any{"command": "ls -la"},
	}
	tests := []struct {
		query string
		want  bool
	}{
		{"", true},
		{"exec", true},
		{"claude", true},
		{"policy", true},
		{"ls", true},
		{"nonexistent", false},
	}
	for _, tt := range tests {
		if got := eventMatchesQuery(evt, tt.query); got != tt.want {
			t.Errorf("eventMatchesQuery(query=%q) = %v, want %v", tt.query, got, tt.want)
		}
	}
}

// --- extractPrimaryRequestValue (audit_helpers.go) ---

func TestExtractPrimaryRequestValue(t *testing.T) {
	tests := []struct {
		name string
		req  map[string]any
		want string
	}{
		{"command", map[string]any{"command": "ls"}, "ls"},
		{"path", map[string]any{"path": "/etc/passwd"}, "/etc/passwd"},
		{"file_path", map[string]any{"file_path": "/tmp/x"}, "/tmp/x"},
		{"empty", map[string]any{}, ""},
		{"nil", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPrimaryRequestValue(tt.req)
			if got != tt.want {
				t.Errorf("extractPrimaryRequestValue() = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- createShellShim (wrap.go) ---

func TestCreateShellShim_Coverage(t *testing.T) {
	path, err := createShellShim("http://localhost:8080", "tok123", "enforce", "/bin/bash")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer os.Remove(path)
	defer os.Remove(path + ".tok")

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat shim: %v", err)
	}
	if info.Size() == 0 {
		t.Error("shim file is empty")
	}

	// Verify token file permissions (Unix only — Windows doesn't have Unix-style perms)
	if runtime.GOOS != "windows" {
		tokInfo, err := os.Stat(path + ".tok")
		if err != nil {
			t.Fatalf("stat token file: %v", err)
		}
		if tokInfo.Mode().Perm() != 0o600 {
			t.Errorf("token file perms = %o, want 600", tokInfo.Mode().Perm())
		}
	}
}

// --- formatDenyMessage (color.go) ---

func TestFormatDenyMessage(t *testing.T) {
	msg := formatDenyMessage("rm -rf /", "too dangerous", nil)
	if msg == "" {
		t.Error("expected non-empty message")
	}
}

// --- verifyAnchors (audit_helpers.go) ---

func TestVerifyAnchors_NoAnchors(t *testing.T) {
	dir := t.TempDir()
	err := verifyAnchorsWithSince(dir, map[string]string{}, true, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- filterEventsBySince (audit_helpers.go) ---

func TestFilterEventsBySince(t *testing.T) {
	t.Run("empty since", func(t *testing.T) {
		events := []audit.Event{{Tool: "exec"}}
		filtered, label, err := filterEventsBySince(events, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if label != "all time" {
			t.Errorf("expected 'all time', got %q", label)
		}
		if len(filtered) != 1 {
			t.Errorf("expected 1 event, got %d", len(filtered))
		}
	})

	t.Run("invalid duration", func(t *testing.T) {
		_, _, err := filterEventsBySince(nil, "invalid")
		if err == nil {
			t.Error("expected error for invalid duration")
		}
	})
}

// --- newPolicyLintCmd (lint.go) via cobra execution ---

func TestNewPolicyLintCmd_FileNotFound(t *testing.T) {
	cmd := newPolicyLintCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"/nonexistent/policy.yaml"})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestNewPolicyLintCmd_ValidFile(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)
	p := filepath.Join(dir, "policy.yaml")
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
	cmd := newPolicyLintCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{p})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(out.String()), p+": no issues found"; got != want {
		t.Fatalf("lint output = %q, want %q", got, want)
	}
}

// --- newLogCmd paths (log.go) ---

func TestNewLogCmd(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)
	cmd := &cobra.Command{Use: "root"}
	logCmd := newLogCmd(&rootOptions{})
	cmd.AddCommand(logCmd)

	// Test with empty audit dir
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"log", "--audit-dir", dir})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "No events found." {
		t.Fatalf("empty log output = %q", got)
	}
}

// --- doctorVersionCheck (doctor.go) ---

func TestDoctorVersionCheck(t *testing.T) {
	var buf bytes.Buffer
	// With dev build version, should return 0 immediately
	issues := doctorVersionCheck(&buf, false, nil)
	if issues < 0 {
		t.Errorf("unexpected negative issues: %d", issues)
	}
}

// --- doctorHooks (doctor.go) ---

func TestDoctorHooks(t *testing.T) {
	var results []checkResult
	emit := func(name, status, msg string) {
		results = append(results, checkResult{Name: name, Status: status, Message: msg})
	}
	// Should not panic even if no hooks configured
	issues := doctorHooks(emit)
	if issues < 0 {
		t.Errorf("unexpected negative issues: %d", issues)
	}
}
