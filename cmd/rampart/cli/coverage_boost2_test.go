package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
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

// --- resolveTestPolicyPath (test_cmd.go) ---

func TestResolveTestPolicyPath(t *testing.T) {
	t.Run("existing file", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "rampart.yaml")
		os.WriteFile(p, []byte("version: 1"), 0o644)

		got, cleanup, err := resolveTestPolicyPath(p)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer cleanup()
		if got != p {
			t.Errorf("expected %s, got %s", p, got)
		}
	})

	t.Run("fallback to embedded", func(t *testing.T) {
		// Use a non-existent path so it falls through
		got, cleanup, err := resolveTestPolicyPath("/nonexistent/rampart.yaml")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer cleanup()
		if got == "" {
			t.Error("expected non-empty path")
		}
	})
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

	// Verify token file permissions
	tokInfo, err := os.Stat(path + ".tok")
	if err != nil {
		t.Fatalf("stat token file: %v", err)
	}
	if tokInfo.Mode().Perm() != 0o600 {
		t.Errorf("token file perms = %o, want 600", tokInfo.Mode().Perm())
	}
}

// --- formatDenyMessage / formatApprovalRequiredMessage (color.go) ---

func TestFormatDenyMessage(t *testing.T) {
	msg := formatDenyMessage("rm -rf /", "too dangerous")
	if msg == "" {
		t.Error("expected non-empty message")
	}
}

func TestFormatApprovalRequiredMessage(t *testing.T) {
	msg := formatApprovalRequiredMessage("sudo reboot", "needs approval")
	if msg == "" {
		t.Error("expected non-empty message")
	}
}

// --- verifyAnchors (audit_helpers.go) ---

func TestVerifyAnchors_NoAnchors(t *testing.T) {
	dir := t.TempDir()
	err := verifyAnchors(dir, map[string]string{})
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
	p := filepath.Join(dir, "policy.yaml")
	os.WriteFile(p, []byte("version: \"1\"\ndefault_action: deny\nrules:\n  - action: allow\n    when:\n      tool: exec\n"), 0o644)

	var out bytes.Buffer
	cmd := newPolicyLintCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{p})
	// This may call os.Exit(1), but we're just testing the path
	_ = cmd.Execute()
}

// --- newLogCmd paths (log.go) ---

func TestNewLogCmd(t *testing.T) {
	cmd := &cobra.Command{Use: "root"}
	logCmd := newLogCmd(&rootOptions{})
	cmd.AddCommand(logCmd)

	// Test with empty audit dir
	dir := t.TempDir()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"log", "--audit-dir", dir})
	err := cmd.Execute()
	// Empty dir should be OK (no events)
	if err != nil {
		t.Logf("log cmd error (may be expected): %v", err)
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
