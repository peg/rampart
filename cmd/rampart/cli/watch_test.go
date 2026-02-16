package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExpandHome(t *testing.T) {
	home, _ := os.UserHomeDir()
	tests := []struct {
		input string
		want  string
		err   bool
	}{
		{"~/foo", filepath.Join(home, "foo"), false},
		{"~", home, false},
		{"/absolute/path", "/absolute/path", false},
		{"relative/path", "relative/path", false},
		{"", "", true},
		{"  ", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := expandHome(tt.input)
			if (err != nil) != tt.err {
				t.Fatalf("expandHome(%q) err=%v, wantErr=%v", tt.input, err, tt.err)
			}
			if !tt.err && got != tt.want {
				t.Errorf("expandHome(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestLatestAuditFile_NoFiles(t *testing.T) {
	dir := t.TempDir()
	got, err := latestAuditFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	today := time.Now().UTC().Format("2006-01-02")
	if !filepath.IsAbs(got) || !contains(got, today) {
		t.Errorf("latestAuditFile empty dir = %q", got)
	}
}

func TestLatestAuditFile_WithFiles(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "audit-hook-2026-01-01.jsonl")
	f2 := filepath.Join(dir, "audit-hook-2026-01-02.jsonl")
	os.WriteFile(f1, []byte("old\n"), 0o644)
	time.Sleep(10 * time.Millisecond)
	os.WriteFile(f2, []byte("new\n"), 0o644)

	got, err := latestAuditFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != f2 {
		t.Errorf("latestAuditFile = %q, want %q", got, f2)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
