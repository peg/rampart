package policy

import (
	"path/filepath"
	"testing"
)

func TestAddUserOverrideAllow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "user-overrides.yaml")

	pattern, err := AddUserOverrideAllow(path, "exec", "curl -fsS http://100.94.29.8:8989/api/v3/system/status", "User allowed (always)")
	if err != nil {
		t.Fatalf("AddUserOverrideAllow: %v", err)
	}
	if pattern == "" {
		t.Fatal("expected non-empty pattern")
	}

	p, err := LoadUserOverridesPolicy(path)
	if err != nil {
		t.Fatalf("LoadUserOverridesPolicy: %v", err)
	}
	if len(p.Policies) != 1 {
		t.Fatalf("expected 1 override policy, got %d", len(p.Policies))
	}
	if p.Policies[0].Rules[0].Action != "allow" {
		t.Fatalf("expected allow action, got %q", p.Policies[0].Rules[0].Action)
	}
	if len(p.Policies[0].Rules[0].When.CommandMatches) != 1 {
		t.Fatalf("expected one command_matches pattern")
	}
}
