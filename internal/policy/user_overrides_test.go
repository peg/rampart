package policy

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddUserOverrideAllow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "user-overrides.yaml")

	pattern, err := AddUserOverrideAllow(path, "exec", "curl -fsS http://192.0.2.10:8989/api/v3/system/status", "User allowed (always)")
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

func TestAddUserOverrideAllowPreservesExplicitGlob(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user-overrides.yaml")
	pattern, err := AddUserOverrideAllow(path, "exec", "npm install *", "")
	require.NoError(t, err)
	assert.Equal(t, "npm install *", pattern)
}

func TestAddUserOverrideAllowStoresFileToolAsPathMatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user-overrides.yaml")
	pattern, err := AddUserOverrideAllow(path, "write", "/tmp/output-*.txt", "")
	require.NoError(t, err)
	assert.Equal(t, "/tmp/output-*.txt", pattern)

	overrides, err := LoadUserOverridesPolicy(path)
	require.NoError(t, err)
	require.Len(t, overrides.Policies, 1)
	when := overrides.Policies[0].Rules[0].When
	assert.Equal(t, []string{"/tmp/output-*.txt"}, when.PathMatches)
	assert.Empty(t, when.CommandMatches)
}

func TestAddUserOverrideAllowRejectsEmptyAuthority(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user-overrides.yaml")
	_, err := AddUserOverrideAllow(path, " ", "ls", "")
	assert.Error(t, err)
	_, err = AddUserOverrideAllow(path, "exec", "   ", "")
	assert.Error(t, err)
	_, err = AddUserOverrideAllow(path, "mcp.tool", "value", "")
	assert.Error(t, err)
}
