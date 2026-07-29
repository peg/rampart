package policy

import (
	"os"
	"path/filepath"
	"strings"
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

func TestEnsureUserOverrideAllowReportsDuplicate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user-overrides.yaml")
	first, err := EnsureUserOverrideAllow(path, "exec", "echo safe", "")
	require.NoError(t, err)
	assert.True(t, first.Created)

	second, err := EnsureUserOverrideAllow(path, "exec", "echo safe", "")
	require.NoError(t, err)
	assert.False(t, second.Created)
	assert.Equal(t, first.Name, second.Name)
}

func TestEnsureUserOverrideAllowRejectsOversizedPatternBeforeWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user-overrides.yaml")
	_, err := EnsureUserOverrideAllow(path, "exec", strings.Repeat("a", MaxGlobPatternLen+1), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid allow pattern")
	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr))
}

func TestLoadUserOverridesPolicyAcceptsLegacyScalarTool(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user-overrides.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`policies:
  - name: legacy
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["echo safe"]
`), 0o600))

	overrides, err := LoadUserOverridesPolicy(path)
	require.NoError(t, err)
	require.Len(t, overrides.Policies, 1)
	assert.Equal(t, stringOrSlice{"exec"}, overrides.Policies[0].Match.Tool)
}
