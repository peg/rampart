package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyShow_BuiltIn(t *testing.T) {
	stdout, _, err := runCLI(t, "policy", "show", "standard")
	require.NoError(t, err)
	assert.Contains(t, stdout, "version:")
}

func TestPolicyShow_UnknownPolicy(t *testing.T) {
	_, _, err := runCLI(t, "policy", "show", "nonexistent-policy")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a built-in profile")
}

func TestPolicyList_ShowsInstalledState(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	policyDir := filepath.Join(home, ".rampart", "policies")
	require.NoError(t, os.MkdirAll(policyDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(policyDir, "standard.yaml"), []byte("version: \"1\"\n"), 0o644))

	// Default format: backward-compatible NAME | DESCRIPTION | TAGS
	stdout, _, err := runCLI(t, "policy", "list")
	require.NoError(t, err)
	assert.Contains(t, stdout, "NAME")
	assert.Contains(t, stdout, "DESCRIPTION")
	assert.Contains(t, stdout, "TAGS")

	// Extended format: NAME | DESCRIPTION | SOURCE | INSTALLED
	stdout2, _, err := runCLI(t, "policy", "list", "--extended")
	require.NoError(t, err)
	assert.Contains(t, stdout2, "built-in")
	assert.Contains(t, stdout2, "INSTALLED")
	assert.Contains(t, stdout2, "✓")
}

func TestPolicyList_BuiltInDescriptions(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	stdout, _, err := runCLI(t, "policy", "list")
	require.NoError(t, err)

	// Each built-in should have its differentiated description, not generic "Built-in profile".
	assert.Contains(t, stdout, "Balanced default policy")
	assert.Contains(t, stdout, "Maximum restriction")
	assert.Contains(t, stdout, "Permissive")
}

func TestPolicyRemove_RefusesBuiltIn(t *testing.T) {
	_, _, err := runCLI(t, "policy", "remove", "standard")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "built-in profile")
}

func TestPolicyRemove_RemovesInstalledPolicy(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	path := filepath.Join(home, ".rampart", "policies", "custom.yaml")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte("version: \"1\"\n"), 0o644))

	stdout, _, err := runCLI(t, "policy", "remove", "custom")
	require.NoError(t, err)
	assert.Contains(t, stdout, "Removed")
	if strings.Contains(stdout, "standard") {
		t.Fatalf("unexpected output: %s", stdout)
	}

	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr))
}

func TestSanitizePolicyName_RejectsPathTraversal(t *testing.T) {
	// sanitizePolicyName must reject names that would escape ~/.rampart/policies/.
	cases := []struct {
		name    string
		wantErr bool
	}{
		{"research-agent", false},
		{"my-policy", false},
		{"../../etc/shadow", true},
		{"../evil", true},
		{"foo/bar", true},
		{"..", true},
		{".", true},
		{"", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := sanitizePolicyName(tc.name)
			if tc.wantErr {
				require.Error(t, err, "expected error for name %q", tc.name)
			} else {
				require.NoError(t, err, "unexpected error for name %q", tc.name)
			}
		})
	}
}
