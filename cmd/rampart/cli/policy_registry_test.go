package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyFetch_InstallsPolicyFromRegistry(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	policyContent := []byte("version: \"1\"\npolicies: []\n")
	sum := sha256.Sum256(policyContent)
	expectedSHA := hex.EncodeToString(sum[:])

	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/registry.json":
			_, _ = fmt.Fprintf(w, `{"version":"1","updated_at":"2026-01-01T00:00:00Z","policies":[{"name":"test-custom-policy","description":"Test policy","tags":["test"],"url":"%s/policies/test-custom-policy.yaml","sha256":"%s","version":"1.0.0","author":"Rampart"}]}`,
				serverURL, expectedSHA)
		case "/policies/test-custom-policy.yaml":
			_, _ = w.Write(policyContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL = server.URL // https://127.0.0.1:PORT

	oldManifestURL := defaultPolicyRegistryManifestURL
	oldClient := defaultPolicyRegistryHTTPClient
	defaultPolicyRegistryManifestURL = server.URL + "/registry.json"
	defaultPolicyRegistryHTTPClient = server.Client() // trusts the TLS test cert
	t.Cleanup(func() {
		defaultPolicyRegistryManifestURL = oldManifestURL
		defaultPolicyRegistryHTTPClient = oldClient
	})

	stdout, _, err := runCLI(t, "policy", "fetch", "test-custom-policy")
	require.NoError(t, err)
	assert.Contains(t, stdout, "Installed \"test-custom-policy\"")

	dest := filepath.Join(home, ".rampart", "policies", "test-custom-policy.yaml")
	data, readErr := os.ReadFile(dest)
	require.NoError(t, readErr)
	assert.Equal(t, string(policyContent), string(data))
}

func TestVerifyPolicySHA256(t *testing.T) {
	content := []byte("policy-body")
	sum := sha256.Sum256(content)
	expected := hex.EncodeToString(sum[:])

	require.NoError(t, verifyPolicySHA256(content, expected, "custom"))

	err := verifyPolicySHA256(content, "deadbeef", "custom")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sha256 mismatch")
}

func TestPolicyFetch_SHA256Mismatch(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	policyContent := []byte("version: \"1\"\npolicies: []\n")

	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/registry.json":
			_, _ = fmt.Fprintf(w, `{"version":"1","updated_at":"2026-01-01T00:00:00Z","policies":[{"name":"test-bad-hash","description":"Test policy","tags":["test"],"url":"%s/policies/test-bad-hash.yaml","sha256":"%s","version":"1.0.0","author":"Rampart"}]}`,
				serverURL, "deadbeef")
		case "/policies/test-bad-hash.yaml":
			_, _ = w.Write(policyContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	oldManifestURL := defaultPolicyRegistryManifestURL
	oldClient := defaultPolicyRegistryHTTPClient
	defaultPolicyRegistryManifestURL = server.URL + "/registry.json"
	defaultPolicyRegistryHTTPClient = server.Client()
	t.Cleanup(func() {
		defaultPolicyRegistryManifestURL = oldManifestURL
		defaultPolicyRegistryHTTPClient = oldClient
	})

	_, _, err := runCLI(t, "policy", "fetch", "test-bad-hash")
	require.Error(t, err)
	// With remote-first download, a SHA256 mismatch falls through to embedded
	// (which doesn't exist), producing "unable to download or find embedded copy".
	assert.Contains(t, err.Error(), "unable to download or find embedded copy")

	dest := filepath.Join(home, ".rampart", "policies", "test-bad-hash.yaml")
	_, statErr := os.Stat(dest)
	assert.True(t, os.IsNotExist(statErr))
}

func TestPolicyList_UsesCacheAndRefresh(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	var manifestHits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/registry.json" {
			http.NotFound(w, r)
			return
		}
		manifestHits.Add(1)
		_, _ = fmt.Fprint(w, `{"version":"1","updated_at":"2026-01-01T00:00:00Z","policies":[{"name":"mcp-server","description":"MCP profile","tags":["mcp"],"url":"https://example.com/mcp-server.yaml","sha256":"abc123","version":"1.0.0","author":"Rampart"}]}`)
	}))
	defer server.Close()

	oldManifestURL := defaultPolicyRegistryManifestURL
	oldClient := defaultPolicyRegistryHTTPClient
	defaultPolicyRegistryManifestURL = server.URL + "/registry.json"
	defaultPolicyRegistryHTTPClient = server.Client()
	t.Cleanup(func() {
		defaultPolicyRegistryManifestURL = oldManifestURL
		defaultPolicyRegistryHTTPClient = oldClient
	})

	stdout1, _, err := runCLI(t, "policy", "list")
	require.NoError(t, err)
	assert.Contains(t, stdout1, "mcp-server")

	stdout2, _, err := runCLI(t, "policy", "list")
	require.NoError(t, err)
	assert.Contains(t, stdout2, "mcp-server")

	_, _, err = runCLI(t, "policy", "list", "--refresh")
	require.NoError(t, err)

	assert.Equal(t, int64(2), manifestHits.Load(), "expected first list + refresh to hit server")

	cachePath := filepath.Join(home, ".rampart", policyRegistryCacheFileName)
	_, statErr := os.Stat(cachePath)
	require.NoError(t, statErr)
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

func TestPolicyFetch_RejectsPathTraversalName(t *testing.T) {
	// A compromised registry manifest could contain a name like "../../etc/cron.d/backdoor".
	// The sanitizePolicyName guard must reject this before any file is written.
	//
	// We test sanitizePolicyName directly since manifest validation would reject
	// these names before they could ever reach the fetch path.
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
