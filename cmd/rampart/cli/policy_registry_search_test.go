package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peg/rampart/internal/detect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// rampart policy search
// ---------------------------------------------------------------------------

func TestPolicySearch_MatchesByName(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	srv := registryTestServer(t, testManifest())
	defer srv.Close()
	patchRegistryURL(t, srv)

	stdout, _, err := runCLI(t, "policy", "search", "kubernetes")
	require.NoError(t, err)
	assert.Contains(t, stdout, "kubernetes")
	assert.Contains(t, stdout, "87%")
}

func TestPolicySearch_MatchesByTag(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	srv := registryTestServer(t, testManifest())
	defer srv.Close()
	patchRegistryURL(t, srv)

	stdout, _, err := runCLI(t, "policy", "search", "cluster", "--tag", "kubernetes")
	require.NoError(t, err)
	assert.Contains(t, stdout, "kubernetes")
}

func TestPolicySearch_NoResults(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	srv := registryTestServer(t, testManifest())
	defer srv.Close()
	patchRegistryURL(t, srv)

	stdout, _, err := runCLI(t, "policy", "search", "nonexistent-foobar-xyz")
	require.NoError(t, err)
	assert.Contains(t, stdout, "No policies found")
}

func TestPolicySearch_MinScore(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	srv := registryTestServer(t, testManifest())
	defer srv.Close()
	patchRegistryURL(t, srv)

	stdout, _, err := runCLI(t, "policy", "search", "k", "--min-score", "90")
	require.NoError(t, err)
	// kubernetes has bench_score=87, should not match with min-score=90
	assert.NotContains(t, stdout, "kubernetes")
}

func TestPolicySearch_JSON(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	srv := registryTestServer(t, testManifest())
	defer srv.Close()
	patchRegistryURL(t, srv)

	stdout, _, err := runCLI(t, "policy", "search", "kubernetes", "--json")
	require.NoError(t, err)

	var results []policyRegistryEntry
	require.NoError(t, json.Unmarshal([]byte(stdout), &results))
	assert.Len(t, results, 1)
	assert.Equal(t, "kubernetes", results[0].Name)
}

// ---------------------------------------------------------------------------
// rampart policy show
// ---------------------------------------------------------------------------

func TestPolicyShow_PrintsYAML(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	policyContent := []byte("version: \"1\"\npolicies: []\n")
	sum := sha256.Sum256(policyContent)
	expectedSHA := hex.EncodeToString(sum[:])

	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/registry.json":
			_, _ = fmt.Fprintf(w, `{"version":"1","updated_at":"2026-01-01T00:00:00Z","policies":[{"name":"test-policy","description":"Test","tags":["test"],"url":"%s/policies/test-policy.yaml","sha256":"%s","version":"1.0.0","author":"test"}]}`,
				serverURL, expectedSHA)
		case "/policies/test-policy.yaml":
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

	stdout, _, err := runCLI(t, "policy", "show", "test-policy")
	require.NoError(t, err)
	assert.Contains(t, stdout, "version:")
	assert.Contains(t, stdout, "policies:")
}

func TestPolicyShow_UnknownPolicy(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	srv := registryTestServer(t, testManifest())
	defer srv.Close()
	patchRegistryURL(t, srv)

	_, _, err := runCLI(t, "policy", "show", "nonexistent-policy")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestPolicyShow_BuiltIn(t *testing.T) {
	stdout, _, err := runCLI(t, "policy", "show", "standard")
	require.NoError(t, err)
	assert.Contains(t, stdout, "version:")
}

// ---------------------------------------------------------------------------
// rampart policy list (installed state)
// ---------------------------------------------------------------------------

func TestPolicyList_ShowsInstalledState(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	// Create an installed policy.
	policyDir := filepath.Join(home, ".rampart", "policies")
	require.NoError(t, os.MkdirAll(policyDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(policyDir, "standard.yaml"), []byte("version: \"1\"\n"), 0o644))

	srv := registryTestServer(t, testManifest())
	defer srv.Close()
	patchRegistryURL(t, srv)

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
	assert.Contains(t, stdout2, "community")
	assert.Contains(t, stdout2, "INSTALLED")
	assert.Contains(t, stdout2, "✓")
}

// ---------------------------------------------------------------------------
// rampart policy install (alias for fetch)
// ---------------------------------------------------------------------------

func TestPolicyInstall_IsAlias(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	policyContent := []byte("version: \"1\"\npolicies: []\n")
	sum := sha256.Sum256(policyContent)
	expectedSHA := hex.EncodeToString(sum[:])

	var serverURL string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/registry.json":
			_, _ = fmt.Fprintf(w, `{"version":"1","updated_at":"2026-01-01T00:00:00Z","policies":[{"name":"test-install","description":"Test","tags":["test"],"url":"%s/policies/test-install.yaml","sha256":"%s","version":"1.0.0","author":"test"}]}`,
				serverURL, expectedSHA)
		case "/policies/test-install.yaml":
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

	stdout, _, err := runCLI(t, "policy", "install", "test-install")
	require.NoError(t, err)
	assert.Contains(t, stdout, "Installed")

	dest := filepath.Join(home, ".rampart", "policies", "test-install.yaml")
	_, statErr := os.Stat(dest)
	assert.NoError(t, statErr)
}

// ---------------------------------------------------------------------------
// suggestPolicies
// ---------------------------------------------------------------------------

func TestSuggestPolicies_MapsDetectedTools(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".rampart", "policies"), 0o755))

	result := &detect.DetectResult{
		HasKubectl:   true,
		HasDocker:    true,
		HasTerraform: false,
	}
	manifest := &policyRegistryManifest{
		Version: "1",
		Policies: []policyRegistryEntry{
			{Name: "kubernetes", Description: "K8s", Tags: []string{"k8s"}, BenchScore: 87},
			{Name: "docker", Description: "Docker", Tags: []string{"docker"}, BenchScore: 75},
			{Name: "terraform", Description: "TF", Tags: []string{"tf"}, BenchScore: 79},
		},
	}

	suggestions := suggestPolicies(result, manifest)
	assert.Len(t, suggestions, 2)

	names := make([]string, len(suggestions))
	for i, s := range suggestions {
		names[i] = s.PolicyName
	}
	assert.Contains(t, names, "kubernetes")
	assert.Contains(t, names, "docker")
	assert.NotContains(t, names, "terraform")
}

func TestSuggestPolicies_ExcludesInstalled(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	policyDir := filepath.Join(home, ".rampart", "policies")
	require.NoError(t, os.MkdirAll(policyDir, 0o755))
	// Pre-install kubernetes
	require.NoError(t, os.WriteFile(filepath.Join(policyDir, "kubernetes.yaml"), []byte("v: 1"), 0o644))

	result := &detect.DetectResult{HasKubectl: true, HasDocker: true}
	manifest := &policyRegistryManifest{
		Version: "1",
		Policies: []policyRegistryEntry{
			{Name: "kubernetes", Description: "K8s", Tags: []string{"k8s"}},
			{Name: "docker", Description: "Docker", Tags: []string{"docker"}},
		},
	}

	suggestions := suggestPolicies(result, manifest)
	assert.Len(t, suggestions, 1)
	assert.Equal(t, "docker", suggestions[0].PolicyName)
}

// ---------------------------------------------------------------------------
// entryMatchesQuery / entryHasTag
// ---------------------------------------------------------------------------

func TestEntryMatchesQuery(t *testing.T) {
	entry := policyRegistryEntry{
		Name:        "kubernetes",
		Description: "Blocks destructive cluster ops",
		Tags:        []string{"k8s", "helm"},
	}

	assert.True(t, entryMatchesQuery(entry, "kube"))
	assert.True(t, entryMatchesQuery(entry, "cluster"))
	assert.True(t, entryMatchesQuery(entry, "helm"))
	assert.True(t, entryMatchesQuery(entry, "KUBE"))
	assert.False(t, entryMatchesQuery(entry, "terraform"))
}

func TestEntryHasTag(t *testing.T) {
	entry := policyRegistryEntry{Tags: []string{"k8s", "helm", "cluster"}}

	assert.True(t, entryHasTag(entry, "k8s"))
	assert.True(t, entryHasTag(entry, "K8S"))
	assert.False(t, entryHasTag(entry, "docker"))
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func testManifest() string {
	return `{
		"version": "1",
		"updated_at": "2026-01-01T00:00:00Z",
		"policies": [
			{
				"name": "kubernetes",
				"description": "Blocks destructive cluster ops",
				"tags": ["kubernetes", "helm", "cluster"],
				"url": "https://example.com/kubernetes.yaml",
				"sha256": "abc123",
				"version": "1.0.0",
				"author": "@rampart-team",
				"bench_score": 87
			},
			{
				"name": "docker",
				"description": "Container guardrails",
				"tags": ["docker", "containers"],
				"url": "https://example.com/docker.yaml",
				"sha256": "def456",
				"version": "1.0.0",
				"author": "@rampart-team",
				"bench_score": 75
			}
		]
	}`
}

func registryTestServer(t *testing.T, manifestJSON string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/registry.json" {
			_, _ = fmt.Fprint(w, manifestJSON)
			return
		}
		http.NotFound(w, r)
	}))
}

func patchRegistryURL(t *testing.T, srv *httptest.Server) {
	t.Helper()
	oldManifestURL := defaultPolicyRegistryManifestURL
	oldClient := defaultPolicyRegistryHTTPClient
	defaultPolicyRegistryManifestURL = srv.URL + "/registry.json"
	defaultPolicyRegistryHTTPClient = srv.Client()
	t.Cleanup(func() {
		defaultPolicyRegistryManifestURL = oldManifestURL
		defaultPolicyRegistryHTTPClient = oldClient
	})
}

func TestDescribeSuggestions(t *testing.T) {
	suggestions := []policySuggestion{
		{Binary: "kubectl", PolicyName: "kubernetes"},
		{Binary: "docker", PolicyName: "docker"},
	}
	desc := describeSuggestions(suggestions)
	assert.Contains(t, desc, "kubernetes")
	assert.Contains(t, desc, "docker")

	empty := describeSuggestions(nil)
	assert.Equal(t, "", empty)
}

func TestPrintPolicySuggestions(t *testing.T) {
	var buf strings.Builder
	suggestions := []policySuggestion{
		{
			Binary:     "kubectl",
			PolicyName: "kubernetes",
			Entry:      policyRegistryEntry{BenchScore: 87},
		},
	}
	printPolicySuggestions(&buf, suggestions)
	out := buf.String()
	assert.Contains(t, out, "kubectl")
	assert.Contains(t, out, "rampart policy fetch kubernetes")
	assert.Contains(t, out, "87%")

	// Empty suggestions should produce no output.
	var buf2 strings.Builder
	printPolicySuggestions(&buf2, nil)
	assert.Equal(t, "", buf2.String())
}

// ---------------------------------------------------------------------------
// --min-score bounds validation
// ---------------------------------------------------------------------------

func TestPolicySearch_MinScoreOutOfBounds(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	srv := registryTestServer(t, testManifest())
	defer srv.Close()
	patchRegistryURL(t, srv)

	_, _, err := runCLI(t, "policy", "search", "k", "--min-score", "101")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--min-score must be between 0 and 100")

	_, _, err = runCLI(t, "policy", "search", "k", "--min-score", "-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--min-score must be between 0 and 100")
}

// ---------------------------------------------------------------------------
// RAMPART_REGISTRY_URL / RAMPART_DEV env override
// ---------------------------------------------------------------------------

func TestRegistryClient_EnvOverrideIgnoredWithoutDev(t *testing.T) {
	// Without RAMPART_DEV=1, the override is silently ignored.
	t.Setenv("RAMPART_REGISTRY_URL", "https://custom.example.com/registry.json")
	// Do NOT set RAMPART_DEV — override should be ignored.

	client := newPolicyRegistryClient()
	assert.Equal(t, defaultPolicyRegistryManifestURL, client.manifestURL,
		"RAMPART_REGISTRY_URL should be ignored without RAMPART_DEV=1")
}

func TestRegistryClient_EnvOverrideHTTPS(t *testing.T) {
	// With RAMPART_DEV=1 and HTTPS URL, override should be accepted.
	t.Setenv("RAMPART_DEV", "1")
	t.Setenv("RAMPART_REGISTRY_URL", "https://custom.example.com/registry.json")

	client := newPolicyRegistryClient()
	assert.Equal(t, "https://custom.example.com/registry.json", client.manifestURL,
		"HTTPS override should be accepted with RAMPART_DEV=1")
}

func TestRegistryClient_EnvOverrideNonHTTPS(t *testing.T) {
	// With RAMPART_DEV=1 but non-HTTPS URL, override should be rejected.
	t.Setenv("RAMPART_DEV", "1")
	t.Setenv("RAMPART_REGISTRY_URL", "http://evil.example.com/registry.json")

	client := newPolicyRegistryClient()
	assert.Equal(t, defaultPolicyRegistryManifestURL, client.manifestURL,
		"non-HTTPS override should be rejected even with RAMPART_DEV=1")
}

// ---------------------------------------------------------------------------
// loadManifest fallback warning
// ---------------------------------------------------------------------------

func TestLoadManifest_FallbackWarning(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	// Point to a server that will refuse connections by using a closed server.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gone", http.StatusInternalServerError)
	}))
	srv.Close() // close immediately to force network failure

	var warnBuf strings.Builder

	oldManifestURL := defaultPolicyRegistryManifestURL
	oldClient := defaultPolicyRegistryHTTPClient
	defaultPolicyRegistryManifestURL = srv.URL + "/registry.json"
	defaultPolicyRegistryHTTPClient = srv.Client()
	t.Cleanup(func() {
		defaultPolicyRegistryManifestURL = oldManifestURL
		defaultPolicyRegistryHTTPClient = oldClient
	})

	client := newPolicyRegistryClient()
	client.warnWriter = &warnBuf

	manifest, err := client.loadManifest(t.Context(), true) // force refresh
	require.NoError(t, err)
	require.NotNil(t, manifest)

	// Should have emitted a fallback warning.
	assert.Contains(t, warnBuf.String(), "using embedded registry data")
}

// ---------------------------------------------------------------------------
// Built-in profile descriptions
// ---------------------------------------------------------------------------

func TestPolicyList_BuiltInDescriptions(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	srv := registryTestServer(t, testManifest())
	defer srv.Close()
	patchRegistryURL(t, srv)

	stdout, _, err := runCLI(t, "policy", "list")
	require.NoError(t, err)

	// Each built-in should have its differentiated description, not generic "Built-in profile".
	assert.Contains(t, stdout, "Balanced default policy")
	assert.Contains(t, stdout, "Maximum restriction")
	assert.Contains(t, stdout, "Permissive")
}
