package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peg/rampart/policies"
	"github.com/peg/rampart/registry"
)

func TestProductionGuardRegistryJourney(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	want, err := policies.Profile("production-guard")
	if err != nil {
		t.Fatal(err)
	}
	var manifest policyRegistryManifest
	if err := json.Unmarshal(registry.RegistryJSON, &manifest); err != nil {
		t.Fatal(err)
	}
	entry, found := findPolicyByName(&manifest, "production-guard")
	if !found || entry.MinRampart != "1.9.0" {
		t.Fatal("versioned production-guard missing from registry")
	}
	if err := verifyPolicySHA256(want, entry.SHA256, entry.Name); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(entry.URL, "/policies/production-guard.yaml") {
		t.Fatal("registry must use canonical embedded source")
	}

	// Exercise the normal HTTPS download and digest validation path without
	// sockets or external requests. The real manifest and profile are served
	// by an in-memory transport; no user state or services are inspected.
	requests := 0
	oldClient := defaultPolicyRegistryHTTPClient
	defaultPolicyRegistryHTTPClient = &http.Client{Transport: redirectTestTransport(func(req *http.Request) (*http.Response, error) {
		var body []byte
		switch req.URL.String() {
		case defaultPolicyRegistryManifestURL:
			body = registry.RegistryJSON
		case entry.URL:
			requests++
			body = want
		default:
			return nil, fmt.Errorf("unexpected synthetic registry request")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body)), Request: req}, nil
	})}
	t.Cleanup(func() { defaultPolicyRegistryHTTPClient = oldClient })

	shown, _, err := runCLI(t, "policy", "show", "production-guard")
	if err != nil || shown != strings.TrimSpace(string(want)) {
		t.Fatalf("preview: %v", err)
	}
	_, stderr, err := runCLI(t, "policy", "fetch", "production-guard", "--dry-run")
	if err != nil || strings.Contains(stderr, "Warning:") {
		t.Fatalf("dry run: %v, %s", err, stderr)
	}
	dest := filepath.Join(home, ".rampart", "policies", "production-guard.yaml")
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("preview installed a policy")
	}
	_, stderr, err = runCLI(t, "policy", "install", "production-guard")
	if err != nil || strings.Contains(stderr, "Warning:") {
		t.Fatalf("install: %v, %s", err, stderr)
	}
	got, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("installed policy differs from pinned source")
	}
	if requests != 2 {
		t.Fatalf("remote policy requests = %d, want 2", requests)
	}
	state, err := builtInPolicyStateForVersion(dest, "v1.9.0")
	if err != nil || !state.MatchesCurrent {
		t.Fatalf("managed profile not recognized: %v", err)
	}
	if _, _, err := runCLI(t, "policy", "install", "production-guard"); err == nil {
		t.Fatal("install overwrote existing profile without force")
	}
}
