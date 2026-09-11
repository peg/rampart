// Copyright 2026 The Rampart Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/peg/rampart/internal/proxy"
)

func TestServeRestartVerifierBindsSameVersionHealthToOwnedInstance(t *testing.T) {
	for _, tc := range []struct {
		name, expected, stateID, healthID, previousID string
		wantError                                     bool
	}{
		{"matching", "v2.0.0", "fresh-instance-0001", "fresh-instance-0001", "previous-instance-0001", false},
		{"unrelated same version", "v2.0.0", "fresh-instance-0001", "other-instance-0001", "previous-instance-0001", true},
		{"reused instance", "v2.0.0", "fresh-instance-0001", "fresh-instance-0001", "fresh-instance-0001", true},
		{"modern identity missing", "v2.0.0", "", "", "previous-instance-0001", true},
		{"legacy rollback", "v1.9.1", "", "", "previous-instance-0001", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			uptime := 1
			identity := proxy.RuntimeIdentity{InstanceID: tc.healthID, Version: tc.expected, Commit: "same-build", Mode: "enforce"}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(proxy.HealthResponse{RuntimeIdentity: identity, Service: "rampart", Status: "ok", UptimeSeconds: &uptime})
			}))
			defer server.Close()
			parsed, _ := url.Parse(server.URL)
			port, _ := strconv.Atoi(parsed.Port())
			state := serveState{URL: server.URL, Port: port, PID: 4242, Started: time.Now().UTC().Format(time.RFC3339Nano), RuntimeIdentity: identity}
			state.InstanceID = tc.stateID
			previous := state
			previous.InstanceID = tc.previousID
			previous.Started = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
			data, _ := json.Marshal(state)
			previousData, _ := json.Marshal(previous)
			deps := testServeRestartVerifierDeps(func(int) (bool, string, error) { return true, "rampart serve", nil })
			_, err := verifyRestartedServeState(context.Background(), home, os.ReadFile, data, tc.expected, previousData, true, time.Now().Add(-time.Second), deps)
			if (err != nil) != tc.wantError {
				t.Fatalf("activation error=%v, wantError=%t", err, tc.wantError)
			}
		})
	}
}

func TestServeRestartVerifierRejectsStaleState(t *testing.T) {
	home := t.TempDir()
	state := serveState{
		URL:     "http://127.0.0.1:9090",
		Port:    9090,
		PID:     1234,
		Started: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano),
	}
	writeUpgradeServeState(t, home, state)

	previous, err := os.ReadFile(filepath.Join(home, ".rampart", serveStateFile))
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifyRestartedServe(context.Background(), home, os.ReadFile, "v1.4.1", previous, true, time.Now(),
		testServeRestartVerifierDeps(func(int) (bool, string, error) { return true, "rampart serve", nil }))
	if err == nil || !strings.Contains(err.Error(), "serve.state is stale") {
		t.Fatalf("stale state error = %v", err)
	}
}

func TestServeRestartVerifierPreservesObservedEndpointAndMode(t *testing.T) {
	for _, tc := range []struct {
		name, oldMode, newMode, changedEndpoint, wantError string
		previousVersion, wantPrepareError                  string
		legacy                                             bool
	}{
		{name: "enforce retained", oldMode: "enforce", newMode: "enforce"},
		{name: "monitor retained", oldMode: "monitor", newMode: "monitor"},
		{name: "disabled retained", oldMode: "disabled", newMode: "disabled"},
		{name: "matching new state and health weakened", oldMode: "enforce", newMode: "monitor", wantError: "mode mismatch"},
		{name: "changed port", oldMode: "enforce", newMode: "enforce", changedEndpoint: "port", wantError: "endpoint differs"},
		{name: "changed TLS", oldMode: "enforce", newMode: "enforce", changedEndpoint: "scheme", wantError: "endpoint differs"},
		{name: "legacy observed mode retained", oldMode: "monitor", newMode: "monitor", legacy: true},
		{name: "legacy observed mode changed", oldMode: "monitor", newMode: "enforce", legacy: true, wantError: "mode mismatch"},
		{name: "modern identity missing before restart", oldMode: "enforce", legacy: true, previousVersion: "2.0.0", wantPrepareError: "lacks instance identity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			uptime := 1
			oldIdentity := proxy.RuntimeIdentity{InstanceID: "previous-instance-0001", Version: "1.9.1", Commit: "previous-build", Mode: tc.oldMode}
			if tc.previousVersion != "" {
				oldIdentity.Version = tc.previousVersion
			}
			if tc.legacy {
				oldIdentity.InstanceID = ""
				oldIdentity.Commit = ""
			}
			var health atomic.Value
			health.Store(proxy.HealthResponse{RuntimeIdentity: oldIdentity, Service: "rampart", Status: "ok", UptimeSeconds: &uptime})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(health.Load().(proxy.HealthResponse))
			}))
			defer server.Close()
			u, _ := url.Parse(server.URL)
			port, _ := strconv.Atoi(u.Port())
			previous := serveState{URL: server.URL, Port: port, PID: 4242, Started: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano), RuntimeIdentity: oldIdentity}
			if tc.legacy {
				previous.RuntimeIdentity = proxy.RuntimeIdentity{}
			}
			writeUpgradeServeState(t, home, previous)
			verifier, err := prepareServeRestartVerifierWithDeps(func() (string, error) { return home, nil }, os.ReadFile,
				testServeRestartVerifierDeps(func(int) (bool, string, error) { return true, "rampart serve", nil }))
			if tc.wantPrepareError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantPrepareError) {
					t.Fatalf("preparation error=%v, want %q", err, tc.wantPrepareError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			candidate := previous
			candidate.RuntimeIdentity = proxy.RuntimeIdentity{InstanceID: "candidate-instance-0001", Version: "2.0.0", Commit: "candidate-build", Mode: tc.newMode}
			candidate.Started = time.Now().UTC().Format(time.RFC3339Nano)
			switch tc.changedEndpoint {
			case "port":
				candidate.Port = port%65535 + 1
				candidate.URL = "http://127.0.0.1:" + strconv.Itoa(candidate.Port)
			case "scheme":
				candidate.URL = strings.Replace(server.URL, "http://", "https://", 1)
			}
			health.Store(proxy.HealthResponse{RuntimeIdentity: candidate.RuntimeIdentity, Service: "rampart", Status: "ok", UptimeSeconds: &uptime})
			writeUpgradeServeState(t, home, candidate)
			err = verifier(context.Background(), "v2.0.0", time.Now().Add(-time.Second))
			if tc.wantError == "" && err != nil || tc.wantError != "" && (err == nil || !strings.Contains(err.Error(), tc.wantError)) {
				t.Fatalf("activation error=%v, want %q", err, tc.wantError)
			}
		})
	}
}

func TestServeRestartPreparationRequiresPreviousRuntime(t *testing.T) {
	home := t.TempDir()
	_, err := prepareServeRestartVerifierWithDeps(func() (string, error) { return home, nil }, os.ReadFile,
		testServeRestartVerifierDeps(func(int) (bool, string, error) {
			t.Fatal("missing state must refuse before process inspection")
			return false, "", nil
		}))
	if err == nil || !strings.Contains(err.Error(), "previous runtime state") {
		t.Fatalf("missing baseline error: %v", err)
	}
}

func TestServeRestartVerifierRejectsWrongVersion(t *testing.T) {
	home := t.TempDir()
	server := newUpgradeHealthServer(t, false, "v1.4.0")
	defer server.Close()

	verifier := prepareUpgradeHealthVerifier(t, home, func(int) (bool, string, error) {
		return true, "rampart serve", nil
	})
	writeFreshUpgradeServeState(t, home, strings.Replace(server.URL, "127.0.0.1", "localhost", 1), 1234)

	err := verifier(context.Background(), "v1.4.1", time.Now().Add(-time.Second))
	if err == nil || !strings.Contains(err.Error(), "version mismatch") {
		t.Fatalf("wrong-version error = %v", err)
	}
}

func TestServeRestartVerifierRejectsUnownedPID(t *testing.T) {
	home := t.TempDir()
	server := newUpgradeHealthServer(t, false, "v1.4.1")
	defer server.Close()

	verifier := prepareUpgradeHealthVerifier(t, home, func(pid int) (bool, string, error) {
		if pid != 9876 {
			t.Fatalf("process pid = %d", pid)
		}
		return false, "python test-server", nil
	})
	writeFreshUpgradeServeState(t, home, server.URL, 9876)

	err := verifier(context.Background(), "v1.4.1", time.Now().Add(-time.Second))
	if err == nil || !strings.Contains(err.Error(), "pid 9876 is not Rampart-owned") {
		t.Fatalf("unowned-pid error = %v", err)
	}
}

func TestServeRestartVerifierAcceptsHealthyHTTPRuntime(t *testing.T) {
	home := t.TempDir()
	server := newUpgradeHealthServer(t, false, "1.4.1")
	defer server.Close()

	verifier := prepareUpgradeHealthVerifier(t, home, func(int) (bool, string, error) {
		return true, "rampart serve", nil
	})
	writeFreshUpgradeServeState(t, home, server.URL, 1234)

	if err := verifier(context.Background(), "v1.4.1", time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("healthy HTTP runtime rejected: %v", err)
	}
}

func TestServeRestartVerifierAcceptsLegacyHealthWithoutServiceIdentity(t *testing.T) {
	home := t.TempDir()
	server := newUpgradeHealthServerWithService(t, false, "v1.4.0", "")
	defer server.Close()

	verifier := prepareUpgradeHealthVerifier(t, home, func(int) (bool, string, error) {
		return true, "rampart serve", nil
	})
	writeFreshUpgradeServeState(t, home, server.URL, 1234)

	if err := verifier(context.Background(), "v1.4.0", time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("legacy Rampart runtime rejected during rollback verification: %v", err)
	}
}

func TestServeRestartVerifierRejectsNewHealthWithoutServiceIdentity(t *testing.T) {
	home := t.TempDir()
	server := newUpgradeHealthServerWithService(t, false, "v1.4.1", "")
	defer server.Close()

	verifier := prepareUpgradeHealthVerifier(t, home, func(int) (bool, string, error) {
		return true, "rampart serve", nil
	})
	writeFreshUpgradeServeState(t, home, server.URL, 1234)

	err := verifier(context.Background(), "v1.4.1", time.Now().Add(-time.Second))
	if err == nil || !strings.Contains(err.Error(), "unexpected health service identity") {
		t.Fatalf("missing new-runtime service identity error = %v", err)
	}
}

func TestServeRestartVerifierAcceptsTLSAutoCertificateOnly(t *testing.T) {
	home := t.TempDir()
	server := newUpgradeHealthServer(t, true, "v1.4.1")
	defer server.Close()

	certPath := filepath.Join(home, ".rampart", "tls", "cert.pem")
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	verifier := prepareUpgradeHealthVerifier(t, home, func(int) (bool, string, error) {
		return true, "rampart serve --tls-auto", nil
	})
	writeFreshUpgradeServeState(t, home, server.URL, 1234)

	if err := verifier(context.Background(), "v1.4.1", time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("healthy tls-auto runtime rejected: %v", err)
	}
}

func TestServeRestartVerifierRejectsHTTPSWithoutManagedTLSAutoCertificate(t *testing.T) {
	home := t.TempDir()
	server := newUpgradeHealthServer(t, true, "v1.4.1")
	defer server.Close()

	verifier := prepareUpgradeHealthVerifier(t, home, func(int) (bool, string, error) {
		return true, "rampart serve --tls-cert /custom/cert.pem", nil
	})
	writeFreshUpgradeServeState(t, home, server.URL, 1234)

	err := verifier(context.Background(), "v1.4.1", time.Now().Add(-time.Second))
	if err == nil || !strings.Contains(err.Error(), "custom --tls-cert runtimes require a manual upgrade") {
		t.Fatalf("custom TLS verification error = %v", err)
	}
}

func TestServeRestartVerifierRejectsRemoteStateURL(t *testing.T) {
	_, err := validateLocalServeStateURL(serveState{
		URL:  "https://example.com:443",
		Port: 443,
		PID:  1234,
	})
	if err == nil || !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("remote state URL error = %v", err)
	}
}

func prepareUpgradeHealthVerifier(
	t *testing.T,
	home string,
	processIdentity func(int) (bool, string, error),
) serveRestartVerifier {
	t.Helper()
	// These cases isolate candidate health validation. Preparation and
	// continuity against a live previous service are covered separately.
	return func(ctx context.Context, version string, restartedAt time.Time) error {
		_, err := verifyRestartedServe(ctx, home, os.ReadFile, version, nil, false, restartedAt,
			testServeRestartVerifierDeps(processIdentity))
		return err
	}
}

func testServeRestartVerifierDeps(processIdentity func(int) (bool, string, error)) serveRestartVerifierDeps {
	return serveRestartVerifierDeps{
		processIdentity: processIdentity,
		now:             time.Now,
		timeout:         250 * time.Millisecond,
		pollInterval:    5 * time.Millisecond,
		requestTimeout:  100 * time.Millisecond,
	}
}

func newUpgradeHealthServer(t *testing.T, useTLS bool, version string) *httptest.Server {
	t.Helper()
	return newUpgradeHealthServerWithService(t, useTLS, version, "rampart")
}

func newUpgradeHealthServerWithService(t *testing.T, useTLS bool, version, service string) *httptest.Server {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		body := map[string]any{
			"status":         "ok",
			"mode":           "enforce",
			"uptime_seconds": 0,
			"version":        version,
		}
		if service != "" {
			body["service"] = service
		}
		_ = json.NewEncoder(w).Encode(body)
	})
	if useTLS {
		return httptest.NewTLSServer(handler)
	}
	return httptest.NewServer(handler)
}

func writeFreshUpgradeServeState(t *testing.T, home, rawURL string, pid int) {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse test server URL %q: %v", rawURL, err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		// httptest URLs always end in :<port>; keep the failure useful if that
		// invariant changes.
		t.Fatalf("parse test server URL %q: %v", rawURL, err)
	}
	writeUpgradeServeState(t, home, serveState{
		URL:     rawURL,
		Port:    port,
		PID:     pid,
		Started: time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func writeUpgradeServeState(t *testing.T, home string, state serveState) {
	t.Helper()
	statePath := filepath.Join(home, ".rampart", serveStateFile)
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
