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
	"testing"
	"time"
)

func TestServeRestartVerifierRejectsStaleState(t *testing.T) {
	home := t.TempDir()
	state := serveState{
		URL:     "http://127.0.0.1:9090",
		Port:    9090,
		PID:     1234,
		Started: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano),
	}
	writeUpgradeServeState(t, home, state)

	verifier, err := prepareServeRestartVerifierWithDeps(
		func() (string, error) { return home, nil },
		os.ReadFile,
		testServeRestartVerifierDeps(func(int) (bool, string, error) { return true, "rampart serve", nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	err = verifier(context.Background(), "v1.4.1", time.Now())
	if err == nil || !strings.Contains(err.Error(), "serve.state is stale") {
		t.Fatalf("stale state error = %v", err)
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
	verifier, err := prepareServeRestartVerifierWithDeps(
		func() (string, error) { return home, nil },
		os.ReadFile,
		testServeRestartVerifierDeps(processIdentity),
	)
	if err != nil {
		t.Fatal(err)
	}
	return verifier
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
