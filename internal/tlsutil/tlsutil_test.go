package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadOrGenerate_CreatesCert(t *testing.T) {
	dir := t.TempDir()
	cfg, fp, err := LoadOrGenerate(dir)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.NotEmpty(t, fp)
	assert.Len(t, cfg.Certificates, 1)

	// Verify files exist.
	_, err = os.Stat(filepath.Join(dir, "cert.pem"))
	assert.NoError(t, err)
	_, err = os.Stat(filepath.Join(dir, "key.pem"))
	assert.NoError(t, err)
}

func TestLoadOrGenerate_ReusesExisting(t *testing.T) {
	dir := t.TempDir()

	// Generate first.
	_, fp1, err := LoadOrGenerate(dir)
	require.NoError(t, err)

	// Load again — should reuse.
	_, fp2, err := LoadOrGenerate(dir)
	require.NoError(t, err)

	assert.Equal(t, fp1, fp2, "should reuse existing cert")
}

func TestLoadFromFiles(t *testing.T) {
	dir := t.TempDir()

	// Generate cert first.
	_, _, err := LoadOrGenerate(dir)
	require.NoError(t, err)

	cfg, fp, err := LoadFromFiles(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.NotEmpty(t, fp)
}

func TestLoadFromFiles_MissingFile(t *testing.T) {
	_, _, err := LoadFromFiles("/nonexistent/cert.pem", "/nonexistent/key.pem")
	assert.Error(t, err)
}

func TestFingerprint(t *testing.T) {
	fp := Fingerprint([]byte("test data"))
	assert.Contains(t, fp, ":")
	// SHA-256 = 32 bytes = 64 hex chars = 32 pairs + 31 colons
	assert.Len(t, fp, 95)
}

func TestGeneratedCertIsValid(t *testing.T) {
	dir := t.TempDir()
	cfg, _, err := LoadOrGenerate(dir)
	require.NoError(t, err)

	// Parse the cert.
	cert, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	require.NoError(t, err)

	assert.Equal(t, "rampart", cert.Subject.CommonName)
	assert.Contains(t, cert.DNSNames, "localhost")
	// Check that 127.0.0.1 is in the cert's IP SANs (may be 4-byte or 16-byte).
	hasLoopback := false
	for _, ip := range cert.IPAddresses {
		if ip.Equal(net.IPv4(127, 0, 0, 1)) {
			hasLoopback = true
			break
		}
	}
	assert.True(t, hasLoopback, "cert should include 127.0.0.1")
	assert.Equal(t, x509.ECDSA, cert.PublicKeyAlgorithm)
}

func TestGeneratedCertPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permissions not enforced on Windows")
	}

	dir := t.TempDir()
	_, _, err := LoadOrGenerate(dir)
	require.NoError(t, err)

	info, err := os.Stat(filepath.Join(dir, "key.pem"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "key should be 0600")

	info, err = os.Stat(filepath.Join(dir, "cert.pem"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "cert should be 0600")
}

func TestTLSServerAcceptsConnections(t *testing.T) {
	dir := t.TempDir()
	tlsCfg, _, err := LoadOrGenerate(dir)
	require.NoError(t, err)

	// Start a TLS server.
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	require.NoError(t, err)
	defer listener.Close()

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}
	go srv.Serve(listener)
	defer srv.Close()

	// Connect with TLS (skip verify since self-signed).
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get("https://" + listener.Addr().String() + "/")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
