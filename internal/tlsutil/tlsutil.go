// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package tlsutil provides TLS certificate management for rampart serve.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/peg/rampart/internal/filetxn"
	"github.com/peg/rampart/internal/securefile"
)

// DefaultCertDir returns the default directory for auto-generated TLS certs.
func DefaultCertDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".rampart", "tls")
}

// LoadOrGenerate loads existing cert/key from dir, or generates a new
// self-signed cert if none exists or the existing one is expired.
// Returns the tls.Config and a human-readable fingerprint string.
func LoadOrGenerate(certDir string) (*tls.Config, string, error) {
	certPath := filepath.Join(certDir, "cert.pem")
	keyPath := filepath.Join(certDir, "key.pem")

	// Refuse special files at managed paths before either reading or replacing
	// them. In particular, following a planted symlink while regenerating a key
	// could truncate an unrelated file outside the TLS directory.
	for _, path := range []string{certPath, keyPath} {
		if err := validateManagedPath(path); err != nil {
			return nil, "", err
		}
	}

	// Try loading an existing managed pair. Harden both files first so Windows
	// receives a protected current-user-only DACL just as Unix receives 0600.
	if pathsExist(certPath, keyPath) {
		if err := securefile.OwnerOnly(certPath); err != nil {
			return nil, "", fmt.Errorf("tls: secure %s: %w", filepath.Base(certPath), err)
		}
		if err := securefile.OwnerOnly(keyPath); err != nil {
			return nil, "", fmt.Errorf("tls: secure %s: %w", filepath.Base(keyPath), err)
		}
		if cfg, fp, err := loadExisting(certPath, keyPath); err == nil {
			return cfg, fp, nil
		}
	}

	// Generate new self-signed cert.
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return nil, "", fmt.Errorf("tls: create cert dir: %w", err)
	}

	if err := generateSelfSigned(certPath, keyPath); err != nil {
		return nil, "", err
	}

	return loadExisting(certPath, keyPath)
}

// LoadFromFiles loads a TLS config from explicit cert and key files.
// Returns the tls.Config and a human-readable fingerprint string.
func LoadFromFiles(certPath, keyPath string) (*tls.Config, string, error) {
	return loadExisting(certPath, keyPath)
}

// Fingerprint computes the SHA-256 fingerprint of a DER-encoded certificate.
func Fingerprint(der []byte) string {
	h := sha256.Sum256(der)
	hex := hex.EncodeToString(h[:])
	// Format as colon-separated pairs for readability.
	var parts []string
	for i := 0; i < len(hex); i += 2 {
		parts = append(parts, hex[i:i+2])
	}
	return strings.Join(parts, ":")
}

func loadExisting(certPath, keyPath string) (*tls.Config, string, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, "", fmt.Errorf("tls: load keypair: %w", err)
	}

	// Check expiry.
	if len(cert.Certificate) > 0 {
		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		if err == nil && time.Now().After(x509Cert.NotAfter) {
			return nil, "", fmt.Errorf("tls: certificate expired at %s", x509Cert.NotAfter)
		}
	}

	fp := ""
	if len(cert.Certificate) > 0 {
		fp = Fingerprint(cert.Certificate[0])
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	return cfg, fp, nil
}

func generateSelfSigned(certPath, keyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("tls: generate key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("tls: generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "rampart"},
		NotBefore:    time.Now().UTC().Add(-1 * time.Hour),
		NotAfter:     time.Now().UTC().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("tls: create certificate: %w", err)
	}

	// Write cert PEM.
	if err := writePEM(certPath, "CERTIFICATE", certDER); err != nil {
		return err
	}

	// Write key PEM.
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("tls: marshal key: %w", err)
	}
	return writePEM(keyPath, "EC PRIVATE KEY", keyDER)
}

func writePEM(path, blockType string, data []byte) error {
	encoded := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: data})
	if encoded == nil {
		return fmt.Errorf("tls: encode %s", filepath.Base(path))
	}

	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("tls: create temporary %s: %w", filepath.Base(path), err)
	}
	tmpPath := f.Name()
	defer os.Remove(tmpPath)

	// Apply the final access controls before private material is written. The
	// ACL/mode follows the file through the atomic rename.
	if err := securefile.OwnerOnly(tmpPath); err != nil {
		_ = f.Close()
		return fmt.Errorf("tls: secure temporary %s: %w", filepath.Base(path), err)
	}
	if _, err := f.Write(encoded); err != nil {
		_ = f.Close()
		return fmt.Errorf("tls: write %s: %w", filepath.Base(path), err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("tls: sync %s: %w", filepath.Base(path), err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("tls: close %s: %w", filepath.Base(path), err)
	}
	if err := filetxn.Replace(tmpPath, path); err != nil {
		return fmt.Errorf("tls: replace %s: %w", filepath.Base(path), err)
	}
	return nil
}

func validateManagedPath(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("tls: inspect %s: %w", filepath.Base(path), err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("tls: managed path is not a regular non-symlink file: %s", path)
	}
	return nil
}

func pathsExist(paths ...string) bool {
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			return false
		}
	}
	return true
}
