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
	"runtime"
	"strings"
	"time"
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

	// Try loading existing.
	if cfg, fp, err := loadExisting(certPath, keyPath); err == nil {
		return cfg, fp, nil
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
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("tls: create %s: %w", filepath.Base(path), err)
	}
	defer f.Close()

	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: data}); err != nil {
		return fmt.Errorf("tls: write %s: %w", filepath.Base(path), err)
	}

	// On non-Windows, ensure restrictive permissions.
	if runtime.GOOS != "windows" {
		if err := f.Chmod(0o600); err != nil {
			return fmt.Errorf("tls: chmod %s: %w", filepath.Base(path), err)
		}
	}

	return nil
}
