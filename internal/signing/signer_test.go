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

package signing

import (
	"bytes"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSignAndValidateRoundtrip(t *testing.T) {
	t.Parallel()

	signer := NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	expiresAt := time.Now().Add(5 * time.Minute)
	approvalID := "approval/with spaces"

	raw := signer.SignURL("http://localhost:9090/", approvalID, expiresAt)
	sig, exp, err := extractSigExp(raw)
	if err != nil {
		t.Fatalf("extract sig/exp: %v", err)
	}
	if !strings.Contains(raw, "/v1/approvals/approval%2Fwith%20spaces/resolve") {
		t.Fatalf("approval path should be escaped, got URL: %q", raw)
	}
	if !signer.ValidateSignature(approvalID, sig, exp) {
		t.Fatal("expected signature validation to succeed")
	}
}

func TestNewSignerCopiesKey(t *testing.T) {
	t.Parallel()

	original := []byte("0123456789abcdef0123456789abcdef")
	signer := NewSigner(original)
	original[0] = 'X'

	exp := time.Now().Add(time.Minute).Unix()
	sig := signer.signature("approval-1", exp)

	mutated := NewSigner(original)
	if sig == mutated.signature("approval-1", exp) {
		t.Fatal("signer should copy the key and not use caller-owned backing array")
	}
}

func TestValidateSignatureRejectsExpiredAndTamperedInputs(t *testing.T) {
	t.Parallel()

	signer := NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	expiredExp := time.Now().Add(-time.Minute).Unix()
	validExpiredSig := signer.signature("approval-1", expiredExp)
	if signer.ValidateSignature("approval-1", validExpiredSig, expiredExp) {
		t.Fatal("expected expired signature to be rejected")
	}

	futureExp := time.Now().Add(5 * time.Minute).Unix()
	validSig := signer.signature("approval-1", futureExp)
	if signer.ValidateSignature("approval-1", validSig+"tampered", futureExp) {
		t.Fatal("expected tampered signature to be rejected")
	}
	if signer.ValidateSignature("approval-2", validSig, futureExp) {
		t.Fatal("expected signature for wrong approval ID to be rejected")
	}
}

func TestValidateSignatureEmptyAndNilInputs(t *testing.T) {
	t.Parallel()

	nilSigner := NewSigner(nil)
	exp := time.Now().Add(time.Minute).Unix()
	emptySig := nilSigner.signature("", exp)
	if !nilSigner.ValidateSignature("", emptySig, exp) {
		t.Fatal("expected empty approval ID and nil key to still produce deterministic valid signature")
	}
	if nilSigner.ValidateSignature("", "", exp) {
		t.Fatal("expected empty signature to fail validation")
	}
}

func TestGenerateKey(t *testing.T) {
	t.Parallel()

	keyA, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	keyB, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey returned error on second call: %v", err)
	}
	if len(keyA) != 32 || len(keyB) != 32 {
		t.Fatalf("expected 32-byte keys, got %d and %d", len(keyA), len(keyB))
	}
	if bytes.Equal(keyA, keyB) {
		t.Fatal("expected generated keys to be random and differ")
	}
}

func TestLoadOrCreateKeyCreateAndLoad(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "nested", "signing.key")

	created, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreateKey create failed: %v", err)
	}
	if len(created) != 32 {
		t.Fatalf("expected created key length 32, got %d", len(created))
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("expected key file permission 0600, got %04o", got)
	}

	loaded, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreateKey load failed: %v", err)
	}
	if !bytes.Equal(created, loaded) {
		t.Fatal("expected loaded key to match created key")
	}
}

func TestLoadOrCreateKeyReadError(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "dir-as-file")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	_, err := LoadOrCreateKey(path)
	if err == nil {
		t.Fatal("expected read error")
	}
	if !strings.Contains(err.Error(), "signing: read key") {
		t.Fatalf("expected read key error, got: %v", err)
	}
}

func TestLoadOrCreateKeyCreateDirError(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	blocker := filepath.Join(tempDir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}
	path := filepath.Join(blocker, "signing.key")

	_, err := LoadOrCreateKey(path)
	if err == nil {
		t.Fatal("expected create key dir error")
	}
	if !strings.Contains(err.Error(), "signing:") {
		t.Fatalf("expected signing error, got: %v", err)
	}
}

func TestLoadOrCreateKeyWriteError(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	noWriteDir := filepath.Join(tempDir, "no-write")
	if err := os.Mkdir(noWriteDir, 0o500); err != nil {
		t.Fatalf("mkdir no-write dir: %v", err)
	}
	path := filepath.Join(noWriteDir, "signing.key")

	_, err := LoadOrCreateKey(path)
	if err == nil {
		t.Fatal("expected write key error")
	}
	if !strings.Contains(err.Error(), "signing: write key") {
		t.Fatalf("expected write key error, got: %v", err)
	}
}

func TestKeyRotationInvalidatesOldSignature(t *testing.T) {
	t.Parallel()

	oldSigner := NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	newSigner := NewSigner([]byte("fedcba9876543210fedcba9876543210"))
	exp := time.Now().Add(5 * time.Minute).Unix()

	oldSig := oldSigner.signature("approval-1", exp)
	newSig := newSigner.signature("approval-1", exp)

	if !oldSigner.ValidateSignature("approval-1", oldSig, exp) {
		t.Fatal("old signer should validate old signature")
	}
	if !newSigner.ValidateSignature("approval-1", newSig, exp) {
		t.Fatal("new signer should validate new signature")
	}
	if newSigner.ValidateSignature("approval-1", oldSig, exp) {
		t.Fatal("new signer should reject old key signature after rotation")
	}
	if oldSigner.ValidateSignature("approval-1", newSig, exp) {
		t.Fatal("old signer should reject new key signature")
	}
}

func TestSignedURLMalformedAndMissingParams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
	}{
		{name: "invalid_url", raw: "http://[::1"},
		{name: "missing_sig", raw: "http://localhost/v1/approvals/a/resolve?exp=123"},
		{name: "missing_exp", raw: "http://localhost/v1/approvals/a/resolve?sig=x"},
		{name: "bad_exp", raw: "http://localhost/v1/approvals/a/resolve?sig=x&exp=not-a-number"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := extractSigExp(tt.raw)
			if err == nil {
				t.Fatal("expected malformed/missing URL parameter error")
			}
		})
	}
}

func extractSigExp(raw string) (string, int64, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", 0, err
	}
	q := u.Query()
	sig := q.Get("sig")
	if sig == "" {
		return "", 0, errors.New("missing sig")
	}
	rawExp := q.Get("exp")
	if rawExp == "" {
		return "", 0, errors.New("missing exp")
	}
	exp, err := strconv.ParseInt(rawExp, 10, 64)
	if err != nil {
		return "", 0, err
	}
	return sig, exp, nil
}
