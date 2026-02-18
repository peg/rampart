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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Signer creates and validates HMAC-signed approval resolve URLs.
type Signer struct {
	key []byte
}

// NewSigner returns a signer for the provided HMAC key.
func NewSigner(key []byte) *Signer {
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	return &Signer{key: keyCopy}
}

// SignURL returns a signed resolve URL for the approval ID and expiry time.
// The signature TTL is coupled to the approval expiry: the signature expires
// when the approval expires, which is correct (you cannot approve after expiry),
// but it means long approval timeouts produce long-lived signed URLs.
func (s *Signer) SignURL(baseURL, approvalID string, expiresAt time.Time) string {
	exp := expiresAt.Unix()
	sig := s.signature(approvalID, exp)
	base := strings.TrimRight(baseURL, "/")
	return fmt.Sprintf("%s/v1/approvals/%s/resolve?sig=%s&exp=%d", base, url.PathEscape(approvalID), url.QueryEscape(sig), exp)
}

// ValidateSignature verifies the signature and expiry for an approval ID.
func (s *Signer) ValidateSignature(approvalID string, sig string, exp int64) bool {
	if time.Now().Unix() > exp {
		return false
	}
	expected := s.signature(approvalID, exp)
	return subtle.ConstantTimeCompare([]byte(sig), []byte(expected)) == 1
}

// GenerateKey creates a 32-byte random signing key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("signing: generate key: %w", err)
	}
	return key, nil
}

// LoadOrCreateKey loads a key from path or creates one when missing.
func LoadOrCreateKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err == nil {
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("signing: read key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("signing: create key dir: %w", err)
	}

	key, err = GenerateKey()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, fmt.Errorf("signing: write key: %w", err)
	}
	return key, nil
}

func (s *Signer) signature(approvalID string, exp int64) string {
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write([]byte(fmt.Sprintf("approve:%s:%d", approvalID, exp)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
