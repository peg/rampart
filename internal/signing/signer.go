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
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/peg/rampart/internal/filetxn"
	"github.com/peg/rampart/internal/securefile"
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
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("signing: create key dir: %w", err)
	}

	operation := "read key"
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		operation = "write key"
	}
	var key []byte
	err := filetxn.WithLock(path, func() error {
		info, err := os.Lstat(path)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return fmt.Errorf("refusing non-regular signing key %s", path)
			}
			if err := securefile.OwnerOnly(path); err != nil {
				return fmt.Errorf("secure signing key: %w", err)
			}
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			data, readErr := io.ReadAll(io.LimitReader(file, 33))
			closeErr := file.Close()
			if readErr != nil {
				return readErr
			}
			if closeErr != nil {
				return closeErr
			}
			if len(data) != 32 {
				return fmt.Errorf("signing key must be exactly 32 bytes (got %d)", len(data))
			}
			key = data
			return nil
		}
		if !os.IsNotExist(err) {
			return err
		}

		generated, err := GenerateKey()
		if err != nil {
			return err
		}
		tmp, err := os.CreateTemp(filepath.Dir(path), ".signing-key-*")
		if err != nil {
			return err
		}
		tmpPath := tmp.Name()
		defer os.Remove(tmpPath)
		if err := securefile.OwnerOnly(tmpPath); err != nil {
			_ = tmp.Close()
			return fmt.Errorf("secure temporary signing key: %w", err)
		}
		if _, err := tmp.Write(generated); err != nil {
			_ = tmp.Close()
			return err
		}
		if err := tmp.Sync(); err != nil {
			_ = tmp.Close()
			return err
		}
		if err := tmp.Close(); err != nil {
			return err
		}
		if err := filetxn.Replace(tmpPath, path); err != nil {
			return err
		}
		key = generated
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("signing: %s: %w", operation, err)
	}
	return key, nil
}

func (s *Signer) signature(approvalID string, exp int64) string {
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write([]byte(fmt.Sprintf("approve:%s:%d", approvalID, exp)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
