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

// Package token manages per-agent authentication tokens for the Rampart proxy.
// Each token is bound to an agent identity and a set of scopes that control
// what API operations the bearer can perform.
package token

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// Prefix for all rampart tokens.
	Prefix = "rampart_"

	// ScopeEval allows tool call evaluation, audit reads, and status checks.
	ScopeEval = "eval"

	// ScopeAdmin allows mutations: approvals, rule deletion, policy reload, token management.
	ScopeAdmin = "admin"

	// tokenBytes is the number of random bytes in a generated token.
	tokenBytes = 24
)

// Token represents a per-agent authentication token.
type Token struct {
	// ID is the full token string (rampart_<hex>). Stored hashed after creation.
	ID string `json:"id"`

	// Agent identifies which AI agent this token is for (e.g., "codex", "claude-code").
	Agent string `json:"agent"`

	// Policy is an optional policy profile name. When set, only policies from
	// this profile are evaluated for tool calls made with this token.
	// Empty means use the global policy set.
	Policy string `json:"policy,omitempty"`

	// Scopes controls what API operations are permitted.
	// Valid values: "eval", "admin".
	Scopes []string `json:"scopes"`

	// CreatedAt is when the token was created.
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt is when the token expires. Zero means no expiry.
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// Note is an optional human-readable description.
	Note string `json:"note,omitempty"`

	// Revoked is true if the token has been explicitly revoked.
	Revoked bool `json:"revoked,omitempty"`
}

// HasScope returns true if the token has the given scope.
func (t Token) HasScope(scope string) bool {
	for _, s := range t.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// IsExpired returns true if the token has an expiry and it has passed.
func (t Token) IsExpired() bool {
	if t.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(t.ExpiresAt)
}

// IsValid returns true if the token is not revoked and not expired.
func (t Token) IsValid() bool {
	return !t.Revoked && !t.IsExpired()
}

// MaskedID returns the token ID with the secret portion masked.
// Shows prefix + first 8 hex chars + "...".
func (t Token) MaskedID() string {
	if len(t.ID) > len(Prefix)+8 {
		return t.ID[:len(Prefix)+8] + "..."
	}
	return t.ID
}

// Store manages per-agent tokens with file-backed persistence.
type Store struct {
	path string
	mu   sync.RWMutex
	data storeData
}

type storeData struct {
	Tokens []Token `json:"tokens"`
}

// NewStore creates a token store backed by the given file path.
// If the file exists, tokens are loaded from it. If not, the store starts empty.
func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	if err := s.load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("token: load store: %w", err)
	}
	return s, nil
}

// DefaultStorePath returns the default token store path (~/.rampart/tokens.json).
func DefaultStorePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("token: resolve home: %w", err)
	}
	return filepath.Join(home, ".rampart", "tokens.json"), nil
}

// Create generates a new agent token and persists it.
// Returns the full token string (only available at creation time).
func (s *Store) Create(agent, policy, note string, scopes []string, expiresAt time.Time) (Token, error) {
	if agent == "" {
		return Token{}, fmt.Errorf("token: agent name is required")
	}
	if len(scopes) == 0 {
		scopes = []string{ScopeEval}
	}
	for _, scope := range scopes {
		if scope != ScopeEval && scope != ScopeAdmin {
			return Token{}, fmt.Errorf("token: invalid scope %q (valid: eval, admin)", scope)
		}
	}

	id, err := generateID()
	if err != nil {
		return Token{}, fmt.Errorf("token: generate ID: %w", err)
	}

	tok := Token{
		ID:        id,
		Agent:     agent,
		Policy:    policy,
		Scopes:    scopes,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: expiresAt,
		Note:      note,
	}

	s.mu.Lock()
	s.data.Tokens = append(s.data.Tokens, tok)
	err = s.save()
	s.mu.Unlock()

	if err != nil {
		return Token{}, fmt.Errorf("token: persist: %w", err)
	}
	return tok, nil
}

// Lookup finds a token by its full ID. Returns the token and true if found
// and valid (not revoked, not expired).
func (s *Store) Lookup(id string) (Token, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, t := range s.data.Tokens {
		if subtle.ConstantTimeCompare([]byte(t.ID), []byte(id)) == 1 {
			if !t.IsValid() {
				return Token{}, false
			}
			return t, true
		}
	}
	return Token{}, false
}

// List returns all tokens (including revoked/expired for display purposes).
func (s *Store) List() []Token {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]Token, len(s.data.Tokens))
	copy(result, s.data.Tokens)
	return result
}

// Revoke marks a token as revoked by ID prefix match.
// Returns the number of tokens revoked.
func (s *Store) Revoke(idPrefix string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for i := range s.data.Tokens {
		if strings.HasPrefix(s.data.Tokens[i].ID, idPrefix) && !s.data.Tokens[i].Revoked {
			s.data.Tokens[i].Revoked = true
			count++
		}
	}

	if count == 0 {
		return 0, fmt.Errorf("token: no active token matching prefix %q", idPrefix)
	}

	if err := s.save(); err != nil {
		return 0, fmt.Errorf("token: persist revocation: %w", err)
	}
	return count, nil
}

// FindByPrefix returns all tokens matching the given ID prefix.
func (s *Store) FindByPrefix(prefix string) []Token {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var matches []Token
	for _, t := range s.data.Tokens {
		if strings.HasPrefix(t.ID, prefix) {
			matches = append(matches, t)
		}
	}
	return matches
}

// Count returns the number of active (non-revoked, non-expired) tokens.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, t := range s.data.Tokens {
		if t.IsValid() {
			count++
		}
	}
	return count
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &s.data)
}

func (s *Store) save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	// Atomic write via temp file + rename.
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".tokens-*.json")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, s.path)
}

func generateID() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return Prefix + hex.EncodeToString(b), nil
}
