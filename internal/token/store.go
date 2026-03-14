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
//
// Tokens are stored as SHA-256 hashes on disk. The plaintext token is shown
// once at creation time and never persisted.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	// Prefix for all rampart tokens.
	Prefix = "rampart_"

	// ScopeEval allows tool call evaluation (POST /v1/eval).
	// Audit reads, status checks, approvals, and rule management require ScopeAdmin.
	ScopeEval = "eval"

	// ScopeAdmin allows mutations: approvals, rule deletion, policy reload, token management.
	ScopeAdmin = "admin"

	// tokenBytes is the number of random bytes in a generated token.
	tokenBytes = 24
)

// validName matches agent and policy names: alphanumeric, dash, underscore, 1-64 chars.
var validName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// Token represents a per-agent authentication token.
type Token struct {
	// Hash is the SHA-256 hex digest of the token ID. The plaintext is never stored.
	Hash string `json:"hash"`

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

	// ExpiresAt is when the token expires. Nil means no expiry.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// Note is an optional human-readable description.
	Note string `json:"note,omitempty"`

	// Revoked is true if the token has been explicitly revoked.
	Revoked bool `json:"revoked,omitempty"`

	// MaskedPrefix is the first 8 hex chars of the token for display/logging.
	MaskedPrefix string `json:"masked_prefix"`
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
	if t.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*t.ExpiresAt)
}

// IsValid returns true if the token is not revoked and not expired.
func (t Token) IsValid() bool {
	return !t.Revoked && !t.IsExpired()
}

// MaskedID returns the token with the secret portion masked.
// Shows prefix + first 8 hex chars + "...".
func (t Token) MaskedID() string {
	return Prefix + t.MaskedPrefix + "..."
}

// LookupResult contains the outcome of a token lookup.
type LookupResult struct {
	Token   Token
	Found   bool
	Revoked bool
	Expired bool
}

// Store manages per-agent tokens with file-backed persistence.
type Store struct {
	path    string
	mu      sync.RWMutex
	data    storeData
	modTime time.Time // last known file mtime for auto-reload
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
// Returns the full plaintext token string (only available at creation time)
// along with the Token record (which contains only the hash).
func (s *Store) Create(agent, policy, note string, scopes []string, expiresAt *time.Time) (plaintext string, tok Token, err error) {
	if agent == "" {
		return "", Token{}, fmt.Errorf("token: agent name is required")
	}
	if !validName.MatchString(agent) {
		return "", Token{}, fmt.Errorf("token: invalid agent name %q (must match [a-zA-Z0-9_-]{1,64})", agent)
	}
	if policy != "" && !validName.MatchString(policy) {
		return "", Token{}, fmt.Errorf("token: invalid policy name %q (must match [a-zA-Z0-9_-]{1,64})", policy)
	}
	if len(scopes) == 0 {
		scopes = []string{ScopeEval}
	}
	for _, scope := range scopes {
		if scope != ScopeEval && scope != ScopeAdmin {
			return "", Token{}, fmt.Errorf("token: invalid scope %q (valid: eval, admin)", scope)
		}
	}

	id, err := generateID()
	if err != nil {
		return "", Token{}, fmt.Errorf("token: generate ID: %w", err)
	}

	hash := hashToken(id)
	masked := id[len(Prefix):]
	if len(masked) > 8 {
		masked = masked[:8]
	}

	tok = Token{
		Hash:         hash,
		Agent:        agent,
		Policy:       policy,
		Scopes:       scopes,
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    expiresAt,
		Note:         note,
		MaskedPrefix: masked,
	}

	s.mu.Lock()
	s.data.Tokens = append(s.data.Tokens, tok)
	if saveErr := s.save(); saveErr != nil {
		// Rollback: remove the token we just appended.
		s.data.Tokens = s.data.Tokens[:len(s.data.Tokens)-1]
		s.mu.Unlock()
		return "", Token{}, fmt.Errorf("token: persist: %w", saveErr)
	}
	s.mu.Unlock()

	return id, tok, nil
}

// Lookup finds a token by its plaintext ID. Hashes the input and compares.
// Returns a LookupResult with details on why lookup may have failed.
func (s *Store) Lookup(id string) LookupResult {
	// Auto-reload if file changed on disk (covers CLI create/revoke while server runs).
	s.maybeReload()

	hash := hashToken(id)

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, t := range s.data.Tokens {
		if subtle.ConstantTimeCompare([]byte(t.Hash), []byte(hash)) == 1 {
			if t.Revoked {
				return LookupResult{Token: t, Found: true, Revoked: true}
			}
			if t.IsExpired() {
				return LookupResult{Token: t, Found: true, Expired: true}
			}
			return LookupResult{Token: t, Found: true}
		}
	}
	return LookupResult{}
}

// List returns all tokens (including revoked/expired for display purposes).
func (s *Store) List() []Token {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]Token, len(s.data.Tokens))
	copy(result, s.data.Tokens)
	return result
}

// Revoke marks a token as revoked by hash prefix match.
// Returns the number of tokens revoked.
func (s *Store) Revoke(prefix string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Match against masked ID (rampart_XXXXXXXX...), masked prefix, or hash prefix.
	// Strip trailing "..." from display format if present.
	cleanPrefix := strings.TrimSuffix(prefix, "...")
	var revokedIndices []int
	for i := range s.data.Tokens {
		t := &s.data.Tokens[i]
		fullMasked := Prefix + t.MaskedPrefix
		matched := strings.HasPrefix(fullMasked, cleanPrefix) ||
			strings.HasPrefix(t.Hash, cleanPrefix)
		if matched && !t.Revoked {
			t.Revoked = true
			revokedIndices = append(revokedIndices, i)
		}
	}

	if len(revokedIndices) == 0 {
		return 0, fmt.Errorf("token: no active token matching prefix %q", prefix)
	}

	if err := s.save(); err != nil {
		// Rollback: restore revoked tokens to active.
		for _, idx := range revokedIndices {
			s.data.Tokens[idx].Revoked = false
		}
		return 0, fmt.Errorf("token: persist revocation: %w", err)
	}
	return len(revokedIndices), nil
}

// FindByPrefix returns all tokens matching the given masked ID prefix or hash prefix.
func (s *Store) FindByPrefix(prefix string) []Token {
	s.mu.RLock()
	defer s.mu.RUnlock()

	clean := strings.TrimSuffix(prefix, "...")
	var matches []Token
	for _, t := range s.data.Tokens {
		fullMasked := Prefix + t.MaskedPrefix
		if strings.HasPrefix(fullMasked, clean) ||
			strings.HasPrefix(t.Hash, clean) {
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
	info, err := os.Stat(s.path)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &s.data); err != nil {
		return err
	}
	s.modTime = info.ModTime()
	return nil
}

// maybeReload checks if the file on disk has changed and reloads if so.
// This allows CLI operations (create, revoke) to take effect without server restart.
func (s *Store) maybeReload() {
	info, err := os.Stat(s.path)
	if err != nil {
		return
	}
	s.mu.RLock()
	stale := info.ModTime().After(s.modTime)
	s.mu.RUnlock()

	if !stale {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Double-check after acquiring write lock.
	info2, err := os.Stat(s.path)
	if err != nil {
		return
	}
	if !info2.ModTime().After(s.modTime) {
		return
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var newData storeData
	if err := json.Unmarshal(data, &newData); err != nil {
		return
	}
	s.data = newData
	s.modTime = info2.ModTime()
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

func hashToken(id string) string {
	h := sha256.Sum256([]byte(id))
	return hex.EncodeToString(h[:])
}
