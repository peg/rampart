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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/peg/rampart/internal/filetxn"
	"github.com/peg/rampart/internal/securefile"
)

const (
	// Prefix for all rampart tokens.
	Prefix = "rampart_"

	// ScopeEval allows tool-call evaluation and enforcement through the
	// /v1/preflight/{tool} endpoint.
	// Audit reads, status checks, approvals, and rule management require ScopeAdmin.
	ScopeEval = "eval"

	// ScopeAdmin allows mutations: approvals, rule deletion, policy reload, token management.
	ScopeAdmin = "admin"

	// tokenBytes is the number of random bytes in a generated token.
	tokenBytes = 24

	maxStoreBytes = 16 << 20
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
	path     string
	mu       sync.RWMutex
	data     storeData
	fileInfo os.FileInfo // identity and metadata of the last successfully loaded file
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

	if saveErr := s.update(func(data *storeData) error {
		data.Tokens = append(data.Tokens, tok)
		return nil
	}); saveErr != nil {
		return "", Token{}, fmt.Errorf("token: persist: %w", saveErr)
	}

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
	s.maybeReload()
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]Token, len(s.data.Tokens))
	copy(result, s.data.Tokens)
	return result
}

// Revoke marks a token as revoked by hash prefix match.
// Returns the number of tokens revoked.
func (s *Store) Revoke(prefix string) (int, error) {
	// Match against masked ID (rampart_XXXXXXXX...), masked prefix, or hash prefix.
	// Strip trailing "..." from display format if present.
	cleanPrefix := strings.TrimSpace(strings.TrimSuffix(prefix, "..."))
	if cleanPrefix == "" {
		return 0, errors.New("token: token ID or prefix is required")
	}

	revoked := 0
	err := s.update(func(data *storeData) error {
		matches := make([]int, 0, 1)
		for i := range data.Tokens {
			if !data.Tokens[i].Revoked && tokenMatchesPrefix(data.Tokens[i], cleanPrefix) {
				matches = append(matches, i)
			}
		}
		if len(matches) == 0 {
			return fmt.Errorf("token: no active token matching prefix %q", prefix)
		}
		if len(matches) > 1 {
			return fmt.Errorf("token: prefix %q matches %d active tokens; be more specific", prefix, len(matches))
		}
		data.Tokens[matches[0]].Revoked = true
		revoked = 1
		return nil
	})
	if err != nil {
		return 0, err
	}
	return revoked, nil
}

// FindByPrefix returns all tokens matching the given masked ID prefix or hash prefix.
func (s *Store) FindByPrefix(prefix string) []Token {
	s.maybeReload()
	s.mu.RLock()
	defer s.mu.RUnlock()

	clean := strings.TrimSpace(strings.TrimSuffix(prefix, "..."))
	if clean == "" {
		return nil
	}
	var matches []Token
	for _, t := range s.data.Tokens {
		if tokenMatchesPrefix(t, clean) {
			matches = append(matches, t)
		}
	}
	return matches
}

func tokenMatchesPrefix(t Token, prefix string) bool {
	if strings.HasPrefix(prefix, Prefix) && len(prefix) == len(Prefix)+tokenBytes*2 {
		return subtle.ConstantTimeCompare([]byte(t.Hash), []byte(hashToken(prefix))) == 1
	}
	return strings.HasPrefix(Prefix+t.MaskedPrefix, prefix) ||
		strings.HasPrefix(t.MaskedPrefix, prefix) ||
		strings.HasPrefix(t.Hash, prefix)
}

// Count returns the number of active (non-revoked, non-expired) tokens.
func (s *Store) Count() int {
	s.maybeReload()
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
	data, fileInfo, err := readStoreFile(s.path)
	if err != nil {
		return err
	}
	s.data = data
	s.fileInfo = fileInfo
	return nil
}

func readStoreFile(path string) (storeData, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return storeData{}, nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return storeData{}, nil, fmt.Errorf("token store is not a regular non-symlink file: %s", path)
	}
	if before.Size() > maxStoreBytes {
		return storeData{}, nil, fmt.Errorf("token store exceeds %d-byte limit", maxStoreBytes)
	}
	if err := securefile.OwnerOnly(path); err != nil {
		return storeData{}, nil, fmt.Errorf("secure token store: %w", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return storeData{}, nil, err
	}
	defer file.Close()

	opened, err := file.Stat()
	if err != nil {
		return storeData{}, nil, err
	}
	after, err := os.Lstat(path)
	if err != nil {
		return storeData{}, nil, err
	}
	if after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() ||
		!os.SameFile(before, after) || !os.SameFile(opened, after) {
		return storeData{}, nil, fmt.Errorf("token store changed while opening: %s", path)
	}
	content, err := io.ReadAll(io.LimitReader(file, maxStoreBytes+1))
	if err != nil {
		return storeData{}, nil, err
	}
	if len(content) > maxStoreBytes {
		return storeData{}, nil, fmt.Errorf("token store exceeds %d-byte limit", maxStoreBytes)
	}
	var data storeData
	if err := json.Unmarshal(content, &data); err != nil {
		return storeData{}, nil, err
	}
	return data, opened, nil
}

// maybeReload checks if the file on disk has changed and reloads if so.
// This allows CLI operations (create, revoke) to take effect without server restart.
func (s *Store) maybeReload() {
	info, err := os.Lstat(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.mu.Lock()
			s.data = storeData{}
			s.fileInfo = nil
			s.mu.Unlock()
		}
		return
	}
	s.mu.RLock()
	stale := storeFileChanged(s.fileInfo, info)
	s.mu.RUnlock()

	if !stale {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Double-check after acquiring write lock.
	info2, err := os.Lstat(s.path)
	if err != nil {
		return
	}
	if !storeFileChanged(s.fileInfo, info2) {
		return
	}
	newData, fileInfo, err := readStoreFile(s.path)
	if err != nil {
		// A changed but unreadable/corrupt authentication store must not leave
		// previously cached credentials active indefinitely.
		s.data = storeData{}
		s.fileInfo = info2
		return
	}
	s.data = newData
	s.fileInfo = fileInfo
}

func storeFileChanged(cached, current os.FileInfo) bool {
	if cached == nil || current == nil {
		return cached != current
	}
	return !os.SameFile(cached, current) || cached.Size() != current.Size() ||
		!cached.ModTime().Equal(current.ModTime()) || cached.Mode() != current.Mode()
}

// update serializes a read-modify-write transaction across Store instances
// and processes, so concurrent CLI token operations cannot lose each other.
func (s *Store) update(fn func(*storeData) error) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	return filetxn.WithLock(s.path, func() error {
		diskData, fileInfo, err := readStoreFile(s.path)
		if errors.Is(err, os.ErrNotExist) {
			diskData = storeData{}
			fileInfo = nil
		} else if err != nil {
			return err
		}
		s.data = diskData
		s.fileInfo = fileInfo
		if err := fn(&s.data); err != nil {
			return err
		}
		if err := s.saveLocked(); err != nil {
			s.data = diskData
			s.fileInfo = fileInfo
			return err
		}
		return nil
	})
}

// saveLocked persists s.data. The caller must hold s.mu and the cross-process
// file transaction lock.
func (s *Store) saveLocked() error {
	data, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > maxStoreBytes {
		return fmt.Errorf("token store exceeds %d-byte limit", maxStoreBytes)
	}

	// Atomic write via temp file + rename.
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".tokens-*.json")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()

	// Harden the temporary before writing token metadata so Windows never
	// exposes it through an inherited directory ACL, even briefly.
	if err := securefile.OwnerOnly(tmpPath); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := filetxn.Replace(tmpPath, s.path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if info, err := os.Stat(s.path); err == nil {
		s.fileInfo = info
	}
	return nil
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
