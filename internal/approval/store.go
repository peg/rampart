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

// Package approval manages pending approval requests for tool calls
// that match a require_approval policy rule.
//
// When the policy engine returns require_approval, the proxy creates
// a pending approval with a unique ID. The approval is held until
// a human resolves it via CLI or HTTP API, or it times out.
package approval

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/peg/rampart/internal/engine"
)

// dedupWindow is the time window for deduplicating identical approval requests.
const dedupWindow = 60 * time.Second

// Status represents the state of an approval request.
type Status int

const (
	StatusPending  Status = iota
	StatusApproved
	StatusDenied
	StatusExpired
)

func (s Status) String() string {
	switch s {
	case StatusPending:
		return "pending"
	case StatusApproved:
		return "approved"
	case StatusDenied:
		return "denied"
	case StatusExpired:
		return "expired"
	default:
		return fmt.Sprintf("status(%d)", int(s))
	}
}

// Request is a pending approval for a tool call.
type Request struct {
	// ID is a unique identifier (ULID).
	ID string

	// Call is the original tool call that triggered the approval.
	Call engine.ToolCall

	// Decision is the policy engine's evaluation result.
	Decision engine.Decision

	// Status is the current approval state.
	Status Status

	// CreatedAt is when the approval was created.
	CreatedAt time.Time

	// ExpiresAt is when the approval times out (auto-denied).
	ExpiresAt time.Time

	// ResolvedAt is when the approval was resolved (if resolved).
	ResolvedAt time.Time

	// ResolvedBy is who resolved the approval (e.g., "cli", "api", "timeout").
	ResolvedBy string

	// Persisted indicates this approval resulted in a persistent allow-always rule.
	Persisted bool

	// dedupKey is the SHA-256 hash of tool+command+agent for deduplication.
	dedupKey string

	// done is closed when the approval is resolved.
	done chan struct{}
}

// persistRecord is the on-disk representation of an approval request.
// Uses flat string fields to avoid circular JSON dependencies on engine types.
type persistRecord struct {
	ID              string            `json:"id"`
	Tool            string            `json:"tool"`
	Agent           string            `json:"agent"`
	Session         string            `json:"session,omitempty"`
	RunID           string            `json:"run_id,omitempty"`
	Command         string            `json:"command,omitempty"`
	Params          map[string]any    `json:"params,omitempty"`
	Input           map[string]any    `json:"input,omitempty"`
	MatchedPolicies []string          `json:"matched_policies,omitempty"`
	Message         string            `json:"message,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	ExpiresAt       time.Time         `json:"expires_at"`
	ResolvedAt      time.Time         `json:"resolved_at,omitempty"`
	ResolvedBy      string            `json:"resolved_by,omitempty"`
	Status          string            `json:"status"`
	Persisted       bool              `json:"persisted,omitempty"`
}

// Store manages pending approval requests.
type Store struct {
	mu              sync.Mutex
	pending         map[string]*Request
	autoApproveRuns map[string]time.Time // run_id -> expiry
	timeout         time.Duration
	onExpire        func(*Request)
	stop            chan struct{}
	persistFile     string
	logger          *slog.Logger
}

// Option configures a Store.
type Option func(*Store)

// WithTimeout sets the default approval timeout.
func WithTimeout(d time.Duration) Option {
	return func(s *Store) {
		s.timeout = d
	}
}

// WithExpireCallback sets a callback for expired approvals.
func WithExpireCallback(fn func(*Request)) Option {
	return func(s *Store) {
		s.onExpire = fn
	}
}

// WithPersistenceFile sets the path of the JSONL file used to persist
// pending approvals across server restarts.
// If empty, persistence is disabled (in-memory only).
func WithPersistenceFile(path string) Option {
	return func(s *Store) {
		s.persistFile = path
	}
}

// WithLogger sets the logger for the store.
func WithLogger(l *slog.Logger) Option {
	return func(s *Store) {
		s.logger = l
	}
}

// NewStore creates a new approval store.
// Starts a background goroutine that cleans up resolved requests every 5 minutes.
func NewStore(opts ...Option) *Store {
	s := &Store{
		pending:         make(map[string]*Request),
		autoApproveRuns: make(map[string]time.Time),
		timeout:         2 * time.Minute, // Match OpenClaw's DEFAULT_APPROVAL_REQUEST_TIMEOUT_MS (130s)
		stop:            make(chan struct{}),
		logger:          slog.Default(),
	}
	for _, opt := range opts {
		opt(s)
	}

	// Load persisted approvals from disk (if a file is configured).
	if s.persistFile != "" {
		s.loadFromDisk()
	}

	// Periodic cleanup of resolved/expired entries.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.Cleanup(10 * time.Minute)
			case <-s.stop:
				return
			}
		}
	}()

	return s
}

// Close stops the background cleanup goroutine.
func (s *Store) Close() {
	select {
	case <-s.stop:
		// Already closed.
	default:
		close(s.stop)
	}
}

// maxPendingApprovals is the maximum number of pending approval requests
// allowed at any time. This prevents memory exhaustion from a flood of
// approval-requiring tool calls.
const maxPendingApprovals = 1000

// ErrTooManyPending is returned when the pending approval limit is reached.
var ErrTooManyPending = fmt.Errorf("approval: too many pending requests (limit: %d)", maxPendingApprovals)

// dedupKey computes a SHA-256 hash of tool + command + agent for dedup lookup.
func dedupKey(call engine.ToolCall) string {
	h := sha256.Sum256([]byte(call.Tool + "\x00" + call.Command() + "\x00" + call.Agent))
	return hex.EncodeToString(h[:])
}

// Create adds a new pending approval and returns it.
// The caller should wait on request.Done() for resolution.
// Returns nil and an error if the pending approval limit has been reached.
//
// If an identical pending approval (same tool + command + agent) was created
// within the last 60 seconds, the existing approval is returned instead of
// creating a duplicate. This handles agent retries on timeout/reconnect.
func (s *Store) Create(call engine.ToolCall, decision engine.Decision) (*Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	key := dedupKey(call)

	// Check for an existing identical pending approval within the dedup window.
	for _, req := range s.pending {
		if req.Status == StatusPending && req.dedupKey == key && now.Sub(req.CreatedAt) < dedupWindow {
			return req, nil
		}
	}

	// Count pending approvals to enforce the size limit.
	pendingCount := 0
	for _, req := range s.pending {
		if req.Status == StatusPending {
			pendingCount++
		}
	}
	if pendingCount >= maxPendingApprovals {
		return nil, ErrTooManyPending
	}
	req := &Request{
		ID:        ulid.Make().String(),
		Call:      call,
		Decision:  decision,
		Status:    StatusPending,
		CreatedAt: now,
		ExpiresAt: now.Add(s.timeout),
		dedupKey:  key,
		done:      make(chan struct{}),
	}

	s.pending[req.ID] = req

	// Persist to disk.
	if s.persistFile != "" {
		if err := s.appendToDisk(req); err != nil {
			s.logger.Warn("approval: failed to persist new approval", "id", req.ID, "error", err)
		}
	}

	// Start expiry timer.
	go s.watchExpiry(req)

	return req, nil
}

// Resolve approves or denies a pending request.
// Returns an error if the request doesn't exist or is already resolved.
func (s *Store) Resolve(id string, approved bool, resolvedBy string, persist bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.pending[id]
	if !ok {
		return fmt.Errorf("approval: unknown id %q", id)
	}

	if req.Status != StatusPending {
		return fmt.Errorf("approval: %s is already %s", id, req.Status)
	}

	if approved {
		req.Status = StatusApproved
	} else {
		req.Status = StatusDenied
	}
	req.ResolvedAt = time.Now()
	req.ResolvedBy = resolvedBy
	req.Persisted = approved && persist // Only set if approved with persist=true

	close(req.done)

	// Rewrite the persistence file to reflect the updated status.
	if s.persistFile != "" {
		if err := s.rewriteDisk(); err != nil {
			s.logger.Warn("approval: failed to rewrite persistence file after resolve", "id", id, "error", err)
		}
	}

	return nil
}

// Get returns a request by ID.
func (s *Store) Get(id string) (*Request, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.pending[id]
	if !ok {
		return nil, false
	}
	// Return a snapshot so callers don't race with watchExpiry writes.
	cp := *req
	return &cp, true
}

// List returns snapshots of all pending requests.
// Callers receive copies, not live pointers, so reads don't race with
// concurrent writes from watchExpiry or Resolve.
func (s *Store) List() []*Request {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make([]*Request, 0, len(s.pending))
	for _, req := range s.pending {
		if req.Status == StatusPending {
			cp := *req
			result = append(result, &cp)
		}
	}
	// Sort by creation time (oldest first) for deterministic ordering.
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	return result
}

// Done returns a channel that's closed when the request is resolved.
func (r *Request) Done() <-chan struct{} {
	return r.done
}

// Cleanup removes resolved/expired requests older than the given duration
// and evicts expired auto-approve cache entries.
func (s *Store) Cleanup(olderThan time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-olderThan)
	removed := 0

	for id, req := range s.pending {
		if req.Status != StatusPending && req.ResolvedAt.Before(cutoff) {
			delete(s.pending, id)
			removed++
		}
	}

	s.cleanAutoApproveCache()

	// Prune the on-disk file to match in-memory state.
	if removed > 0 && s.persistFile != "" {
		if err := s.rewriteDisk(); err != nil {
			s.logger.Warn("approval: failed to rewrite persistence file after cleanup", "error", err)
		}
	}

	return removed
}

// AutoApproveRun marks a run_id for auto-approval until the TTL elapses.
// Subsequent tool calls from that run will be allowed without human review.
func (s *Store) AutoApproveRun(runID string, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.autoApproveRuns[runID] = time.Now().Add(ttl)
}

// IsAutoApproved reports whether the given run_id has been bulk-approved and
// the approval has not yet expired.
func (s *Store) IsAutoApproved(runID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	expiry, ok := s.autoApproveRuns[runID]
	return ok && time.Now().Before(expiry)
}

// cleanAutoApproveCache removes expired run_id entries from the cache.
// Must be called with s.mu held.
func (s *Store) cleanAutoApproveCache() {
	now := time.Now()
	for id, expiry := range s.autoApproveRuns {
		if now.After(expiry) {
			delete(s.autoApproveRuns, id)
		}
	}
}

func (s *Store) watchExpiry(req *Request) {
	timer := time.NewTimer(time.Until(req.ExpiresAt))
	defer timer.Stop()

	select {
	case <-req.done:
		return // Already resolved.
	case <-s.stop:
		return // Store is shutting down.
	case <-timer.C:
		s.mu.Lock()
		if req.Status == StatusPending {
			req.Status = StatusExpired
			req.ResolvedAt = time.Now()
			req.ResolvedBy = "timeout"
			close(req.done)

			if s.onExpire != nil {
				go s.onExpire(req)
			}

			// Rewrite persistence file after timeout expiry.
			if s.persistFile != "" {
				if err := s.rewriteDisk(); err != nil {
					s.logger.Warn("approval: failed to rewrite persistence file after expiry", "id", req.ID, "error", err)
				}
			}
		}
		s.mu.Unlock()
	}
}

// --- Persistence helpers ---

// toRecord converts a Request to its on-disk representation.
func toRecord(req *Request) persistRecord {
	return persistRecord{
		ID:              req.ID,
		Tool:            req.Call.Tool,
		Agent:           req.Call.Agent,
		Session:         req.Call.Session,
		RunID:           req.Call.RunID,
		Command:         req.Call.Command(),
		Params:          req.Call.Params,
		Input:           req.Call.Input,
		MatchedPolicies: req.Decision.MatchedPolicies,
		Message:         req.Decision.Message,
		CreatedAt:       req.CreatedAt,
		ExpiresAt:       req.ExpiresAt,
		ResolvedAt:      req.ResolvedAt,
		ResolvedBy:      req.ResolvedBy,
		Status:          req.Status.String(),
		Persisted:       req.Persisted,
	}
}

// fromRecord reconstructs an in-memory Request from a persist record.
// Returns (nil, false) if the record should be discarded (expired or non-pending).
func fromRecord(rec persistRecord) (*Request, bool) {
	// Only restore truly pending approvals.
	if rec.Status != "pending" {
		return nil, false
	}
	// Discard expired approvals.
	if time.Now().After(rec.ExpiresAt) {
		return nil, false
	}

	call := engine.ToolCall{
		Tool:    rec.Tool,
		Agent:   rec.Agent,
		Session: rec.Session,
		RunID:   rec.RunID,
		Params:  rec.Params,
		Input:   rec.Input,
	}
	if call.Params == nil {
		call.Params = make(map[string]any)
	}
	decision := engine.Decision{
		Action:          engine.ActionRequireApproval,
		MatchedPolicies: rec.MatchedPolicies,
		Message:         rec.Message,
	}

	req := &Request{
		ID:        rec.ID,
		Call:      call,
		Decision:  decision,
		Status:    StatusPending,
		CreatedAt: rec.CreatedAt,
		ExpiresAt: rec.ExpiresAt,
		dedupKey:  dedupKey(call),
		done:      make(chan struct{}),
	}
	return req, true
}

// loadFromDisk reads the persistence file and restores pending (non-expired)
// approvals to the in-memory map. Must be called before the store is used.
// Errors are logged but never fatal — a missing or corrupt file is safe to ignore.
func (s *Store) loadFromDisk() {
	f, err := os.Open(s.persistFile)
	if err != nil {
		if !os.IsNotExist(err) {
			s.logger.Warn("approval: could not open persistence file", "path", s.persistFile, "error", err)
		}
		return
	}
	defer f.Close()

	restored := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec persistRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			s.logger.Warn("approval: skipping malformed persistence record", "error", err)
			continue
		}
		req, ok := fromRecord(rec)
		if !ok {
			continue
		}
		s.pending[req.ID] = req
		go s.watchExpiry(req)
		restored++
	}
	if err := scanner.Err(); err != nil {
		s.logger.Warn("approval: error reading persistence file", "path", s.persistFile, "error", err)
	}
	if restored > 0 {
		s.logger.Info("approval: restored pending approvals from disk", "count", restored, "path", s.persistFile)
	}
}

// appendToDisk appends a single approval record to the JSONL file.
// Must be called with s.mu held.
func (s *Store) appendToDisk(req *Request) error {
	if err := os.MkdirAll(dirOf(s.persistFile), 0o755); err != nil {
		return fmt.Errorf("approval: create dir: %w", err)
	}
	f, err := os.OpenFile(s.persistFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("approval: open persistence file: %w", err)
	}
	defer f.Close()

	data, err := json.Marshal(toRecord(req))
	if err != nil {
		return fmt.Errorf("approval: marshal record: %w", err)
	}
	_, err = fmt.Fprintf(f, "%s\n", data)
	return err
}

// rewriteDisk atomically rewrites the persistence file with the current
// in-memory state. Only pending (non-expired) approvals are written.
// Must be called with s.mu held.
func (s *Store) rewriteDisk() error {
	if err := os.MkdirAll(dirOf(s.persistFile), 0o755); err != nil {
		return fmt.Errorf("approval: create dir: %w", err)
	}

	tmp := s.persistFile + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("approval: open tmp file: %w", err)
	}

	enc := json.NewEncoder(f)
	for _, req := range s.pending {
		// Only persist pending approvals; resolved/expired ones are transient.
		if req.Status != StatusPending {
			continue
		}
		if err := enc.Encode(toRecord(req)); err != nil {
			f.Close()
			os.Remove(tmp)
			return fmt.Errorf("approval: encode record: %w", err)
		}
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, s.persistFile)
}

// dirOf returns the directory portion of a file path.
func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i]
		}
	}
	return "."
}
