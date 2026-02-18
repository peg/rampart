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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

	// dedupKey is the SHA-256 hash of tool+command+agent for deduplication.
	dedupKey string

	// done is closed when the approval is resolved.
	done chan struct{}
}

// Store manages pending approval requests.
type Store struct {
	mu       sync.Mutex
	pending  map[string]*Request
	timeout  time.Duration
	onExpire func(*Request)
	stop     chan struct{}
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

// NewStore creates a new approval store.
// Starts a background goroutine that cleans up resolved requests every 5 minutes.
func NewStore(opts ...Option) *Store {
	s := &Store{
		pending: make(map[string]*Request),
		timeout: 5 * time.Minute,
		stop:    make(chan struct{}),
	}
	for _, opt := range opts {
		opt(s)
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

	// Start expiry timer.
	go s.watchExpiry(req)

	return req, nil
}

// Resolve approves or denies a pending request.
// Returns an error if the request doesn't exist or is already resolved.
func (s *Store) Resolve(id string, approved bool, resolvedBy string) error {
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

	close(req.done)
	return nil
}

// Get returns a request by ID.
func (s *Store) Get(id string) (*Request, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.pending[id]
	return req, ok
}

// List returns all pending requests.
func (s *Store) List() []*Request {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make([]*Request, 0, len(s.pending))
	for _, req := range s.pending {
		if req.Status == StatusPending {
			result = append(result, req)
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

// Cleanup removes resolved/expired requests older than the given duration.
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

	return removed
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
		}
		s.mu.Unlock()
	}
}
