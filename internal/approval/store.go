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
// that match an ask policy rule.
//
// When the policy engine returns ask, the proxy creates
// a pending approval with a unique ID. The approval is held until
// a human resolves it via CLI or HTTP API, or it times out.
package approval

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/internal/filetxn"
	"github.com/peg/rampart/internal/securefile"
)

// dedupWindow is the time window for deduplicating identical approval requests.
const dedupWindow = 60 * time.Second

// approvedReplayWindow is intentionally short: an allow-once approval is only
// useful for the host's immediate retry of the exact tool call.
const approvedReplayWindow = 60 * time.Second

// Approval requests originate from the 1 MiB HTTP API but may contain both
// normalized params and structured input. Keep recovery bounded while leaving
// enough room for that duplicated representation and JSON overhead.
const maxApprovalRecordBytes = 4 * 1024 * 1024

const (
	// A healthy journal is compacted back to live pending approvals after every
	// resolution. These aggregate bounds keep a corrupt or adversarial journal
	// from turning service startup into an unbounded disk/heap scan.
	maxApprovalJournalBytes        = 256 * 1024 * 1024
	maxRestoredApprovalBytes       = 128 * 1024 * 1024
	maxApprovalJournalRecords      = 100_000
	maxReplayGrantBytes            = 16 * 1024
	maxPersistedReplayStateEntries = maxPendingApprovals * 4
)

// Status represents the state of an approval request.
type Status int

const (
	StatusPending Status = iota
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

	// dedupKey scopes retries to one host-provided tool-call identity.
	dedupKey string

	// done is closed when the approval is resolved.
	done chan struct{}
}

// ConsumedApproval describes an allow-once approval consumed by an exact
// retry. It intentionally exposes no broader capability or command pattern.
type ConsumedApproval struct {
	ID         string
	ResolvedBy string
}

// replayGrant is the minimal authorization material retained between an
// approval and the host's exact retry. Fingerprint binds the full execution
// context and payload; ExpiresAt bounds how long that retry may occur.
type replayGrant struct {
	Version     int       `json:"version"`
	ApprovalID  string    `json:"approval_id"`
	Fingerprint string    `json:"fingerprint"`
	ResolvedBy  string    `json:"resolved_by"`
	ResolvedAt  time.Time `json:"resolved_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// autoApproveScope binds a bulk approval to one authenticated execution
// identity. Host-provided run IDs are not globally unique and must never be an
// authorization capability by themselves.
type autoApproveScope struct {
	Agent   string
	Session string
	RunID   string
}

// persistRecord is the on-disk representation of an approval request.
// Uses flat string fields to avoid circular JSON dependencies on engine types.
type persistRecord struct {
	ID              string         `json:"id"`
	Tool            string         `json:"tool"`
	Agent           string         `json:"agent"`
	AgentDepth      int            `json:"agent_depth,omitempty"`
	Session         string         `json:"session,omitempty"`
	RunID           string         `json:"run_id,omitempty"`
	ToolCallID      string         `json:"tool_call_id,omitempty"`
	WorkDir         string         `json:"workdir,omitempty"`
	Command         string         `json:"command,omitempty"`
	Params          map[string]any `json:"params,omitempty"`
	Input           map[string]any `json:"input,omitempty"`
	MatchedPolicies []string       `json:"matched_policies,omitempty"`
	Message         string         `json:"message,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	ExpiresAt       time.Time      `json:"expires_at"`
	ResolvedAt      time.Time      `json:"resolved_at,omitempty"`
	ResolvedBy      string         `json:"resolved_by,omitempty"`
	Status          string         `json:"status"`
	Persisted       bool           `json:"persisted,omitempty"`
}

// Store manages pending approval requests.
type Store struct {
	mu              sync.Mutex
	pending         map[string]*Request
	approvedOnce    map[string]replayGrant // exact call fingerprint -> one-shot grant
	autoApproveRuns map[autoApproveScope]time.Time
	timeout         time.Duration
	onExpire        func(*Request)
	stop            chan struct{}
	closeOnce       sync.Once
	workers         sync.WaitGroup
	closed          bool
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
		approvedOnce:    make(map[string]replayGrant),
		autoApproveRuns: make(map[autoApproveScope]time.Time),
		timeout:         2 * time.Minute,
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
	s.startWorker(func() {
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
	})

	return s
}

// Close stops and joins every Store-owned background worker. Waiting matters
// on Windows, where an expiry worker can otherwise retain a journal handle
// after callers begin removing the Store's data directory.
func (s *Store) Close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		close(s.stop)
		s.mu.Unlock()
		s.workers.Wait()
	})
}

// startWorker registers a Store-owned goroutine before it can run. Callers
// either invoke it during construction or while holding s.mu before closure,
// so no positive WaitGroup delta can race the zero-to-Wait transition.
func (s *Store) startWorker(fn func()) {
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		fn()
	}()
}

// maxPendingApprovals is the maximum number of pending approval requests
// allowed at any time. This prevents memory exhaustion from a flood of
// approval-requiring tool calls.
const maxPendingApprovals = 1000

// ErrTooManyPending is returned when the pending approval limit is reached.
var ErrTooManyPending = fmt.Errorf("approval: too many pending requests (limit: %d)", maxPendingApprovals)

// ErrStoreClosed is returned when a caller tries to enqueue work after Close.
var ErrStoreClosed = fmt.Errorf("approval: store is closed")

// dedupKey computes a scoped retry identity for approval deduplication.
// Without a stable host-provided tool-call ID, deduplication is disabled:
// creating an extra approval is safer than reusing authorization across calls.
func dedupKey(call engine.ToolCall) string {
	if strings.TrimSpace(call.ToolCallID) == "" {
		return ""
	}
	action, err := json.Marshal(struct {
		Agent      string         `json:"agent"`
		AgentDepth int            `json:"agent_depth"`
		Session    string         `json:"session"`
		RunID      string         `json:"run_id"`
		ToolCallID string         `json:"tool_call_id"`
		Tool       string         `json:"tool"`
		WorkDir    string         `json:"workdir"`
		Params     map[string]any `json:"params"`
		Input      map[string]any `json:"input"`
	}{
		Agent:      call.Agent,
		AgentDepth: call.AgentDepth,
		Session:    call.Session,
		RunID:      call.RunID,
		ToolCallID: call.ToolCallID,
		Tool:       call.Tool,
		WorkDir:    call.WorkDir,
		Params:     call.Params,
		Input:      call.Input,
	})
	if err != nil {
		return ""
	}
	h := sha256.Sum256(action)
	return hex.EncodeToString(h[:])
}

// replayKey returns an authorization fingerprint only when the host supplied
// both levels of stable identity needed to resume one exact call. A tool-call
// ID without a run ID is insufficient because hosts may reuse call IDs across
// runs; calls without either identifier must return to the approval queue.
func replayKey(call engine.ToolCall) string {
	if strings.TrimSpace(call.RunID) == "" || strings.TrimSpace(call.ToolCallID) == "" {
		return ""
	}
	return dedupKey(call)
}

// Create adds a new pending approval and returns it.
// The caller should wait on request.Done() for resolution.
// Returns nil and an error if the pending approval limit has been reached.
//
// If the same host-identified tool call was submitted by the same agent,
// session, and run within the last 60 seconds, the existing approval is
// returned. Calls without a stable host-provided tool-call ID are never
// deduplicated.
func (s *Store) Create(call engine.ToolCall, decision engine.Decision) (*Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createLocked(call, decision)
}

// CreateOrAutoApproved atomically checks the run-scoped auto-approval cache
// and, only when no live entry exists, enqueues a pending approval. Keeping
// both operations under one lock prevents a bulk-approval publication from
// racing a stale IsAutoApproved check and leaving an orphan pending request.
func (s *Store) CreateOrAutoApproved(call engine.ToolCall, decision engine.Decision) (*Request, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isAutoApprovedLocked(call) {
		return nil, true, nil
	}
	req, err := s.createLocked(call, decision)
	return req, false, err
}

// createLocked enqueues one request. The caller must hold s.mu.
func (s *Store) createLocked(call engine.ToolCall, decision engine.Decision) (*Request, error) {
	if s.closed {
		return nil, ErrStoreClosed
	}

	now := time.Now()
	key := dedupKey(call)

	// Check for an existing identical pending approval within the dedup window.
	if key != "" {
		for _, req := range s.pending {
			if req.Status == StatusPending && req.dedupKey == key && now.Sub(req.CreatedAt) < dedupWindow {
				return req, nil
			}
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
			delete(s.pending, req.ID)
			return nil, fmt.Errorf("approval: persist new approval: %w", err)
		}
	}

	// Start expiry timer.
	s.startWorker(func() { s.watchExpiry(req) })

	return req, nil
}

// Resolve approves or denies a pending request.
// Returns an error if the request doesn't exist or is already resolved.
func (s *Store) Resolve(id string, approved bool, resolvedBy string) error {
	return s.ResolveBeforePublish(id, approved, resolvedBy, nil)
}

// ResolveBeforePublish resolves a pending request, invoking beforePublish
// after the durable resolution journal entry is written but before any
// authorization is published or any waiter is woken. A non-nil callback is
// intended for required side effects such as the resolution audit record.
//
// If the callback or replay-grant publication fails, the request remains
// pending and its pending state is appended back to the journal. This makes a
// failed resolution retryable without exposing an unaudited authorization.
// The callback runs while the Store mutex is held so concurrent resolves of
// the same request remain single-winner and cannot both publish grants.
func (s *Store) ResolveBeforePublish(
	id string,
	approved bool,
	resolvedBy string,
	beforePublish func(*Request) error,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.pending[id]
	if !ok {
		return fmt.Errorf("approval: unknown id %q", id)
	}

	if req.Status != StatusPending {
		return fmt.Errorf("approval: %s is already %s", id, req.Status)
	}
	if s.persistFile != "" {
		if err := secureExistingApprovalFile(s.persistFile); err != nil {
			return fmt.Errorf("approval: secure persistence journal: %w", err)
		}
	}

	now := time.Now()
	resolved := *req
	if approved {
		resolved.Status = StatusApproved
	} else {
		resolved.Status = StatusDenied
	}
	resolved.ResolvedAt = now
	resolved.ResolvedBy = resolvedBy
	// Durable policy persistence is a separate audited transaction. The store
	// records it only through MarkPersisted after that transaction commits.
	resolved.Persisted = false

	// The resolution journal is required state, not best-effort logging. It
	// must be durable before audit or authorization publication proceeds.
	if s.persistFile != "" {
		if err := s.appendToDisk(&resolved); err != nil {
			return fmt.Errorf("approval: persist resolution: %w", err)
		}
	}

	rollbackPending := func(cause error) error {
		if s.persistFile == "" {
			return cause
		}
		if err := s.appendToDisk(req); err != nil {
			return fmt.Errorf("%w; approval: failed to restore pending journal state: %v", cause, err)
		}
		return cause
	}

	if beforePublish != nil {
		callbackView := resolved
		if err := beforePublish(&callbackView); err != nil {
			return rollbackPending(fmt.Errorf("approval: required pre-publication step: %w", err))
		}
	}

	var grant replayGrant
	grantKey := ""
	if approved {
		grantKey = replayKey(req.Call)
		if grantKey != "" {
			grant = replayGrant{
				Version:     1,
				ApprovalID:  req.ID,
				Fingerprint: grantKey,
				ResolvedBy:  resolvedBy,
				ResolvedAt:  now,
				ExpiresAt:   now.Add(approvedReplayWindow),
			}
			if s.persistFile != "" {
				if err := s.publishReplayGrant(grant); err != nil {
					return rollbackPending(fmt.Errorf("approval: persist exact-replay grant: %w", err))
				}
			}
		}
	}

	// Publication is deliberately last: from this point onward waiters may
	// resume and an exact retry may consume the one-shot authorization.
	req.Status = resolved.Status
	req.ResolvedAt = resolved.ResolvedAt
	req.ResolvedBy = resolved.ResolvedBy
	req.Persisted = resolved.Persisted
	if grantKey != "" {
		s.approvedOnce[grantKey] = grant
	}
	close(req.done)

	// The append above is the durability boundary. Compaction is maintenance
	// only and cannot invalidate a successfully committed resolution.
	if s.persistFile != "" {
		if err := s.rewriteDisk(); err != nil {
			s.logger.Warn("approval: failed to compact persistence file after resolve", "id", id, "error", err)
		}
	}

	return nil
}

// MarkPersisted records that an approved request successfully produced a
// durable allow rule. Callers must invoke this only after the rule transaction
// commits; a persist request by itself is not evidence that authorization was
// actually written.
func (s *Store) MarkPersisted(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.pending[id]
	if !ok {
		return fmt.Errorf("approval: unknown id %q", id)
	}
	if req.Status != StatusApproved {
		return fmt.Errorf("approval: %s is not approved", id)
	}
	req.Persisted = true
	return nil
}

// ConsumeApproved atomically consumes an allow-once approval for the exact
// host-identified tool call. The grant is bound to agent identity and depth,
// session, run ID, tool-call ID, tool name, working directory, params, and
// input by replayKey. A successful grant can never authorize a second retry.
//
// When persistence is enabled, an exclusive consumed marker makes the
// operation one-shot even across concurrently running Store instances. The
// marker is intentionally retained after consumption: failure to clean up
// must fail closed, never recreate authorization.
func (s *Store) ConsumeApproved(call engine.ToolCall) (*ConsumedApproval, bool, error) {
	key := replayKey(call)
	if key == "" {
		return nil, false, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.persistFile != "" {
		grant, consumed, err := s.consumePersistedReplayGrant(key)
		if err != nil || !consumed {
			return nil, consumed, err
		}
		delete(s.approvedOnce, key)
		return &ConsumedApproval{ID: grant.ApprovalID, ResolvedBy: grant.ResolvedBy}, true, nil
	}

	grant, ok := s.approvedOnce[key]
	if !ok {
		return nil, false, nil
	}
	delete(s.approvedOnce, key)
	if time.Now().After(grant.ExpiresAt) {
		return nil, false, nil
	}
	return &ConsumedApproval{ID: grant.ApprovalID, ResolvedBy: grant.ResolvedBy}, true, nil
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
	for key, grant := range s.approvedOnce {
		if time.Now().After(grant.ExpiresAt) {
			delete(s.approvedOnce, key)
		}
	}

	s.cleanAutoApproveCache()
	if s.persistFile != "" {
		s.cleanupPersistedReplayState(olderThan)
	}

	// Prune the on-disk file to match in-memory state.
	if removed > 0 && s.persistFile != "" {
		if err := s.rewriteDisk(); err != nil {
			s.logger.Warn("approval: failed to rewrite persistence file after cleanup", "error", err)
		}
	}

	return removed
}

// autoApproveScopeFor returns a cache key only when all identity fields are
// present. Missing identity fails closed: the approval still resolves the
// pending requests selected by the operator, but it cannot authorize future
// calls through the bulk-approval cache.
func autoApproveScopeFor(call engine.ToolCall) (autoApproveScope, bool) {
	scope := autoApproveScope{
		Agent:   strings.TrimSpace(call.Agent),
		Session: strings.TrimSpace(call.Session),
		RunID:   strings.TrimSpace(call.RunID),
	}
	return scope, scope.Agent != "" && scope.Session != "" && scope.RunID != ""
}

// AutoApproveRun marks one authenticated agent/session/run scope for
// auto-approval until the TTL elapses, but only when that scope has no pending
// approvals. It returns false when the identity is incomplete, the TTL is
// invalid, or a pending request must be resolved first.
func (s *Store) AutoApproveRun(call engine.ToolCall, ttl time.Duration) bool {
	_, installed := s.AutoApproveRunIfNoPending(call, ttl)
	return installed
}

// AutoApproveRunIfNoPending installs one run-scoped auto-approval entry only
// when no pending approval currently exists for that exact scope. When one or
// more requests raced the bulk operation, it returns sorted snapshots for the
// caller to durably resolve and audit before retrying publication.
//
// Used together with CreateOrAutoApproved, this closes both sides of the
// check/create race: either creation wins and must be resolved first, or cache
// publication wins and the creator observes auto-approved state.
func (s *Store) AutoApproveRunIfNoPending(call engine.ToolCall, ttl time.Duration) ([]*Request, bool) {
	scope, ok := autoApproveScopeFor(call)
	if !ok || ttl <= 0 {
		return nil, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	pending := make([]*Request, 0)
	for _, req := range s.pending {
		requestScope, valid := autoApproveScopeFor(req.Call)
		if req.Status != StatusPending || !valid || requestScope != scope {
			continue
		}
		cp := *req
		pending = append(pending, &cp)
	}
	if len(pending) > 0 {
		sort.Slice(pending, func(i, j int) bool {
			if pending[i].CreatedAt.Equal(pending[j].CreatedAt) {
				return pending[i].ID < pending[j].ID
			}
			return pending[i].CreatedAt.Before(pending[j].CreatedAt)
		})
		return pending, false
	}

	s.autoApproveRuns[scope] = time.Now().Add(ttl)
	return nil, true
}

// IsAutoApproved reports whether this exact agent/session/run scope has been
// bulk-approved and the approval has not yet expired.
func (s *Store) IsAutoApproved(call engine.ToolCall) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isAutoApprovedLocked(call)
}

// isAutoApprovedLocked checks one call. The caller must hold s.mu.
func (s *Store) isAutoApprovedLocked(call engine.ToolCall) bool {
	scope, ok := autoApproveScopeFor(call)
	if !ok {
		return false
	}
	expiry, exists := s.autoApproveRuns[scope]
	return exists && time.Now().Before(expiry)
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

			// Journal the timeout before compacting so a concurrent Store cannot
			// resurrect the request from an older pending record.
			if s.persistFile != "" {
				if err := s.appendToDisk(req); err != nil {
					s.logger.Warn("approval: failed to persist expiry", "id", req.ID, "error", err)
				} else if err := s.rewriteDisk(); err != nil {
					s.logger.Warn("approval: failed to compact persistence file after expiry", "id", req.ID, "error", err)
				}
			}
		}
		s.mu.Unlock()
	}
}

// --- Persistence helpers ---

func (s *Store) replayGrantPaths(key string) (data, ready, consumed string) {
	dir := s.persistFile + ".approved-once"
	base := filepath.Join(dir, key)
	return base + ".json", base + ".ready", base + ".consumed"
}

// publishReplayGrant writes the grant data before atomically publishing a
// ready marker. Consumers never read a partially written grant. All files use
// exclusive creation so a reused tool-call identity fails closed.
// Must be called with s.mu held.
func (s *Store) publishReplayGrant(grant replayGrant) error {
	dataPath, readyPath, consumedPath := s.replayGrantPaths(grant.Fingerprint)
	if err := os.MkdirAll(filepath.Dir(dataPath), 0o700); err != nil {
		return fmt.Errorf("create replay grant dir: %w", err)
	}
	for _, path := range []string{readyPath, consumedPath} {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("replay grant identity has already been published or consumed")
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect replay grant state: %w", err)
		}
	}

	encoded, err := json.Marshal(grant)
	if err != nil {
		return fmt.Errorf("marshal replay grant: %w", err)
	}
	if err := writeExclusiveFile(dataPath, append(encoded, '\n')); err != nil {
		return fmt.Errorf("write replay grant: %w", err)
	}
	if err := writeExclusiveFile(readyPath, nil); err != nil {
		_ = os.Remove(dataPath)
		return fmt.Errorf("publish replay grant: %w", err)
	}
	return nil
}

// consumePersistedReplayGrant claims a published grant before reading it.
// O_CREATE|O_EXCL is supported on every Rampart platform and ensures only one
// process can win. The consumed marker remains as a fail-closed tombstone.
// Must be called with s.mu held.
func (s *Store) consumePersistedReplayGrant(key string) (replayGrant, bool, error) {
	dataPath, readyPath, consumedPath := s.replayGrantPaths(key)
	if err := secureExistingApprovalFile(readyPath); err != nil {
		if os.IsNotExist(err) {
			return replayGrant{}, false, nil
		}
		return replayGrant{}, false, fmt.Errorf("inspect replay grant: %w", err)
	}
	if err := secureExistingApprovalFile(dataPath); err != nil {
		return replayGrant{}, false, fmt.Errorf("secure replay grant data: %w", err)
	}

	if err := writeExclusiveFile(consumedPath, []byte(time.Now().UTC().Format(time.RFC3339Nano)+"\n")); err != nil {
		if os.IsExist(err) {
			return replayGrant{}, false, nil
		}
		return replayGrant{}, false, fmt.Errorf("claim replay grant: %w", err)
	}

	encoded, err := readBoundedApprovalFile(dataPath, maxReplayGrantBytes)
	if err != nil {
		return replayGrant{}, false, fmt.Errorf("read claimed replay grant: %w", err)
	}
	var grant replayGrant
	if err := json.Unmarshal(encoded, &grant); err != nil {
		return replayGrant{}, false, fmt.Errorf("decode claimed replay grant: %w", err)
	}
	if grant.Version != 1 || grant.Fingerprint != key || grant.ApprovalID == "" {
		return replayGrant{}, false, fmt.Errorf("claimed replay grant failed integrity validation")
	}

	// The claim is already permanent, so cleanup failures cannot permit reuse.
	for _, path := range []string{readyPath, dataPath} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			s.logger.Warn("approval: failed to clean consumed replay grant", "path", path, "error", err)
		}
	}
	if time.Now().After(grant.ExpiresAt) {
		return replayGrant{}, false, nil
	}
	return grant, true, nil
}

func writeExclusiveFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if err := securefile.OwnerOnly(path); err != nil {
		return fmt.Errorf("secure exclusive file: %w", err)
	}
	if len(data) > 0 {
		if _, err := f.Write(data); err != nil {
			return err
		}
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// Persist the directory entry as well as the file contents. In particular,
	// a consumed replay tombstone must survive a crash; otherwise an approval
	// that was already spent could reappear after reboot on filesystems that had
	// not yet committed the directory metadata.
	if err := filetxn.SyncDir(filepath.Dir(path)); err != nil {
		return err
	}
	ok = true
	return nil
}

// cleanupPersistedReplayState removes expired, unconsumed grants and old
// consumed tombstones. Tombstones live for longer than the pending timeout so
// a stale concurrent Store cannot republish authorization from an old request.
// Malformed or ambiguous state is retained fail-closed for operator review.
// Must be called with s.mu held.
func (s *Store) cleanupPersistedReplayState(olderThan time.Duration) {
	dir := s.persistFile + ".approved-once"
	now := time.Now()
	tombstoneCutoff := now.Add(-(s.timeout + approvedReplayWindow + olderThan))
	err := walkApprovalStateDir(dir, maxPersistedReplayStateEntries, func(entry os.DirEntry) error {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		path := filepath.Join(dir, entry.Name())
		switch {
		case strings.HasSuffix(entry.Name(), ".json"):
			encoded, readErr := readBoundedApprovalFile(path, maxReplayGrantBytes)
			if readErr != nil {
				return nil
			}
			var grant replayGrant
			if json.Unmarshal(encoded, &grant) != nil || grant.Version != 1 || grant.Fingerprint == "" {
				return nil
			}
			if now.After(grant.ExpiresAt) {
				_ = os.Remove(path)
				_ = os.Remove(strings.TrimSuffix(path, ".json") + ".ready")
			}
		case strings.HasSuffix(entry.Name(), ".consumed"):
			info, statErr := entry.Info()
			if statErr != nil || !info.Mode().IsRegular() || !info.ModTime().Before(tombstoneCutoff) {
				return nil
			}
			base := strings.TrimSuffix(path, ".consumed")
			if !approvalStatePathAbsent(base + ".ready") {
				return nil
			}
			if !approvalStatePathAbsent(base + ".json") {
				return nil
			}
			_ = os.Remove(path)
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		s.logger.Warn("approval: cannot fully inspect replay grant dir", "path", dir, "error", err)
	}
}

func approvalStatePathAbsent(path string) bool {
	_, err := os.Lstat(path)
	return os.IsNotExist(err)
}

// walkApprovalStateDir visits replay-state entries in bounded batches. It also
// validates that the opened directory is the same non-symlink directory entry
// inspected before opening, closing the ordinary lstat/open substitution gap.
func walkApprovalStateDir(dir string, maxEntries int, visit func(os.DirEntry) error) error {
	before, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return fmt.Errorf("approval: replay state path is not a non-symlink directory: %s", dir)
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	opened, err := directory.Stat()
	if err != nil {
		return err
	}
	after, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !opened.IsDir() || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return fmt.Errorf("approval: replay state directory changed while opening: %s", dir)
	}

	const batchSize = 128
	visited := 0
	for {
		entries, readErr := directory.ReadDir(batchSize)
		for _, entry := range entries {
			if visited >= maxEntries {
				return fmt.Errorf("approval: replay state directory exceeds %d-entry limit", maxEntries)
			}
			visited++
			if err := visit(entry); err != nil {
				return err
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func readBoundedApprovalFile(path string, maxBytes int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing non-regular approval state file %s", path)
	}
	if err := securefile.OwnerOnly(path); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	after, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return nil, fmt.Errorf("approval state file changed while opening: %s", path)
	}
	if opened.Size() > maxBytes {
		return nil, fmt.Errorf("approval state file %s exceeds %d-byte limit", path, maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("approval state file %s exceeds %d-byte limit", path, maxBytes)
	}
	return data, nil
}

// toRecord converts a Request to its on-disk representation.
func toRecord(req *Request) persistRecord {
	return persistRecord{
		ID:              req.ID,
		Tool:            req.Call.Tool,
		Agent:           req.Call.Agent,
		AgentDepth:      req.Call.AgentDepth,
		Session:         req.Call.Session,
		RunID:           req.Call.RunID,
		ToolCallID:      req.Call.ToolCallID,
		WorkDir:         req.Call.WorkDir,
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
		Tool:       rec.Tool,
		Agent:      rec.Agent,
		AgentDepth: rec.AgentDepth,
		Session:    rec.Session,
		RunID:      rec.RunID,
		ToolCallID: rec.ToolCallID,
		WorkDir:    rec.WorkDir,
		Params:     rec.Params,
		Input:      rec.Input,
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

// readLatestRecordsLocked replays the JSONL journal into its latest record per
// approval ID. The caller must hold the filetxn lock for s.persistFile.
func (s *Store) readLatestRecordsLocked() (map[string]persistRecord, error) {
	records := make(map[string]persistRecord)
	if err := secureExistingApprovalFile(s.persistFile); err != nil {
		if os.IsNotExist(err) {
			return records, nil
		}
		return nil, err
	}
	f, err := os.Open(s.persistFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxApprovalJournalBytes {
		return nil, fmt.Errorf("approval: persistence journal exceeds %d-byte limit", maxApprovalJournalBytes)
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), maxApprovalRecordBytes)
	recordSizes := make(map[string]int64)
	var activeBytes int64
	var scannedBytes int64
	recordCount := 0
	now := time.Now()
	for scanner.Scan() {
		line := scanner.Bytes()
		recordCount++
		if recordCount > maxApprovalJournalRecords {
			return nil, fmt.Errorf("approval: persistence journal exceeds %d-record limit", maxApprovalJournalRecords)
		}
		scannedBytes += int64(len(line) + 1)
		if scannedBytes > maxApprovalJournalBytes {
			return nil, fmt.Errorf("approval: persistence journal exceeds %d-byte limit", maxApprovalJournalBytes)
		}
		if len(line) == 0 {
			continue
		}
		var rec persistRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			s.logger.Warn("approval: skipping malformed persistence record", "error", err)
			continue
		}
		if strings.TrimSpace(rec.ID) == "" {
			s.logger.Warn("approval: skipping persistence record without an id")
			continue
		}
		if rec.Status != "pending" || !now.Before(rec.ExpiresAt) {
			activeBytes -= recordSizes[rec.ID]
			delete(recordSizes, rec.ID)
			delete(records, rec.ID)
			continue
		}
		oldSize, exists := recordSizes[rec.ID]
		if !exists && len(records) >= maxPendingApprovals {
			return nil, ErrTooManyPending
		}
		nextSize := int64(len(line))
		nextActiveBytes := activeBytes - oldSize + nextSize
		if nextActiveBytes > maxRestoredApprovalBytes {
			return nil, fmt.Errorf("approval: live persistence state exceeds %d-byte restore limit", maxRestoredApprovalBytes)
		}
		records[rec.ID] = rec
		recordSizes[rec.ID] = nextSize
		activeBytes = nextActiveBytes
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

// loadFromDisk reads the persistence journal and restores pending
// (non-expired) approvals. Reads use the same cross-process lock as append and
// compaction, so startup cannot observe a half-published replacement.
func (s *Store) loadFromDisk() {
	if err := os.MkdirAll(filepath.Dir(s.persistFile), 0o700); err != nil {
		s.logger.Warn("approval: could not create persistence directory", "path", s.persistFile, "error", err)
		return
	}
	var records map[string]persistRecord
	err := filetxn.WithLock(s.persistFile, func() error {
		var readErr error
		records, readErr = s.readLatestRecordsLocked()
		return readErr
	})
	if err != nil {
		s.logger.Warn("approval: could not read persistence file", "path", s.persistFile, "error", err)
		return
	}

	restored := 0
	for _, rec := range records {
		if restored >= maxPendingApprovals {
			s.logger.Warn("approval: persisted pending limit reached; refusing additional restored requests", "limit", maxPendingApprovals)
			break
		}
		req, ok := fromRecord(rec)
		if !ok {
			continue
		}
		// A crash can occur after an exact-replay grant is durably published
		// but before the pending JSONL is rewritten. Treat either the ready
		// marker or its consumed tombstone as authoritative so the resolved
		// request is never resurrected after restart.
		if key := replayKey(req.Call); key != "" {
			_, readyPath, consumedPath := s.replayGrantPaths(key)
			settled := false
			for _, path := range []string{readyPath, consumedPath} {
				if _, statErr := os.Stat(path); statErr == nil {
					settled = true
					break
				} else if !os.IsNotExist(statErr) {
					s.logger.Warn("approval: cannot inspect replay grant state; skipping pending request fail-closed", "id", req.ID, "path", path, "error", statErr)
					settled = true
					break
				}
			}
			if settled {
				continue
			}
		}
		s.pending[req.ID] = req
		s.startWorker(func() { s.watchExpiry(req) })
		restored++
	}
	if restored > 0 {
		s.logger.Info("approval: restored pending approvals from disk", "count", restored, "path", s.persistFile)
	}
}

// appendToDisk appends a single approval record to the JSONL file.
// Must be called with s.mu held.
func (s *Store) appendToDisk(req *Request) error {
	if err := os.MkdirAll(filepath.Dir(s.persistFile), 0o700); err != nil {
		return fmt.Errorf("approval: create dir: %w", err)
	}

	data, err := json.Marshal(toRecord(req))
	if err != nil {
		return fmt.Errorf("approval: marshal record: %w", err)
	}
	if len(data) > maxApprovalRecordBytes {
		return fmt.Errorf("approval: persistence record exceeds %d-byte limit", maxApprovalRecordBytes)
	}
	return filetxn.WithLock(s.persistFile, func() error {
		created := false
		if statErr := secureExistingApprovalFile(s.persistFile); os.IsNotExist(statErr) {
			created = true
		} else if statErr != nil {
			return fmt.Errorf("approval: inspect persistence file: %w", statErr)
		}
		f, openErr := os.OpenFile(s.persistFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if openErr != nil {
			return fmt.Errorf("approval: open persistence file: %w", openErr)
		}
		if secureErr := securefile.OwnerOnly(s.persistFile); secureErr != nil {
			_ = f.Close()
			if created {
				_ = os.Remove(s.persistFile)
			}
			return fmt.Errorf("approval: secure persistence file: %w", secureErr)
		}
		info, statErr := f.Stat()
		if statErr != nil {
			_ = f.Close()
			return fmt.Errorf("approval: stat persistence file: %w", statErr)
		}
		if info.Size()+int64(len(data))+1 > maxApprovalJournalBytes {
			_ = f.Close()
			return fmt.Errorf("approval: persistence journal would exceed %d-byte limit", maxApprovalJournalBytes)
		}
		if _, writeErr := fmt.Fprintf(f, "%s\n", data); writeErr != nil {
			_ = f.Close()
			return writeErr
		}
		if syncErr := f.Sync(); syncErr != nil {
			_ = f.Close()
			return syncErr
		}
		if closeErr := f.Close(); closeErr != nil {
			return closeErr
		}
		if created {
			return filetxn.SyncDir(filepath.Dir(s.persistFile))
		}
		return nil
	})
}

// rewriteDisk compacts the persistence journal using the latest on-disk state,
// not this Store's potentially stale in-memory snapshot. This preserves
// approvals created by other processes while dropping resolved and expired
// records. Replacement works on Windows as well as Unix.
// Must be called with s.mu held.
func (s *Store) rewriteDisk() error {
	dir := filepath.Dir(s.persistFile)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("approval: create dir: %w", err)
	}
	return filetxn.WithLock(s.persistFile, func() error {
		records, err := s.readLatestRecordsLocked()
		if err != nil {
			return fmt.Errorf("approval: replay persistence journal: %w", err)
		}
		pending := make([]persistRecord, 0, len(records))
		now := time.Now()
		for _, rec := range records {
			if rec.Status == "pending" && now.Before(rec.ExpiresAt) {
				pending = append(pending, rec)
			}
		}
		sort.Slice(pending, func(i, j int) bool {
			if pending[i].CreatedAt.Equal(pending[j].CreatedAt) {
				return pending[i].ID < pending[j].ID
			}
			return pending[i].CreatedAt.Before(pending[j].CreatedAt)
		})

		f, err := os.CreateTemp(dir, ".approvals-*.jsonl.tmp")
		if err != nil {
			return fmt.Errorf("approval: create tmp file: %w", err)
		}
		tmp := f.Name()
		keepTemp := true
		defer func() {
			_ = f.Close()
			if keepTemp {
				_ = os.Remove(tmp)
			}
		}()
		if err := securefile.OwnerOnly(tmp); err != nil {
			return fmt.Errorf("approval: secure tmp file: %w", err)
		}

		enc := json.NewEncoder(f)
		for _, rec := range pending {
			if err := enc.Encode(rec); err != nil {
				return fmt.Errorf("approval: encode record: %w", err)
			}
		}
		if err := f.Sync(); err != nil {
			return fmt.Errorf("approval: sync tmp file: %w", err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("approval: close tmp file: %w", err)
		}
		if err := filetxn.Replace(tmp, s.persistFile); err != nil {
			return fmt.Errorf("approval: replace persistence file: %w", err)
		}
		keepTemp = false
		return nil
	})
}

// secureExistingApprovalFile hardens an existing approval-state file and
// rejects links or special files. os.ErrNotExist is preserved so callers can
// distinguish an absent optional file from a hardening failure.
func secureExistingApprovalFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("refusing non-regular approval state file %s", path)
	}
	return securefile.OwnerOnly(path)
}
