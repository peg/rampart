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
	"bytes"
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
	"github.com/peg/rampart/internal/notify"
	"github.com/peg/rampart/internal/securefile"
)

const (
	// DefaultTimeout is how long a pending approval remains open when the
	// server does not configure an explicit timeout. Explicit run grants use
	// the same default so the displayed and enforced durations do not diverge.
	DefaultTimeout = 2 * time.Minute

	// approvedReplayWindow is intentionally short: an allow-once approval is
	// only useful for the host's immediate retry of the exact tool call.
	approvedReplayWindow = 60 * time.Second
)

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

	// replayIdentity is captured from the original call, never its redacted review.
	replayIdentity string
	redacted       bool
	scopeRedacted  bool
	review         engine.ToolCall

	// ownerScope is a one-way digest binding token-originated approvals.
	ownerScope string

	// runScope is the immutable owner-bound run identity captured at creation.
	// Never recompute authorization scope from the exported Call snapshot,
	// which callers may retain after Create returns.
	runScope    autoApproveScope
	hasRunScope bool

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
	Agent      string
	Session    string
	RunID      string
	OwnerScope string
}

type runScopeMutationKind uint8

const (
	runScopeCreated runScopeMutationKind = iota + 1
	runScopeApproved
	runScopeDenied
	runScopeExpired
	runScopeDeleted
)

const (
	maxRunScopeSnapshotMutations = maxPendingApprovals * 8
	maxActiveRunScopeSnapshots   = 64
)

type runScopeMutation struct {
	kind  runScopeMutationKind
	id    string
	actor *RunScopeSnapshot
}

// RunScopeSnapshot is a store-bound, single-use authorization transaction for
// one immutable agent/session/run/credential-owner scope. Pending contains
// copies safe for callers to inspect; all security state remains unexported.
type RunScopeSnapshot struct {
	Pending []*Request

	store     *Store
	scope     autoApproveScope
	reviewed  map[string]struct{}
	mutations []runScopeMutation
	expiresAt time.Time
	invalid   bool
	consumed  bool
}

// RunApprovalCommit is proof that this snapshot, rather than another
// resolver, committed one approval transition in the Store.
type RunApprovalCommit struct {
	ID string
}

// persistRecord is the on-disk representation of an approval request.
// Uses flat string fields to avoid circular JSON dependencies on engine types.
type persistRecord struct {
	Version         int            `json:"version,omitempty"`
	Fingerprint     string         `json:"fingerprint,omitempty"`
	Replay          bool           `json:"replay,omitempty"`
	Redacted        bool           `json:"redacted,omitempty"`
	ScopeRedacted   bool           `json:"run_scope_redacted,omitempty"`
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
	OwnerScope      string         `json:"owner_scope,omitempty"`
}

const scopedPendingStatus = "pending-v2"

// Store manages pending approval requests.
type Store struct {
	identityKey     [sha256.Size]byte
	identityErr     error
	mu              sync.Mutex
	pending         map[string]*Request
	approvedOnce    map[string]replayGrant // exact call/owner key -> one-shot grant
	autoApproveRuns map[autoApproveScope]time.Time
	activeRunScopes map[autoApproveScope]*RunScopeSnapshot
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
		activeRunScopes: make(map[autoApproveScope]*RunScopeSnapshot),
		timeout:         DefaultTimeout,
		stop:            make(chan struct{}),
		logger:          slog.Default(),
	}
	for _, opt := range opts {
		opt(s)
	}

	s.identityErr = s.initializeIdentityKey()
	if s.identityErr != nil {
		s.logger.Error("approval: identity state unavailable; refusing authorization", "error", s.identityErr)
	}

	// Load persisted approvals only after establishing the keyed identity.
	if s.persistFile != "" && s.identityErr == nil {
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

func ownerScopeDigest(scope string) string {
	if strings.TrimSpace(scope) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("approval-owner-v1\x00" + scope))
	return hex.EncodeToString(sum[:])
}

// ownerBoundKey domain-separates token-owned state from v1 action-only replay
// paths. Older binaries therefore cannot consume a scoped grant unscoped.
func ownerBoundKey(key, ownerScope string) string {
	if key == "" || ownerScope == "" {
		return key
	}
	sum := sha256.Sum256([]byte("approval-replay-v2\x00" + key + "\x00" + ownerScope))
	return "v2-" + hex.EncodeToString(sum[:])
}

func replayGrantVersion(key string) int {
	if strings.HasPrefix(key, "v3-") {
		return 3
	}
	if strings.HasPrefix(key, "v2-") {
		return 2
	}
	return 1
}

// Create adds a new pending approval and returns it.
// The caller should wait on request.Done() for resolution.
// Returns nil and an error if the pending approval limit has been reached.
//
// A still-pending request with the same stable host identity is returned.
// Calls without a stable host-provided tool-call ID are never deduplicated.
func (s *Store) Create(call engine.ToolCall, decision engine.Decision) (*Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createLocked(call, decision, "")
}

// CreateOrAutoApproved atomically checks the run-scoped auto-approval cache
// and, only when no live entry exists, enqueues a pending approval. Keeping
// both operations under one lock prevents a bulk-approval publication from
// racing a stale IsAutoApproved check and leaving an orphan pending request.
// A non-empty owner scope binds pending and replay state to that caller.
func (s *Store) CreateOrAutoApproved(call engine.ToolCall, decision engine.Decision, ownerScope string) (*Request, bool, error) {
	req, _, autoApproved, err := s.CreateOrAutoApprovedWithExpiry(call, decision, ownerScope)
	return req, autoApproved, err
}

// CreateOrAutoApprovedWithExpiry is CreateOrAutoApproved plus the exact expiry
// of a run grant observed by this call. The expiry is zero when the request is
// enqueued instead. Callers that disclose grant lifetime must use this value
// rather than reconstructing a fresh timeout after the cache lookup.
func (s *Store) CreateOrAutoApprovedWithExpiry(
	call engine.ToolCall,
	decision engine.Decision,
	ownerScope string,
) (*Request, time.Time, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.checkIdentityKey(); err != nil {
		return nil, time.Time{}, false, err
	}
	ownerScope = ownerScopeDigest(ownerScope)
	if expiresAt, ok := s.autoApprovalExpiryLocked(call, ownerScope); ok {
		return nil, expiresAt, true, nil
	}
	req, err := s.createLocked(call, decision, ownerScope)
	return req, time.Time{}, false, err
}

// createLocked enqueues one request. The caller must hold s.mu.
func (s *Store) createLocked(call engine.ToolCall, decision engine.Decision, ownerScope string) (*Request, error) {
	if s.closed {
		return nil, ErrStoreClosed
	}

	if err := s.checkIdentityKey(); err != nil {
		return nil, err
	}
	now := time.Now()
	call, encoded, err := snapshotCall(call)
	if err != nil {
		return nil, fmt.Errorf("approval: cannot snapshot action: %w", err)
	}
	key := s.keyedIdentity(ownerBoundKey(dedupKey(call), ownerScope))
	review, redacted, err := redactCallSnapshot(call, encoded)
	if err != nil {
		return nil, fmt.Errorf("approval: cannot snapshot action: %w", err)
	}

	// Stable invocation identity remains singular for its full pending lifetime.
	if key != "" {
		for _, req := range s.pending {
			if req.Status == StatusPending && req.dedupKey == key && now.Before(req.ExpiresAt) {
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
		ID:            ulid.Make().String(),
		Call:          review,
		Decision:      decision,
		Status:        StatusPending,
		CreatedAt:     now,
		ExpiresAt:     now.Add(s.timeout),
		dedupKey:      key,
		redacted:      redacted,
		scopeRedacted: runScopeChangedByRedaction(call, review),
		ownerScope:    ownerScope,
		done:          make(chan struct{}),
	}
	req.review = review
	req.Call = req.reviewCopy()
	if replayKey(call) != "" {
		req.replayIdentity = key
	}
	req.Decision.Message = notify.SanitizeCommand(decision.Message)
	req.Decision.MatchedPolicies = append([]string(nil), decision.MatchedPolicies...)
	for i := range req.Decision.MatchedPolicies {
		req.Decision.MatchedPolicies[i] = notify.SanitizeCommand(req.Decision.MatchedPolicies[i])
	}
	if scope, valid := autoApproveScopeFor(call, ownerScope); valid && !req.scopeRedacted {
		req.runScope = scope
		req.hasRunScope = true
	}

	s.pending[req.ID] = req

	// Persist to disk.
	if s.persistFile != "" {
		if err := s.appendToDisk(req); err != nil {
			delete(s.pending, req.ID)
			return nil, fmt.Errorf("approval: persist new approval: %w", err)
		}
	}
	s.recordRunScopeMutationLocked(req, runScopeCreated, nil)

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
	return s.resolveBeforePublishLocked(id, approved, resolvedBy, beforePublish, nil)
}

// ResolveBeforePublishForRunScopeSnapshot commits one approval through the
// active store-bound run snapshot and returns a commit receipt for API/audit
// reporting. Grant publication trusts the Store's internal actor-tagged
// mutation log, never caller-supplied IDs.
func (s *Store) ResolveBeforePublishForRunScopeSnapshot(
	snapshot *RunScopeSnapshot,
	id string,
	resolvedBy string,
	beforePublish func(*Request) error,
) (*RunApprovalCommit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.runScopeSnapshotActiveLocked(snapshot) {
		return nil, fmt.Errorf("approval: run-scope snapshot is stale, consumed, or belongs to another store")
	}
	if !time.Now().Before(snapshot.expiresAt) {
		return nil, fmt.Errorf("approval: run-scope snapshot authorization window expired")
	}
	req, ok := s.pending[id]
	if !ok || !req.hasRunScope || req.runScope != snapshot.scope {
		return nil, fmt.Errorf("approval: %q does not belong to the active run-scope snapshot", id)
	}
	if !time.Now().Before(req.ExpiresAt) {
		return nil, fmt.Errorf("approval: %q expired before resolution publication", id)
	}
	if err := s.resolveBeforePublishLocked(id, true, resolvedBy, beforePublish, snapshot); err != nil {
		return nil, err
	}
	return &RunApprovalCommit{ID: id}, nil
}

// resolveBeforePublishLocked implements the durable transition and observable
// publication boundary. The caller must hold s.mu. actor is non-nil only for
// an approval committed by the matching active run-scope transaction.
func (s *Store) resolveBeforePublishLocked(
	id string,
	approved bool,
	resolvedBy string,
	beforePublish func(*Request) error,
	actor *RunScopeSnapshot,
) error {

	if err := s.checkIdentityKey(); err != nil {
		return err
	}
	req, ok := s.pending[id]
	if !ok {
		return fmt.Errorf("approval: unknown id %q", id)
	}

	if req.Status != StatusPending {
		return fmt.Errorf("approval: %s is already %s", id, req.Status)
	}
	if !time.Now().Before(req.ExpiresAt) {
		return fmt.Errorf("approval: %s expired before resolution publication", id)
	}
	if s.persistFile != "" {
		if err := secureExistingApprovalFile(s.persistFile); err != nil {
			return fmt.Errorf("approval: secure persistence journal: %w", err)
		}
	}

	now := time.Now()
	resolved := *req
	resolved.Call = req.reviewCopy()
	if approved {
		resolved.Status = StatusApproved
	} else {
		resolved.Status = StatusDenied
	}
	resolved.ResolvedAt = now
	resolvedBy = notify.SanitizeCommand(resolvedBy)
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
	if actor != nil && !time.Now().Before(actor.expiresAt) {
		return rollbackPending(fmt.Errorf("approval: run-scope snapshot authorization window expired before resolution publication"))
	}
	if !time.Now().Before(req.ExpiresAt) {
		return rollbackPending(fmt.Errorf("approval: %s expired before resolution publication", id))
	}

	var grant replayGrant
	grantKey := ""
	if approved {
		grantKey = req.replayIdentity
		if grantKey != "" {
			grant = replayGrant{
				Version:     replayGrantVersion(grantKey),
				ApprovalID:  req.ID,
				Fingerprint: grantKey,
				ResolvedBy:  resolvedBy,
				ResolvedAt:  now,
				ExpiresAt:   now.Add(approvedReplayWindow),
			}
			if actor != nil && actor.expiresAt.Before(grant.ExpiresAt) {
				grant.ExpiresAt = actor.expiresAt
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
	if approved {
		s.recordRunScopeMutationLocked(req, runScopeApproved, actor)
	} else {
		s.recordRunScopeMutationLocked(req, runScopeDenied, actor)
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
	return s.ConsumeApprovedFor(call, "")
}

// ConsumeApprovedFor binds exact replay to an opaque caller-owned scope.
func (s *Store) ConsumeApprovedFor(call engine.ToolCall, ownerScope string) (*ConsumedApproval, bool, error) {
	if err := s.checkIdentityKey(); err != nil {
		return nil, false, err
	}
	call, _, err := snapshotCall(call)
	if err != nil {
		return nil, false, fmt.Errorf("approval: cannot snapshot replay: %w", err)
	}
	key := s.keyedIdentity(ownerBoundKey(replayKey(call), ownerScopeDigest(ownerScope)))
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

// reviewCopy returns a deep copy of the JSON-compatible snapshot established
// at creation or journal decoding. No mutable exported map is authoritative.
func (r *Request) reviewCopy() engine.ToolCall {
	call := r.review
	call.Params, call.Input = cloneReviewMap(call.Params), cloneReviewMap(call.Input)
	return call
}

// HasRedactions reports whether a literal learned rule would differ from the original action.
func (r *Request) HasRedactions() bool { return r.redacted }

// CanAuthorizeRun reports whether the displayed run identity preserves the
// original scope and can support explicit future-run authorization.
func (r *Request) CanAuthorizeRun() bool { return r.hasRunScope }

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
	cp.Call = req.reviewCopy()
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
			cp.Call = req.reviewCopy()
			result = append(result, &cp)
		}
	}
	// Sort by creation time (oldest first) for deterministic ordering.
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	return result
}

// BeginRunScopeSnapshot atomically validates and captures every currently
// pending approval for one exact owner-bound run. Mutations committed after
// this boundary are recorded on the returned store-bound token until it is
// either published or aborted.
func (s *Store) BeginRunScopeSnapshot(call engine.ToolCall, reviewedIDs []string, ttl time.Duration) (*RunScopeSnapshot, error) {
	if len(reviewedIDs) == 0 {
		return nil, fmt.Errorf("approval: run scope requires reviewed approval ids")
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("approval: run scope requires a positive authorization window")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.pruneExpiredRunScopeSnapshotsLocked(now)

	reviewed := make(map[string]struct{}, len(reviewedIDs))
	matching := make([]*Request, 0, len(reviewedIDs))
	var scope autoApproveScope
	for index, rawID := range reviewedIDs {
		id := strings.TrimSpace(rawID)
		if id == "" {
			return nil, fmt.Errorf("approval: run scope contains an empty approval id")
		}
		if _, duplicate := reviewed[id]; duplicate {
			return nil, fmt.Errorf("approval: run scope contains duplicate approval id %q", id)
		}
		reviewed[id] = struct{}{}

		req, ok := s.pending[id]
		if !ok || req.Status != StatusPending || !now.Before(req.ExpiresAt) {
			return nil, fmt.Errorf("approval: %q is no longer pending", id)
		}
		if !req.hasRunScope {
			return nil, fmt.Errorf("approval: %q has incomplete run identity", id)
		}
		if index == 0 {
			scope = req.runScope
			if scope.Agent != strings.TrimSpace(call.Agent) ||
				scope.Session != strings.TrimSpace(call.Session) ||
				scope.RunID != strings.TrimSpace(call.RunID) {
				return nil, fmt.Errorf("approval: %q does not belong to the requested run identity", id)
			}
		} else if req.runScope != scope {
			return nil, fmt.Errorf("approval: run scope ids span multiple identities or credential owners")
		}
		cp := *req
		cp.Call = req.reviewCopy()
		matching = append(matching, &cp)
	}

	for _, req := range s.pending {
		if req.Status != StatusPending || !req.hasRunScope || req.runScope != scope {
			continue
		}
		if !now.Before(req.ExpiresAt) {
			return nil, fmt.Errorf("approval: run scope contains expired pending approval %q", req.ID)
		}
		if _, selected := reviewed[req.ID]; !selected {
			return nil, fmt.Errorf("approval: run scope omitted pending approval %q", req.ID)
		}
	}
	if active := s.activeRunScopes[scope]; active != nil {
		return nil, fmt.Errorf("approval: another run-scope authorization is already in progress")
	}
	if expiry, exists := s.autoApproveRuns[scope]; exists {
		if time.Now().Before(expiry) {
			return nil, fmt.Errorf("approval: run scope already has active future-call authority")
		}
		delete(s.autoApproveRuns, scope)
	}
	if len(s.activeRunScopes) >= maxActiveRunScopeSnapshots {
		return nil, fmt.Errorf("approval: too many run-scope authorizations are already in progress")
	}

	snapshot := &RunScopeSnapshot{
		Pending:   matching,
		store:     s,
		scope:     scope,
		reviewed:  reviewed,
		expiresAt: now.Add(ttl),
	}
	s.activeRunScopes[scope] = snapshot
	return snapshot, nil
}

// AbortRunScopeSnapshot releases an unpublished snapshot. It is idempotent;
// successful publication consumes and releases the token first.
func (s *Store) AbortRunScopeSnapshot(snapshot *RunScopeSnapshot) {
	if snapshot == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if snapshot.store != s || snapshot.consumed || s.activeRunScopes[snapshot.scope] != snapshot {
		return
	}
	delete(s.activeRunScopes, snapshot.scope)
	snapshot.consumed = true
}

func (s *Store) runScopeSnapshotActiveLocked(snapshot *RunScopeSnapshot) bool {
	return snapshot != nil && snapshot.store == s && !snapshot.consumed && s.activeRunScopes[snapshot.scope] == snapshot
}

func (s *Store) pruneExpiredRunScopeSnapshotsLocked(now time.Time) {
	for scope, snapshot := range s.activeRunScopes {
		if snapshot != nil && !snapshot.consumed && now.Before(snapshot.expiresAt) {
			continue
		}
		delete(s.activeRunScopes, scope)
		if snapshot != nil {
			snapshot.consumed = true
		}
	}
}

func (s *Store) recordRunScopeMutationLocked(req *Request, kind runScopeMutationKind, actor *RunScopeSnapshot) {
	if req == nil || !req.hasRunScope {
		return
	}
	snapshot := s.activeRunScopes[req.runScope]
	if snapshot == nil || snapshot.invalid {
		return
	}
	if len(snapshot.mutations) >= maxRunScopeSnapshotMutations {
		snapshot.invalid = true
		return
	}
	snapshot.mutations = append(snapshot.mutations, runScopeMutation{kind: kind, id: req.ID, actor: actor})
}

// Done returns a channel that's closed when the request is resolved.
func (r *Request) Done() <-chan struct{} {
	return r.done
}

// OwnerScopeID is an opaque store-owned identifier used only to keep bulk
// authorization within the caller boundary that created this request.
func (r *Request) OwnerScopeID() string {
	return r.ownerScope
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
			s.recordRunScopeMutationLocked(req, runScopeDeleted, nil)
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
func autoApproveScopeFor(call engine.ToolCall, ownerScope string) (autoApproveScope, bool) {
	scope := autoApproveScope{
		Agent:      strings.TrimSpace(call.Agent),
		Session:    strings.TrimSpace(call.Session),
		RunID:      strings.TrimSpace(call.RunID),
		OwnerScope: ownerScope,
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
	return s.autoApproveRunIfNoPending(call, "", ttl)
}

// AutoApproveRunIfNoPendingForRequest installs only the owner scope carried by
// a request the operator explicitly selected for bulk resolution.
func (s *Store) AutoApproveRunIfNoPendingForRequest(call engine.ToolCall, source *Request, ttl time.Duration) ([]*Request, bool) {
	pending, _, installed, _ := s.AutoApproveRunBeforePublishForRequest(call, source, ttl, nil)
	return pending, installed
}

// AutoApproveRunBeforePublishForRunScopeSnapshot publishes future authority
// only when every mutation since BeginRunScopeSnapshot is accounted for. New
// pending requests are returned for caller review/audit; any denial, expiry,
// deletion, or approval by another resolver invalidates publication.
func (s *Store) AutoApproveRunBeforePublishForRunScopeSnapshot(
	snapshot *RunScopeSnapshot,
	beforePublish func(time.Time) error,
) ([]*Request, time.Time, bool, error) {
	if snapshot == nil {
		return nil, time.Time{}, false, fmt.Errorf("approval: invalid run-scope publication request")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.runScopeSnapshotActiveLocked(snapshot) {
		return nil, time.Time{}, false, fmt.Errorf("approval: run-scope snapshot is stale, consumed, or belongs to another store")
	}
	if snapshot.invalid {
		return nil, time.Time{}, false, fmt.Errorf("approval: run-scope mutation log exceeded its safety bound")
	}
	if !time.Now().Before(snapshot.expiresAt) {
		return nil, time.Time{}, false, fmt.Errorf("approval: run-scope snapshot authorization window expired")
	}

	created := make(map[string]struct{})
	committed := make(map[string]struct{})
	for _, mutation := range snapshot.mutations {
		switch mutation.kind {
		case runScopeCreated:
			created[mutation.id] = struct{}{}
		case runScopeApproved:
			if mutation.actor != snapshot {
				return nil, time.Time{}, false, fmt.Errorf("approval: %q was approved outside the active run-scope transaction", mutation.id)
			}
			committed[mutation.id] = struct{}{}
		case runScopeDenied:
			return nil, time.Time{}, false, fmt.Errorf("approval: %q was denied after the run-scope snapshot", mutation.id)
		case runScopeExpired:
			return nil, time.Time{}, false, fmt.Errorf("approval: %q expired after the run-scope snapshot", mutation.id)
		case runScopeDeleted:
			return nil, time.Time{}, false, fmt.Errorf("approval: %q was deleted after the run-scope snapshot", mutation.id)
		default:
			return nil, time.Time{}, false, fmt.Errorf("approval: unknown run-scope mutation")
		}
	}
	for id := range snapshot.reviewed {
		if _, ok := committed[id]; !ok {
			if req, exists := s.pending[id]; exists && req.Status == StatusPending && req.hasRunScope && req.runScope == snapshot.scope {
				continue
			}
			return nil, time.Time{}, false, fmt.Errorf("approval: reviewed approval %q was not committed by the active run-scope transaction", id)
		}
	}

	pending := make([]*Request, 0)
	for _, req := range s.pending {
		if req.Status != StatusPending || !req.hasRunScope || req.runScope != snapshot.scope {
			continue
		}
		if _, reviewed := snapshot.reviewed[req.ID]; !reviewed {
			if _, arrivedAfterSnapshot := created[req.ID]; !arrivedAfterSnapshot {
				return nil, time.Time{}, false, fmt.Errorf("approval: unaccounted pending approval %q in run scope", req.ID)
			}
		}
		cp := *req
		cp.Call = req.reviewCopy()
		pending = append(pending, &cp)
	}
	if len(pending) > 0 {
		sort.Slice(pending, func(i, j int) bool {
			if pending[i].CreatedAt.Equal(pending[j].CreatedAt) {
				return pending[i].ID < pending[j].ID
			}
			return pending[i].CreatedAt.Before(pending[j].CreatedAt)
		})
		return pending, time.Time{}, false, nil
	}

	expiresAt := snapshot.expiresAt
	if beforePublish != nil {
		if err := beforePublish(expiresAt); err != nil {
			return nil, time.Time{}, false, fmt.Errorf("approval: required run-grant pre-publication step: %w", err)
		}
	}
	if !time.Now().Before(expiresAt) {
		return nil, time.Time{}, false, fmt.Errorf("approval: run grant expired before publication")
	}
	s.autoApproveRuns[snapshot.scope] = expiresAt

	delete(s.activeRunScopes, snapshot.scope)
	snapshot.consumed = true
	return nil, expiresAt, true, nil
}

// AutoApproveRunBeforePublishForRequest installs only the owner scope carried
// by a request the operator explicitly selected. The callback runs under the
// Store lock before the cache entry is installed, so callers can require a
// durable audit record without opening a create/publication race.
func (s *Store) AutoApproveRunBeforePublishForRequest(
	call engine.ToolCall,
	source *Request,
	ttl time.Duration,
	beforePublish func(time.Time) error,
) ([]*Request, time.Time, bool, error) {
	if source == nil || !source.hasRunScope {
		return nil, time.Time{}, false, nil
	}
	return s.autoApproveRunBeforePublish(call, source.ownerScope, ttl, beforePublish)
}

func (s *Store) autoApproveRunIfNoPending(call engine.ToolCall, ownerScope string, ttl time.Duration) ([]*Request, bool) {
	pending, _, installed, _ := s.autoApproveRunBeforePublish(call, ownerScope, ttl, nil)
	return pending, installed
}

func (s *Store) autoApproveRunBeforePublish(
	call engine.ToolCall,
	ownerScope string,
	ttl time.Duration,
	beforePublish func(time.Time) error,
) ([]*Request, time.Time, bool, error) {
	scope, ok := autoApproveScopeFor(call, ownerScope)
	if !ok || ttl <= 0 {
		return nil, time.Time{}, false, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeRunScopes[scope] != nil {
		return nil, time.Time{}, false, fmt.Errorf("approval: run-scope authorization is already in progress")
	}

	pending := make([]*Request, 0)
	for _, req := range s.pending {
		if req.Status != StatusPending || !req.hasRunScope || req.runScope != scope {
			continue
		}
		cp := *req
		cp.Call = req.reviewCopy()
		pending = append(pending, &cp)
	}
	if len(pending) > 0 {
		sort.Slice(pending, func(i, j int) bool {
			if pending[i].CreatedAt.Equal(pending[j].CreatedAt) {
				return pending[i].ID < pending[j].ID
			}
			return pending[i].CreatedAt.Before(pending[j].CreatedAt)
		})
		return pending, time.Time{}, false, nil
	}

	expiresAt := time.Now().Add(ttl)
	if beforePublish != nil {
		if err := beforePublish(expiresAt); err != nil {
			return nil, time.Time{}, false, fmt.Errorf("approval: required run-grant pre-publication step: %w", err)
		}
	}
	if !time.Now().Before(expiresAt) {
		return nil, time.Time{}, false, fmt.Errorf("approval: run grant expired before publication")
	}
	s.autoApproveRuns[scope] = expiresAt
	return nil, expiresAt, true, nil
}

// IsAutoApproved reports whether this exact agent/session/run scope has been
// bulk-approved and the approval has not yet expired.
func (s *Store) IsAutoApproved(call engine.ToolCall) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isAutoApprovedLocked(call, "")
}

// isAutoApprovedLocked checks one call. The caller must hold s.mu.
func (s *Store) isAutoApprovedLocked(call engine.ToolCall, ownerScope string) bool {
	_, ok := s.autoApprovalExpiryLocked(call, ownerScope)
	return ok
}

func (s *Store) autoApprovalExpiryLocked(call engine.ToolCall, ownerScope string) (time.Time, bool) {
	scope, ok := autoApproveScopeFor(call, ownerScope)
	if !ok {
		return time.Time{}, false
	}
	expiry, exists := s.autoApproveRuns[scope]
	if !exists {
		return time.Time{}, false
	}
	if !time.Now().Before(expiry) {
		delete(s.autoApproveRuns, scope)
		return time.Time{}, false
	}
	return expiry, true
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
			s.recordRunScopeMutationLocked(req, runScopeExpired, nil)
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
	if grant.Version != replayGrantVersion(key) || grant.Fingerprint != key || grant.ApprovalID == "" {
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
			if json.Unmarshal(encoded, &grant) != nil || grant.Fingerprint == "" || grant.Version != replayGrantVersion(grant.Fingerprint) {
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
	call := req.review
	status := req.Status.String()
	if status == "pending" {
		status = privatePendingStatus
	}
	return persistRecord{
		Version:         3,
		Fingerprint:     req.dedupKey,
		Replay:          req.replayIdentity != "",
		Redacted:        req.redacted,
		ScopeRedacted:   req.scopeRedacted,
		ID:              req.ID,
		Tool:            call.Tool,
		Agent:           call.Agent,
		AgentDepth:      call.AgentDepth,
		Session:         call.Session,
		RunID:           call.RunID,
		ToolCallID:      call.ToolCallID,
		WorkDir:         call.WorkDir,
		Command:         call.Command(),
		Params:          call.Params,
		Input:           call.Input,
		MatchedPolicies: req.Decision.MatchedPolicies,
		Message:         req.Decision.Message,
		CreatedAt:       req.CreatedAt,
		ExpiresAt:       req.ExpiresAt,
		ResolvedAt:      req.ResolvedAt,
		ResolvedBy:      req.ResolvedBy,
		Status:          status,
		Persisted:       req.Persisted,
		OwnerScope:      req.ownerScope,
	}
}

// fromRecord reconstructs an in-memory Request from a persist record.
// Returns (nil, false) if the record should be discarded (expired or non-pending).
func fromRecord(rec persistRecord) (*Request, bool) {
	if !pendingRecordLive(rec, time.Now()) {
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
		ID:         rec.ID,
		Call:       call,
		Decision:   decision,
		Status:     StatusPending,
		CreatedAt:  rec.CreatedAt,
		ExpiresAt:  rec.ExpiresAt,
		dedupKey:   ownerBoundKey(dedupKey(call), rec.OwnerScope),
		ownerScope: rec.OwnerScope,
		done:       make(chan struct{}),
	}
	req.review = call
	req.Call = req.reviewCopy()
	if rec.Version == 3 {
		req.dedupKey = rec.Fingerprint
		req.redacted = rec.Redacted
		req.scopeRedacted = rec.ScopeRedacted
		if rec.Replay {
			req.replayIdentity = rec.Fingerprint
		}
	} else if replayKey(call) != "" {
		req.replayIdentity = req.dedupKey
	}
	if scope, valid := autoApproveScopeFor(call, rec.OwnerScope); valid && !req.scopeRedacted {
		req.runScope = scope
		req.hasRunScope = true
	}
	return req, true
}

func pendingRecordLive(rec persistRecord, now time.Time) bool {
	switch rec.Status {
	case privatePendingStatus:
		if rec.Version != 3 || !now.Before(rec.ExpiresAt) {
			return false
		}
		if rec.Fingerprint == "" {
			return !rec.Replay
		}
		_, err := hex.DecodeString(strings.TrimPrefix(rec.Fingerprint, "v3-"))
		return strings.HasPrefix(rec.Fingerprint, "v3-") && len(rec.Fingerprint) == 3+sha256.Size*2 && err == nil
	case "pending":
		return rec.OwnerScope == "" && now.Before(rec.ExpiresAt)
	case scopedPendingStatus:
		_, err := hex.DecodeString(rec.OwnerScope)
		return len(rec.OwnerScope) == sha256.Size*2 && err == nil && now.Before(rec.ExpiresAt)
	default:
		return false
	}
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
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.UseNumber()
		if err := decoder.Decode(&rec); err != nil {
			s.logger.Warn("approval: skipping malformed persistence record", "error", err)
			continue
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			s.logger.Warn("approval: skipping persistence record with trailing data")
			continue
		}
		if strings.TrimSpace(rec.ID) == "" {
			s.logger.Warn("approval: skipping persistence record without an id")
			continue
		}
		if !pendingRecordLive(rec, now) {
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
		if rec.Version != 3 {
			legacy, ok := fromRecord(rec)
			if !ok {
				return nil, fmt.Errorf("approval: cannot migrate pending identity")
			}
			legacy.dedupKey = s.keyedIdentity(legacy.dedupKey)
			legacy.replayIdentity = s.keyedIdentity(legacy.replayIdentity)
			var redactErr error
			legacy.Call, legacy.redacted, redactErr = redactedCall(legacy.review)
			legacy.scopeRedacted = runScopeChangedByRedaction(legacy.review, legacy.Call)
			legacy.review = legacy.Call
			if redactErr != nil {
				return nil, redactErr
			}
			legacy.Decision.Message = notify.SanitizeCommand(legacy.Decision.Message)
			for i := range legacy.Decision.MatchedPolicies {
				legacy.Decision.MatchedPolicies[i] = notify.SanitizeCommand(legacy.Decision.MatchedPolicies[i])
			}
			rec = toRecord(legacy)
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
	if err := s.rewriteDisk(); err != nil {
		s.identityErr = fmt.Errorf("approval: pending migration failed: %w", err)
		s.logger.Error("approval: refusing authorization after migration failure", "error", s.identityErr)
		return
	}
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
		if key := req.replayIdentity; key != "" {
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
		s.recordRunScopeMutationLocked(req, runScopeCreated, nil)
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
			if pendingRecordLive(rec, now) {
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
