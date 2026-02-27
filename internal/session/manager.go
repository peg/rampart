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

package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
	"unicode"
)

// Manager handles loading, updating, and cleanup of session state files.
// Each Manager is bound to a specific session ID; use a zero-sessionID Manager
// (e.g. NewManager(dir, "", logger)) solely for Cleanup calls.
type Manager struct {
	dir       string
	sessionID string
	logger    *slog.Logger
}

// NewManager creates a Manager for the given directory and session.
// dir is the base directory for session state files (typically
// ~/.rampart/session-state/). If dir is empty, the platform default
// (~/.rampart/session-state/) is used automatically on first I/O.
func NewManager(dir, sessionID string, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		dir:       dir,
		sessionID: sessionID,
		logger:    logger,
	}
}

// resolveDir returns the effective state directory, creating it if necessary.
func (m *Manager) resolveDir() (string, error) {
	d := m.dir
	if d == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("session: home dir: %w", err)
		}
		d = filepath.Join(home, ".rampart", "session-state")
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", fmt.Errorf("session: mkdir %s: %w", d, err)
	}
	return d, nil
}

// validateSessionID checks that sessionID contains only safe characters.
// This prevents path traversal attacks via crafted session IDs like "../../etc/cron.d/evil".
func validateSessionID(id string) error {
	if id == "" {
		return errors.New("session: sessionID is required")
	}
	for _, r := range id {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' {
			return fmt.Errorf("session: invalid character %q in session_id", r)
		}
	}
	return nil
}

// statePath returns the path for the current session's JSON file.
func (m *Manager) statePath() (string, error) {
	if err := validateSessionID(m.sessionID); err != nil {
		return "", err
	}
	d, err := m.resolveDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, m.sessionID+".json"), nil
}

// load reads and deserialises the session state file.
// Returns a new empty State if the file does not yet exist.
func (m *Manager) load(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		now := time.Now().UTC()
		return &State{
			SessionID:        m.sessionID,
			CreatedAt:        now,
			LastActive:       now,
			PendingAsks:      make(map[string]PendingAsk),
			SessionApprovals: make(map[string]ApprovalRecord),
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("session: read %s: %w", path, err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("session: parse %s: %w", path, err)
	}
	// Ensure maps are non-nil after unmarshal.
	if s.PendingAsks == nil {
		s.PendingAsks = make(map[string]PendingAsk)
	}
	if s.SessionApprovals == nil {
		s.SessionApprovals = make(map[string]ApprovalRecord)
	}
	return &s, nil
}

// save serialises state and writes it atomically via a temp-file + rename.
// If the marshalled payload exceeds maxStateSize the oldest PendingAsks
// entries are trimmed first, then the oldest SessionApprovals entries.
func (m *Manager) save(path string, s *State) error {
	s.LastActive = time.Now().UTC()

	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("session: marshal state: %w", err)
	}

	// Trim loop until under size limit.
	trimmed := false
	for len(data) > maxStateSize && (len(s.PendingAsks) > 0 || len(s.SessionApprovals) > 0) {
		m.trimOldest(s)
		data, err = json.Marshal(s)
		if err != nil {
			return fmt.Errorf("session: marshal trimmed state: %w", err)
		}
		trimmed = true
	}
	if trimmed {
		m.logger.Debug("session: state file exceeded size limit, trimmed old entries",
			"session_id", s.SessionID,
			"size_bytes", len(data),
		)
	}

	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, ".session-*.json.tmp")
	if err != nil {
		return fmt.Errorf("session: create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("session: write temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("session: close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("session: rename temp file: %w", err)
	}
	return nil
}

// trimOldest removes the single oldest PendingAsk or SessionApproval to
// reduce file size. Called repeatedly when the file is over-size.
func (m *Manager) trimOldest(s *State) {
	// Prefer to remove pending asks (oldest first).
	if len(s.PendingAsks) > 0 {
		var oldestKey string
		var oldestTime time.Time
		for k, v := range s.PendingAsks {
			if oldestKey == "" || v.AskedAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.AskedAt
			}
		}
		delete(s.PendingAsks, oldestKey)
		return
	}
	// Fall back to removing the oldest session approval.
	if len(s.SessionApprovals) > 0 {
		var oldestKey string
		var oldestTime time.Time
		for k, v := range s.SessionApprovals {
			if oldestKey == "" || v.FirstApproved.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.FirstApproved
			}
		}
		delete(s.SessionApprovals, oldestKey)
	}
}

// RecordAsk records a pending ask for the given toolUseID.
// The entry is written to pending_asks[toolUseID] in the session state file.
func (m *Manager) RecordAsk(toolUseID, tool, command, pattern, policyName, message string) error {
	return m.RecordAskWithAudit(toolUseID, tool, command, pattern, policyName, message, false, "")
}

// RecordAskWithAudit records a pending ask and optional audit linkage metadata.
func (m *Manager) RecordAskWithAudit(toolUseID, tool, command, pattern, policyName, message string, audit bool, auditApprovalID string) error {
	path, err := m.statePath()
	if err != nil {
		return err
	}
	s, err := m.load(path)
	if err != nil {
		return err
	}

	s.PendingAsks[toolUseID] = PendingAsk{
		Tool:               tool,
		Command:            command,
		GeneralizedPattern: pattern,
		AskedAt:            time.Now().UTC(),
		PolicyName:         policyName,
		DecisionMessage:    message,
		Audit:              audit,
		AuditApprovalID:    auditApprovalID,
	}

	if err := m.save(path, s); err != nil {
		return err
	}
	m.logger.Debug("session: recorded ask",
		"session_id", m.sessionID,
		"tool_use_id", toolUseID,
		"tool", tool,
		"pattern", pattern,
		"audit", audit,
		"audit_approval_id", auditApprovalID,
	)
	return nil
}

// ObserveApproval moves toolUseID from pending_asks to session_approvals,
// incrementing the approval count. Returns the updated ApprovalRecord.
// Returns an error if toolUseID is not found in pending_asks.
func (m *Manager) ObserveApproval(toolUseID string) (*ApprovalRecord, error) {
	_, record, err := m.ObserveApprovalWithAsk(toolUseID)
	return record, err
}

// ObserveApprovalWithAsk is like ObserveApproval, but also returns the pending
// ask metadata that was observed and removed.
func (m *Manager) ObserveApprovalWithAsk(toolUseID string) (*PendingAsk, *ApprovalRecord, error) {
	path, err := m.statePath()
	if err != nil {
		return nil, nil, err
	}
	s, err := m.load(path)
	if err != nil {
		return nil, nil, err
	}

	ask, ok := s.PendingAsks[toolUseID]
	if !ok {
		return nil, nil, fmt.Errorf("session: no pending ask for tool_use_id %q", toolUseID)
	}

	// Key for the approval record: "{tool}:{generalized_pattern}".
	approvalKey := ask.Tool + ":" + ask.GeneralizedPattern

	now := time.Now().UTC()
	existing, exists := s.SessionApprovals[approvalKey]
	var record ApprovalRecord
	if exists {
		record = existing
		record.LastApproved = now
		record.ApprovalCount++
	} else {
		record = ApprovalRecord{
			Pattern:       ask.GeneralizedPattern,
			Tool:          ask.Tool,
			FirstApproved: now,
			LastApproved:  now,
			ApprovalCount: 1,
		}
	}

	s.SessionApprovals[approvalKey] = record
	delete(s.PendingAsks, toolUseID)

	if err := m.save(path, s); err != nil {
		return nil, nil, err
	}
	m.logger.Debug("session: observed approval",
		"session_id", m.sessionID,
		"tool_use_id", toolUseID,
		"pattern", ask.GeneralizedPattern,
		"approval_count", record.ApprovalCount,
	)
	askCopy := ask
	return &askCopy, &record, nil
}

// DismissAsk removes a pending ask without recording an approval outcome.
// This is used when a user denies the native ask prompt (PostToolUseFailure).
func (m *Manager) DismissAsk(toolUseID string) (*PendingAsk, error) {
	path, err := m.statePath()
	if err != nil {
		return nil, err
	}
	s, err := m.load(path)
	if err != nil {
		return nil, err
	}

	ask, ok := s.PendingAsks[toolUseID]
	if !ok {
		return nil, fmt.Errorf("session: no pending ask for tool_use_id %q", toolUseID)
	}
	delete(s.PendingAsks, toolUseID)

	if err := m.save(path, s); err != nil {
		return nil, err
	}
	askCopy := ask
	return &askCopy, nil
}

// Cleanup removes session state files that have not been active within maxAge.
// It iterates over all *.json files in the state directory and removes any
// whose last_active timestamp is older than now-maxAge. Files that cannot be
// parsed are also removed to avoid stale garbage accumulating.
func (m *Manager) Cleanup(maxAge time.Duration) error {
	d, err := m.resolveDir()
	if err != nil {
		return err
	}

	entries, err := os.ReadDir(d)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // nothing to clean
		}
		return fmt.Errorf("session: cleanup readdir %s: %w", d, err)
	}

	cutoff := time.Now().UTC().Add(-maxAge)
	var removed, failed int

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if filepath.Ext(name) != ".json" {
			continue
		}

		fp := filepath.Join(d, name)
		data, err := os.ReadFile(fp)
		if err != nil {
			m.logger.Debug("session: cleanup cannot read file", "path", fp, "error", err)
			failed++
			continue
		}

		var s State
		if err := json.Unmarshal(data, &s); err != nil {
			// Unparseable file — remove it.
			m.logger.Debug("session: cleanup removing unparseable file", "path", fp)
			if removeErr := os.Remove(fp); removeErr != nil {
				m.logger.Debug("session: cleanup remove failed", "path", fp, "error", removeErr)
				failed++
			} else {
				removed++
			}
			continue
		}

		if s.LastActive.Before(cutoff) {
			if removeErr := os.Remove(fp); removeErr != nil {
				m.logger.Debug("session: cleanup remove failed", "path", fp, "error", removeErr)
				failed++
			} else {
				m.logger.Debug("session: cleanup removed stale session file",
					"session_id", s.SessionID,
					"last_active", s.LastActive,
				)
				removed++
			}
		}
	}

	if removed > 0 || failed > 0 {
		m.logger.Info("session: cleanup complete",
			"removed", removed,
			"failed", failed,
		)
	}
	return nil
}
