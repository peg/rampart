// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	sharedStateFilename = ".audit-chain-state.json"
	sharedStateVersion  = 1
)

// sharedChainState is a small coordination checkpoint, not an integrity
// authority. Long-running sink creation verifies the complete JSONL chain;
// short-lived native-hook startup may validate this checkpoint against the
// current file and last event instead. Writes always revalidate it under the
// directory lock and fall back to complete recovery whenever it is absent,
// stale, or malformed.
type sharedChainState struct {
	Version        int    `json:"version"`
	EventCount     int64  `json:"event_count"`
	LastHash       string `json:"last_hash"`
	CurrentFile    string `json:"current_file"`
	CurrentSize    int64  `json:"current_size"`
	LastEventFile  string `json:"last_event_file,omitempty"`
	LastEventStart int64  `json:"last_event_start,omitempty"`
	LastEventSize  int64  `json:"last_event_size,omitempty"`
}

func (s *JSONLSink) applyRecoveredStateLocked(state recoveredChainState) {
	s.eventCount = state.eventCount
	s.lastHash = state.lastHash
	s.currentSize = state.lastFileSize
	s.lastEventFile = state.lastEventFile
	s.lastEventStart = state.lastEventStart
	s.lastEventSize = state.lastEventSize
}

func (s *JSONLSink) currentSharedStateLocked() sharedChainState {
	return sharedChainState{
		Version:        sharedStateVersion,
		EventCount:     s.eventCount,
		LastHash:       s.lastHash,
		CurrentFile:    s.currentFile,
		CurrentSize:    s.currentSize,
		LastEventFile:  s.lastEventFile,
		LastEventStart: s.lastEventStart,
		LastEventSize:  s.lastEventSize,
	}
}

func (s *JSONLSink) writeSharedStateLocked() error {
	state := s.currentSharedStateLocked()
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("audit: marshal shared chain state: %w", err)
	}
	data = append(data, '\n')

	path := filepath.Join(s.dir, sharedStateFilename)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit: open shared chain state: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("audit: write shared chain state: %w", err)
	}
	if s.fsync {
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return fmt.Errorf("audit: fsync shared chain state: %w", err)
		}
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("audit: close shared chain state: %w", err)
	}
	return nil
}

func (s *JSONLSink) refreshSharedStateLocked() error {
	state, usable, err := s.readSharedStateLocked()
	if err != nil {
		return err
	}
	if usable {
		return s.adoptSharedStateLocked(state)
	}

	// A process may have stopped after appending a record but before updating
	// the checkpoint. Recover from the log, which remains the source of truth.
	recovered, err := recoverChainStateFromDir(s.dir, s.logger)
	if err != nil {
		return fmt.Errorf("audit: recover shared chain state: %w", err)
	}
	s.applyRecoveredStateLocked(recovered)
	name := recovered.lastFile
	if name == "" {
		name = s.nextFilenameLocked()
	}
	if err := s.switchFileLocked(name); err != nil {
		return err
	}
	return s.writeSharedStateLocked()
}

func (s *JSONLSink) readSharedStateLocked() (sharedChainState, bool, error) {
	path := filepath.Join(s.dir, sharedStateFilename)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return sharedChainState{}, false, nil
	}
	if err != nil {
		return sharedChainState{}, false, fmt.Errorf("audit: read shared chain state: %w", err)
	}

	var state sharedChainState
	if err := json.Unmarshal(data, &state); err != nil {
		s.logger.Warn("audit: shared chain state is unreadable; recovering from JSONL", "error", err)
		return sharedChainState{}, false, nil
	}
	valid, err := s.validateSharedStateLocked(state)
	if err != nil {
		return sharedChainState{}, false, err
	}
	if !valid {
		s.logger.Warn("audit: shared chain state is stale; recovering from JSONL")
		return sharedChainState{}, false, nil
	}
	return state, true, nil
}

func (s *JSONLSink) validateSharedStateLocked(state sharedChainState) (bool, error) {
	if state.Version != sharedStateVersion || state.EventCount < 0 ||
		state.CurrentFile == "" || filepath.Base(state.CurrentFile) != state.CurrentFile {
		return false, nil
	}
	if _, managed := auditFileSortKey(state.CurrentFile); !managed {
		return false, nil
	}
	if (state.EventCount == 0) != (state.LastHash == "") {
		return false, nil
	}

	files, err := managedAuditFiles(s.dir)
	if err != nil {
		return false, err
	}
	if len(files) == 0 || files[len(files)-1] != state.CurrentFile {
		return false, nil
	}
	info, err := os.Stat(filepath.Join(s.dir, state.CurrentFile))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("audit: stat shared chain file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() != state.CurrentSize {
		return false, nil
	}

	if state.EventCount == 0 {
		return state.CurrentSize == 0 && state.LastEventFile == "" &&
			state.LastEventStart == 0 && state.LastEventSize == 0, nil
	}
	if filepath.Base(state.LastEventFile) != state.LastEventFile ||
		state.LastEventStart < 0 || state.LastEventSize <= 0 || state.LastEventSize > MaxRecordBytes+1 {
		return false, nil
	}
	if _, managed := auditFileSortKey(state.LastEventFile); !managed {
		return false, nil
	}
	if state.LastEventFile == state.CurrentFile &&
		state.LastEventStart+state.LastEventSize != state.CurrentSize {
		return false, nil
	}
	if !containsAuditFile(files, state.LastEventFile) {
		return false, nil
	}

	tail, valid, err := validateSharedLastEvent(s.dir, state)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, nil
	}
	if state.LastEventFile != state.CurrentFile {
		return validateCurrentFilePrecedesTail(s.dir, state, tail)
	}
	return true, nil
}

func validateSharedLastEvent(dir string, state sharedChainState) (Event, bool, error) {
	file, err := os.Open(filepath.Join(dir, state.LastEventFile))
	if os.IsNotExist(err) {
		return Event{}, false, nil
	}
	if err != nil {
		return Event{}, false, fmt.Errorf("audit: open shared chain tail: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Event{}, false, fmt.Errorf("audit: stat shared chain tail: %w", err)
	}
	if state.LastEventStart+state.LastEventSize != info.Size() {
		return Event{}, false, nil
	}

	record := make([]byte, state.LastEventSize)
	n, err := file.ReadAt(record, state.LastEventStart)
	if err != nil {
		return Event{}, false, fmt.Errorf("audit: read shared chain tail: %w", err)
	}
	if n != len(record) || len(record) == 0 || record[len(record)-1] != '\n' {
		return Event{}, false, nil
	}

	var event Event
	if err := json.Unmarshal(bytes.TrimSpace(record), &event); err != nil || event.ID == "" || event.Hash != state.LastHash {
		return Event{}, false, nil
	}
	ok, err := event.VerifyHash()
	if err != nil {
		return Event{}, false, fmt.Errorf("audit: verify shared chain tail: %w", err)
	}
	return event, ok, nil
}

func validateCurrentFilePrecedesTail(dir string, state sharedChainState, tail Event) (bool, error) {
	record, err := readLastAuditRecord(filepath.Join(dir, state.CurrentFile), state.CurrentSize)
	if err != nil {
		return false, err
	}
	if len(record) == 0 {
		return false, nil
	}

	var event Event
	if err := json.Unmarshal(record, &event); err != nil {
		return false, nil
	}
	if event.ID != "" {
		ok, err := event.VerifyHash()
		if err != nil {
			return false, fmt.Errorf("audit: verify current shared chain event: %w", err)
		}
		return ok && tail.PrevHash == event.Hash, nil
	}

	var header struct {
		ChainContinue *string `json:"chain_continue"`
		PrevFile      *string `json:"prev_file"`
	}
	if err := json.Unmarshal(record, &header); err != nil || header.ChainContinue == nil || header.PrevFile == nil {
		return false, nil
	}
	return *header.ChainContinue == tail.Hash, nil
}

func readLastAuditRecord(path string, size int64) ([]byte, error) {
	if size <= 0 {
		return nil, nil
	}
	const suffixBytes = int64(MaxRecordBytes + 2)
	start := int64(0)
	if size > suffixBytes {
		start = size - suffixBytes
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("audit: open current shared chain file: %w", err)
	}
	defer file.Close()
	data := make([]byte, size-start)
	n, err := file.ReadAt(data, start)
	if err != nil {
		return nil, fmt.Errorf("audit: read current shared chain file: %w", err)
	}
	if n != len(data) {
		return nil, fmt.Errorf("audit: short read of current shared chain file")
	}
	if start > 0 {
		newline := bytes.IndexByte(data, '\n')
		if newline < 0 {
			return nil, errRecordTooLarge
		}
		data = data[newline+1:]
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, nil
	}
	if newline := bytes.LastIndexByte(data, '\n'); newline >= 0 {
		data = data[newline+1:]
	}
	if len(data) > MaxRecordBytes {
		return nil, errRecordTooLarge
	}
	return data, nil
}

func containsAuditFile(files []string, name string) bool {
	for _, file := range files {
		if file == name {
			return true
		}
	}
	return false
}

func (s *JSONLSink) adoptSharedStateLocked(state sharedChainState) error {
	if err := s.switchFileLocked(state.CurrentFile); err != nil {
		return err
	}
	s.eventCount = state.EventCount
	s.lastHash = state.LastHash
	s.currentSize = state.CurrentSize
	s.lastEventFile = state.LastEventFile
	s.lastEventStart = state.LastEventStart
	s.lastEventSize = state.LastEventSize
	return nil
}

func (s *JSONLSink) switchFileLocked(name string) error {
	if s.file != nil && s.currentFile == name {
		openInfo, openErr := s.file.Stat()
		pathInfo, pathErr := os.Stat(filepath.Join(s.dir, name))
		if openErr == nil && pathErr == nil && os.SameFile(openInfo, pathInfo) {
			return nil
		}
	}
	if s.file != nil {
		if err := s.file.Close(); err != nil {
			return fmt.Errorf("audit: close stale jsonl file: %w", err)
		}
		s.file = nil
	}
	return s.openNamedFileLocked(name)
}
