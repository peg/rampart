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

package audit

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

type recoveredChainState struct {
	eventCount int64
	lastHash   string
	lastFile   string
}

// recoverChainStateFromDir reconstructs the append position from the latest
// valid event in existing JSONL audit files. Chain-continuation headers are
// skipped. Anchors are checkpoints for verification, not the authority for the
// next event's prev_hash.
func recoverChainStateFromDir(dir string, logger *slog.Logger) (recoveredChainState, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return recoveredChainState{}, fmt.Errorf("read audit directory: %w", err)
	}

	files := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		// The audit directory also contains hook and export JSONL files. They
		// are valid audit data, but they are not part of this sink's hash chain
		// and must not influence its recovered append position.
		if _, managed := auditFileSortKey(entry.Name()); !managed {
			continue
		}
		files = append(files, entry.Name())
	}
	SortAuditFiles(files)

	var state recoveredChainState
	for _, name := range files {
		path := filepath.Join(dir, name)
		file, err := os.Open(path)
		if err != nil {
			return recoveredChainState{}, fmt.Errorf("open %s: %w", name, err)
		}

		reader := bufio.NewReaderSize(file, auditReaderBufferBytes)
		lineNum := 0
		for {
			record, complete, readErr := readRecord(reader)
			if errors.Is(readErr, io.EOF) {
				break
			}
			lineNum++
			if readErr != nil {
				_ = file.Close()
				return recoveredChainState{}, fmt.Errorf("read %s line %d: %w", name, lineNum, readErr)
			}
			if !complete {
				_ = file.Close()
				return recoveredChainState{}, fmt.Errorf("read %s line %d: unterminated audit record", name, lineNum)
			}
			line := bytes.TrimSpace(record)
			if len(line) == 0 {
				continue
			}

			var event Event
			if err := json.Unmarshal(line, &event); err != nil {
				_ = file.Close()
				return recoveredChainState{}, fmt.Errorf("parse %s line %d: %w", name, lineNum, err)
			}
			if event.ID == "" {
				var header struct {
					ChainContinue *string `json:"chain_continue"`
					PrevFile      *string `json:"prev_file"`
				}
				if err := json.Unmarshal(line, &header); err == nil && header.ChainContinue != nil && header.PrevFile != nil {
					continue
				}
				_ = file.Close()
				return recoveredChainState{}, fmt.Errorf("parse %s line %d: record has no event id", name, lineNum)
			}
			ok, verifyErr := event.VerifyHash()
			if verifyErr != nil {
				_ = file.Close()
				return recoveredChainState{}, fmt.Errorf("verify %s line %d event %s: %w", name, lineNum, event.ID, verifyErr)
			}
			if !ok {
				_ = file.Close()
				return recoveredChainState{}, fmt.Errorf("verify %s line %d event %s: hash mismatch", name, lineNum, event.ID)
			}

			state.eventCount++
			state.lastHash = event.Hash
			state.lastFile = name
		}
		if err := file.Close(); err != nil {
			return recoveredChainState{}, fmt.Errorf("close %s: %w", name, err)
		}
	}
	return state, nil
}

// JSONLSink is an append-only JSONL audit sink with hash chaining.
type JSONLSink struct {
	mu sync.Mutex

	dir            string
	file           *os.File
	currentFile    string
	currentSize    int64
	lastHash       string
	eventCount     int64
	fsync          bool
	rotateSize     int64
	anchorInterval int
	closed         bool
	logger         *slog.Logger
}

// NewJSONLSink creates a JSONL-backed audit sink in dir.
func NewJSONLSink(dir string, opts ...SinkOption) (*JSONLSink, error) {
	if dir == "" {
		return nil, fmt.Errorf("audit: sink dir is empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit: create sink dir: %w", err)
	}

	cfg := defaultSinkConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	logger := cfg.logger
	if logger == nil {
		logger = slog.Default()
	}

	sink := &JSONLSink{
		dir:            dir,
		fsync:          cfg.fsync,
		rotateSize:     cfg.rotateSize,
		anchorInterval: cfg.anchorInterval,
		logger:         logger,
	}

	// Recover append state from existing JSONL events. Anchors are not trusted as
	// the sole chain head because they can be absent, stale, or tampered with.
	recovered, err := recoverChainStateFromDir(dir, logger)
	if err != nil {
		return nil, fmt.Errorf("audit: recover chain state: %w", err)
	}
	sink.eventCount = recovered.eventCount
	sink.lastHash = recovered.lastHash
	if sink.eventCount > 0 {
		logger.Info("audit: recovered chain state from log files",
			"event_count", sink.eventCount,
			"hash", sink.lastHash,
			"file", recovered.lastFile,
		)
	}

	// Inspect the current anchor for diagnostics only. The next event always
	// continues from the latest valid JSONL event recovered above.
	anchorPath := filepath.Join(dir, anchorFilename)
	if data, err := os.ReadFile(anchorPath); err == nil {
		var anchor ChainAnchor
		if err := json.Unmarshal(data, &anchor); err == nil && anchor.EventID != "" {
			if anchor.Hash == sink.lastHash && anchor.EventCount == sink.eventCount {
				logger.Debug("audit: anchor matches recovered chain head",
					"event_count", anchor.EventCount,
					"hash", anchor.Hash,
					"file", anchor.File,
				)
			} else {
				logger.Debug("audit: anchor is not current chain head; continuing from latest log event",
					"anchor_event_count", anchor.EventCount,
					"recovered_event_count", sink.eventCount,
					"anchor_hash", anchor.Hash,
					"recovered_hash", sink.lastHash,
					"file", anchor.File,
				)
			}
		}
	}

	if err := sink.openNewFileLocked(false, ""); err != nil {
		return nil, err
	}
	return sink, nil
}

// NewEventID returns a new ULID event identifier.
func NewEventID() string {
	id, err := ulid.New(ulid.Timestamp(time.Now().UTC()), rand.Reader)
	if err == nil {
		return id.String()
	}

	slog.Error("audit: generate event id", "error", err)
	return ulid.Make().String()
}

// Write appends a single event to the JSONL audit trail.
func (s *JSONLSink) Write(event Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return fmt.Errorf("audit: write on closed sink")
	}
	event.PrevHash = s.lastHash
	event, line, err := marshalRecord(event)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	if s.shouldRotateLocked(len(line)) || s.dayChangedLocked() {
		if err := s.rotateLocked(); err != nil {
			return err
		}
	}
	if _, err := s.file.Write(line); err != nil {
		return fmt.Errorf("audit: write event: %w", err)
	}

	s.currentSize += int64(len(line))

	if s.fsync {
		if err := s.file.Sync(); err != nil {
			return fmt.Errorf("audit: fsync event: %w", err)
		}
	}

	s.lastHash = event.Hash
	s.eventCount++
	if s.shouldAnchorLocked() {
		if err := s.writeAnchorLocked(event); err != nil {
			return err
		}
	}

	s.logger.Debug("audit: wrote event",
		"event_id", event.ID,
		"event_count", s.eventCount,
		"file", s.currentFile,
	)

	return nil
}

// Flush flushes pending data to disk.
func (s *JSONLSink) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	if s.file == nil {
		return nil
	}
	if err := s.file.Sync(); err != nil {
		return fmt.Errorf("audit: flush sink: %w", err)
	}
	return nil
}

// Close flushes and closes the sink.
func (s *JSONLSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	if s.file == nil {
		return nil
	}
	if err := s.file.Sync(); err != nil {
		return fmt.Errorf("audit: close sync: %w", err)
	}
	if err := s.file.Close(); err != nil {
		return fmt.Errorf("audit: close sink file: %w", err)
	}
	s.file = nil
	return nil
}

func (s *JSONLSink) filePath() string {
	return filepath.Join(s.dir, s.currentFile)
}
