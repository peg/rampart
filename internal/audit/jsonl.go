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
	"crypto/rand"
	"encoding/json"
	"fmt"
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
func recoverChainStateFromDir(dir string, logger *slog.Logger) recoveredChainState {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if logger != nil {
			logger.Debug("audit: read audit dir during recovery", "error", err)
		}
		return recoveredChainState{}
	}

	files := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
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
			if logger != nil {
				logger.Debug("audit: open audit file during recovery", "file", name, "error", err)
			}
			continue
		}

		scanner := bufio.NewScanner(file)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			var event Event
			if err := json.Unmarshal([]byte(line), &event); err != nil {
				if logger != nil {
					logger.Debug("audit: skip unparsable audit line during recovery", "file", name, "line", lineNum, "error", err)
				}
				continue
			}
			if event.ID == "" {
				continue
			}
			ok, err := event.VerifyHash()
			if err != nil || !ok {
				if logger != nil {
					logger.Debug("audit: skip invalid audit event during recovery", "file", name, "line", lineNum, "event_id", event.ID, "error", err)
				}
				continue
			}

			state.eventCount++
			state.lastHash = event.Hash
			state.lastFile = name
		}
		if err := scanner.Err(); err != nil && logger != nil {
			logger.Debug("audit: scan audit file during recovery", "file", name, "error", err)
		}
		_ = file.Close()
	}
	return state
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
	recovered := recoverChainStateFromDir(dir, logger)
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
	event = applyEventDefaults(event)

	event.PrevHash = s.lastHash
	if err := event.ComputeHash(); err != nil {
		return fmt.Errorf("audit: compute hash: %w", err)
	}

	line, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("audit: marshal event: %w", err)
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
