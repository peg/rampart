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

// readLastLineHash reads the last non-empty line of a JSONL file and extracts
// its "hash" field. Returns the hash and true if successful.
func readLastLineHash(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()

	var lastLine string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if line := scanner.Text(); line != "" {
			lastLine = line
		}
	}
	if lastLine == "" {
		return "", false
	}
	var partial struct {
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal([]byte(lastLine), &partial); err != nil {
		return "", false
	}
	return partial.Hash, partial.Hash != ""
}

// countLinesInDir counts non-empty lines across all .jsonl files in dir
// using streaming IO to avoid loading entire files into memory.
func countLinesInDir(dir string) int64 {
	var count int64
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			if len(scanner.Bytes()) > 0 {
				count++
			}
		}
		_ = f.Close()
	}
	return count
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

	// Recover state from anchor file if it exists.
	anchorPath := filepath.Join(dir, anchorFilename)
	anchorTrusted := false
	if data, err := os.ReadFile(anchorPath); err == nil {
		var anchor ChainAnchor
		if err := json.Unmarshal(data, &anchor); err == nil {
			// Validate anchor: verify the hash matches the last line of the referenced log file.
			if anchor.File != "" {
				if lastHash, ok := readLastLineHash(filepath.Join(dir, anchor.File)); ok {
					if lastHash == anchor.Hash {
						anchorTrusted = true
					} else {
						logger.Warn("audit: anchor hash mismatch — possible tampering, falling back to line count",
							"anchor_hash", anchor.Hash,
							"file_hash", lastHash,
							"file", anchor.File,
						)
					}
				}
			}
			if anchorTrusted {
				sink.lastHash = anchor.Hash
				sink.eventCount = anchor.EventCount
				logger.Info("audit: recovered state from anchor",
					"event_count", anchor.EventCount,
					"hash", anchor.Hash,
				)
			}
		}
	}
	if !anchorTrusted {
		// No anchor — count non-empty lines in existing log files to recover eventCount.
		sink.eventCount = countLinesInDir(dir)
		if sink.eventCount > 0 {
			logger.Info("audit: recovered event count from log files", "event_count", sink.eventCount)
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
	if event.ID == "" {
		event.ID = NewEventID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

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
