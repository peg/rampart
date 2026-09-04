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

	"github.com/peg/rampart/internal/filetxn"
)

type recoveredChainState struct {
	eventCount      int64
	lastHash        string
	lastFile        string
	lastFileSize    int64
	lastEventFile   string
	lastEventStart  int64
	lastEventSize   int64
	rootCount       int
	prefixHash      string
	witnessMismatch bool
}

type chainFileOpener func(string) (io.ReadCloser, error)

var errChainNeedsLinkRecovery = errors.New("audit chain is not in file order")

// recoverChainStateFromDir reconstructs the append position from the latest
// valid event in existing JSONL audit files. It verifies every event hash,
// prev_hash link, and chain-continuation header. Anchors are checkpoints for
// diagnostics, not the authority for the next event's prev_hash.
func recoverChainStateFromDir(dir string, logger *slog.Logger) (recoveredChainState, error) {
	files, err := managedAuditFiles(dir)
	if err != nil {
		return recoveredChainState{}, err
	}
	return recoverChainState(dir, files, func(name string) (io.ReadCloser, error) {
		return openAuditRegular(filepath.Join(dir, name), os.O_RDONLY)
	}, nil, logger)
}

func recoverChainState(dir string, files []string, open chainFileOpener, checkpoints map[int64]string, logger *slog.Logger) (recoveredChainState, error) {
	state, err := recoverChainStateInFileOrder(files, open, checkpoints)
	if !errors.Is(err, errChainNeedsLinkRecovery) {
		return state, err
	}

	// Older Rampart versions reopened the daily base file after size rotation.
	// Their valid chain can therefore cross files out of filename order. Use a
	// bounded-metadata link traversal only for that legacy layout; ordinary
	// recovery remains streaming and constant-memory.
	if logger != nil {
		logger.Warn("audit: recovering legacy out-of-file-order hash chain")
	}
	return recoverChainStateByLinks(files, open, checkpoints)
}

func recoverChainStateInFileOrder(files []string, open chainFileOpener, checkpoints map[int64]string) (recoveredChainState, error) {
	var state recoveredChainState
	previousFile := ""
	for _, name := range files {
		file, err := open(name)
		if err != nil {
			return recoveredChainState{}, fmt.Errorf("open %s: %w", name, err)
		}

		reader := bufio.NewReaderSize(file, auditReaderBufferBytes)
		lineNum := 0
		cursor := int64(0)
		seenRecord := false
		seenHeader := false
		for {
			recordStart := cursor
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
			cursor += int64(len(record) + 1)
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
					if seenRecord || seenHeader {
						_ = file.Close()
						return recoveredChainState{}, fmt.Errorf("verify %s line %d: chain continuation must be the first record", name, lineNum)
					}
					if *header.ChainContinue != state.lastHash {
						_ = file.Close()
						return recoveredChainState{}, fmt.Errorf("%w: verify %s line %d: chain continuation %q does not match previous hash %q", errChainNeedsLinkRecovery, name, lineNum, *header.ChainContinue, state.lastHash)
					}
					if *header.PrevFile != previousFile {
						_ = file.Close()
						return recoveredChainState{}, fmt.Errorf("verify %s line %d: prev_file %q does not match previous audit file %q", name, lineNum, *header.PrevFile, previousFile)
					}
					seenHeader = true
					seenRecord = true
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
			if event.PrevHash != state.lastHash {
				_ = file.Close()
				return recoveredChainState{}, fmt.Errorf("%w: verify %s line %d event %s: prev_hash %q does not match previous event hash %q", errChainNeedsLinkRecovery, name, lineNum, event.ID, event.PrevHash, state.lastHash)
			}

			state.eventCount++
			if event.PrevHash == "" {
				state.rootCount++
			}
			state.observeWitness(state.eventCount, event.Hash, checkpoints)
			state.lastHash = event.Hash
			state.lastEventFile = name
			state.lastEventStart = recordStart
			state.lastEventSize = int64(len(record) + 1)
			seenRecord = true
		}
		if err := file.Close(); err != nil {
			return recoveredChainState{}, fmt.Errorf("close %s: %w", name, err)
		}
		state.lastFile = name
		state.lastFileSize = cursor
		previousFile = name
	}
	return state, nil
}

func (s *recoveredChainState) observeWitness(count int64, hash string, checkpoints map[int64]string) {
	if expected, retained := checkpoints[count]; retained {
		s.prefixHash = hash
		s.witnessMismatch = s.witnessMismatch || expected != hash
	}
}

func managedAuditFiles(dir string) ([]string, error) {
	if err := validateAuditDirectory(dir); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read audit directory: %w", err)
	}

	files := make([]string, 0)
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect audit file %s: %w", entry.Name(), err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("audit: path is not a regular non-symlink file: %s", filepath.Join(dir, entry.Name()))
		}
		// The audit directory also contains hook and export JSONL files. They
		// are valid audit data, but they are not part of this sink's hash chain.
		if _, managed := auditFileSortKey(entry.Name()); managed {
			files = append(files, entry.Name())
		}
	}
	SortAuditFiles(files)
	return files, nil
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
	lastEventFile  string
	lastEventStart int64
	lastEventSize  int64
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
	if err := validateAuditDirectory(dir); err != nil {
		return nil, err
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

	// Recovery and file selection share the same cross-process directory lock
	// used by Write, so two sinks cannot recover and then independently fork the
	// chain before either publishes its state. Short-lived hook writers may use
	// the validated checkpoint/tail fast path; any inconsistency falls back to a
	// complete recovery before a record can be appended.
	var recovered recoveredChainState
	usedCheckpoint := false
	err := sink.withDirectoryLock(func() error {
		if cfg.checkpointStartup {
			state, usable, stateErr := sink.readSharedStateLocked()
			if stateErr != nil {
				return stateErr
			}
			if usable {
				if err := sink.adoptSharedStateLocked(state); err != nil {
					return err
				}
				usedCheckpoint = true
				return nil
			}
		}

		var recoverErr error
		recovered, recoverErr = recoverChainStateFromDir(dir, logger)
		if recoverErr != nil {
			return fmt.Errorf("audit: recover chain state: %w", recoverErr)
		}
		sink.applyRecoveredStateLocked(recovered)

		name := recovered.lastFile
		if name == "" {
			name = sink.nextFilenameLocked()
		}
		if err := sink.openNamedFileLocked(name); err != nil {
			return err
		}
		return sink.writeSharedStateLocked()
	})
	if err != nil {
		if sink.file != nil {
			_ = sink.file.Close()
		}
		return nil, err
	}
	if usedCheckpoint {
		logger.Debug("audit: resumed chain from validated checkpoint",
			"event_count", sink.eventCount,
			"hash", sink.lastHash,
			"file", sink.currentFile,
		)
	} else if sink.eventCount > 0 {
		logger.Info("audit: recovered chain state from log files",
			"event_count", sink.eventCount,
			"hash", sink.lastHash,
			"file", recovered.lastFile,
		)
	}

	// Inspect the current anchor for diagnostics only. The next event always
	// continues from the latest valid JSONL event recovered above.
	anchorPath := filepath.Join(dir, anchorFilename)
	data, exists, err := readAuditMetadata(anchorPath)
	if err != nil {
		_ = sink.Close()
		return nil, fmt.Errorf("audit: inspect chain anchor: %w", err)
	}
	if exists {
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
	return s.withDirectoryLock(func() error {
		if err := s.refreshSharedStateLocked(); err != nil {
			return err
		}

		event.PrevHash = s.lastHash
		encodedEvent, line, err := marshalRecord(event)
		if err != nil {
			return err
		}
		line = append(line, '\n')

		if s.shouldRotateLocked(len(line)) || s.dayChangedLocked() {
			if err := s.rotateLocked(); err != nil {
				return err
			}
		}
		eventStart := s.currentSize
		if _, err := s.file.Write(line); err != nil {
			return fmt.Errorf("audit: write event: %w", err)
		}

		s.currentSize += int64(len(line))

		if s.fsync {
			if err := s.file.Sync(); err != nil {
				return fmt.Errorf("audit: fsync event: %w", err)
			}
		}

		s.lastHash = encodedEvent.Hash
		s.eventCount++
		s.lastEventFile = s.currentFile
		s.lastEventStart = eventStart
		s.lastEventSize = int64(len(line))
		if err := s.writeSharedStateLocked(); err != nil {
			return err
		}
		if s.shouldAnchorLocked() {
			if err := s.writeAnchorLocked(encodedEvent); err != nil {
				return err
			}
		}

		s.logger.Debug("audit: wrote event",
			"event_id", encodedEvent.ID,
			"event_count", s.eventCount,
			"file", s.currentFile,
		)

		return nil
	})
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
	if s.fsync {
		if err := s.file.Sync(); err != nil {
			return fmt.Errorf("audit: close sync: %w", err)
		}
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

func (s *JSONLSink) withDirectoryLock(fn func() error) error {
	if err := validateAuditDirectory(s.dir); err != nil {
		return err
	}
	statePath := filepath.Join(s.dir, sharedStateFilename)
	lockPath := statePath + ".rampart.lock"
	if _, _, err := inspectAuditRegularPath(lockPath); err != nil {
		return fmt.Errorf("audit: unsafe directory lock: %w", err)
	}
	return filetxn.WithLock(statePath, func() error {
		if _, _, err := inspectAuditRegularPath(lockPath); err != nil {
			return fmt.Errorf("audit: unsafe directory lock: %w", err)
		}
		return fn()
	})
}
