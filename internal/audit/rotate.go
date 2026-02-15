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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const anchorFilename = "audit-anchor.json"

func (s *JSONLSink) shouldRotateLocked(incoming int) bool {
	if s.rotateSize <= 0 {
		return false
	}
	return s.currentSize+int64(incoming) > s.rotateSize
}

func (s *JSONLSink) openNewFileLocked(withHeader bool, prevFile string) error {
	name := s.nextFilenameLocked()
	path := filepath.Join(s.dir, name)

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit: open jsonl file: %w", err)
	}

	// Get current file size (file may already exist from earlier today).
	info, statErr := file.Stat()
	if statErr != nil {
		file.Close()
		return fmt.Errorf("audit: stat jsonl file: %w", statErr)
	}

	s.file = file
	s.currentFile = name
	s.currentSize = info.Size()

	if !withHeader {
		return nil
	}
	return s.writeChainContinuationLocked(prevFile)
}

func (s *JSONLSink) rotateLocked() error {
	prevFile := s.currentFile
	if s.file != nil {
		if err := s.file.Close(); err != nil {
			return fmt.Errorf("audit: close rotated file: %w", err)
		}
		s.file = nil
	}

	if err := s.openRotatedFileLocked(prevFile); err != nil {
		return err
	}

	s.logger.Info("audit: rotated jsonl file",
		"file", s.currentFile,
		"prev_file", prevFile,
		"last_hash", s.lastHash,
	)

	return nil
}

// openRotatedFileLocked opens the next file for size-based or day-change rotation.
// For day changes it uses the base daily name; for size rotation within the same day
// it uses a sequenced name.
func (s *JSONLSink) openRotatedFileLocked(prevFile string) error {
	var name string
	today := time.Now().UTC().Format("2006-01-02")
	if strings.HasPrefix(prevFile, today) {
		// Same day — size rotation, use sequence number.
		name = s.nextRotatedFilenameLocked()
	} else {
		// New day — use base daily name.
		name = s.nextFilenameLocked()
	}

	path := filepath.Join(s.dir, name)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit: open jsonl file: %w", err)
	}

	info, statErr := file.Stat()
	if statErr != nil {
		file.Close()
		return fmt.Errorf("audit: stat jsonl file: %w", statErr)
	}

	s.file = file
	s.currentFile = name
	s.currentSize = info.Size()

	return s.writeChainContinuationLocked(prevFile)
}

func (s *JSONLSink) writeChainContinuationLocked(prevFile string) error {
	header := map[string]any{
		"chain_continue": s.lastHash,
		"prev_file":      prevFile,
	}

	line, err := json.Marshal(header)
	if err != nil {
		return fmt.Errorf("audit: marshal chain continuation: %w", err)
	}

	line = append(line, '\n')
	if _, err := s.file.Write(line); err != nil {
		return fmt.Errorf("audit: write chain continuation: %w", err)
	}

	s.currentSize += int64(len(line))
	if !s.fsync {
		return nil
	}
	if err := s.file.Sync(); err != nil {
		return fmt.Errorf("audit: fsync chain continuation: %w", err)
	}
	return nil
}

// dayChangedLocked reports whether the current date (UTC) differs from the
// date encoded in the current filename.
func (s *JSONLSink) dayChangedLocked() bool {
	today := time.Now().UTC().Format("2006-01-02")
	// currentFile is "YYYY-MM-DD.jsonl" or "YYYY-MM-DD.N.jsonl"
	return !strings.HasPrefix(s.currentFile, today)
}

// nextFilenameLocked returns the daily file name. On the first call of a day
// it returns "YYYY-MM-DD.jsonl". Size-based rotation within the same day is
// handled by nextRotatedFilenameLocked which appends a sequence number.
func (s *JSONLSink) nextFilenameLocked() string {
	return time.Now().UTC().Format("2006-01-02") + ".jsonl"
}

// nextRotatedFilenameLocked returns a sequenced filename for size-based
// rotation within the same day, e.g. "2026-02-13.1.jsonl".
func (s *JSONLSink) nextRotatedFilenameLocked() string {
	today := time.Now().UTC().Format("2006-01-02")
	// Find next available sequence number.
	for seq := 1; ; seq++ {
		name := fmt.Sprintf("%s.p%d.jsonl", today, seq)
		path := filepath.Join(s.dir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return name
		}
	}
}
