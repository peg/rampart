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

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("audit: open jsonl file: %w", err)
	}

	s.file = file
	s.currentFile = name
	s.currentSize = 0

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

	if err := s.openNewFileLocked(true, prevFile); err != nil {
		return err
	}

	s.logger.Info("audit: rotated jsonl file",
		"file", s.currentFile,
		"prev_file", prevFile,
		"last_hash", s.lastHash,
	)

	return nil
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

func (s *JSONLSink) nextFilenameLocked() string {
	now := time.Now().UTC().Truncate(time.Second)
	if !s.lastFileAt.IsZero() && !now.After(s.lastFileAt) {
		now = s.lastFileAt.Add(time.Second)
	}
	s.lastFileAt = now
	return "audit-" + now.Format("2006-01-02T15-04-05") + ".jsonl"
}
