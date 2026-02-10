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

// Package audit provides a tamper-evident audit trail for agent tool calls.
//
// ReadEventsFromOffset reads JSONL audit events from a file starting at a byte offset.
// It returns parsed events, the new offset after reading, and any error.
// This is the shared implementation used by both CLI audit commands and the watch TUI.
package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// ReadEventsFromOffset reads audit events from path starting at the given byte offset.
// Returns the parsed events, the new file offset, and any error.
// If the file has been truncated (offset > size), it resets to the beginning.
// Partial (unterminated) lines are not consumed — the offset stays before them
// so they can be re-read once complete.
func ReadEventsFromOffset(path string, offset int64) ([]Event, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, offset, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, offset, fmt.Errorf("audit: stat %s: %w", path, err)
	}
	if offset > info.Size() {
		offset = 0
	}

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, offset, fmt.Errorf("audit: seek %s: %w", path, err)
	}

	reader := bufio.NewReader(f)
	cursor := offset
	events := make([]Event, 0, 8)

	for {
		line, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, cursor, fmt.Errorf("audit: read line: %w", err)
		}

		// EOF with no data — done.
		if line == "" && errors.Is(err, io.EOF) {
			return events, cursor, nil
		}

		// Partial line (no trailing newline) — don't consume it.
		if !strings.HasSuffix(line, "\n") {
			return events, cursor, nil
		}

		cursor += int64(len(line))
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			if errors.Is(err, io.EOF) {
				return events, cursor, nil
			}
			continue
		}

		var evt Event
		if unmarshalErr := json.Unmarshal([]byte(trimmed), &evt); unmarshalErr == nil {
			events = append(events, evt)
		}

		if errors.Is(err, io.EOF) {
			return events, cursor, nil
		}
	}
}
