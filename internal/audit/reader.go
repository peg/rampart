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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// MaxRecordBytes is the largest JSON object Rampart will write or read as one
// audit JSONL record. Writers compact oversized fields to size/digest metadata;
// readers enforce the same ceiling so corrupt or hostile files cannot force an
// unbounded allocation.
const MaxRecordBytes = 2 * 1024 * 1024

const auditReaderBufferBytes = 64 * 1024

var errRecordTooLarge = fmt.Errorf("audit: record exceeds %d-byte limit", MaxRecordBytes)

// OpenRegularFile opens an existing audit file only when the directory entry
// and resulting handle both refer to the same regular, non-symlink file. It is
// intended for streaming call sites that cannot use ReadEventsFromOffset.
// The caller must close the returned file.
func OpenRegularFile(path string) (*os.File, error) {
	return openAuditRegular(path, os.O_RDONLY)
}

// readRecord reads at most one JSONL record. complete is false only for an
// unterminated final record, which callers may retry after more data is written.
// The returned record does not include the trailing newline.
func readRecord(reader *bufio.Reader) (record []byte, complete bool, err error) {
	for {
		chunk, readErr := reader.ReadSlice('\n')
		record = append(record, chunk...)

		if readErr == nil {
			record = record[:len(record)-1]
			if len(record) > MaxRecordBytes {
				return nil, false, errRecordTooLarge
			}
			return record, true, nil
		}

		if len(record) > MaxRecordBytes {
			return nil, false, errRecordTooLarge
		}
		if errors.Is(readErr, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(readErr, io.EOF) {
			if len(record) == 0 {
				return nil, false, io.EOF
			}
			return record, false, nil
		}
		return nil, false, readErr
	}
}

// ReadEventsFromOffset reads audit events from path starting at the given byte offset.
// Returns the parsed events, the new file offset, and any error.
// If the file has been truncated (offset > size), it resets to the beginning.
// Partial (unterminated) lines are not consumed — the offset stays before them
// so they can be re-read once complete.
func ReadEventsFromOffset(path string, offset int64) ([]Event, int64, error) {
	f, err := OpenRegularFile(path)
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

	reader := bufio.NewReaderSize(f, auditReaderBufferBytes)
	cursor := offset
	events := make([]Event, 0, 8)

	for {
		line, complete, readErr := readRecord(reader)
		if errors.Is(readErr, io.EOF) {
			return events, cursor, nil
		}
		if readErr != nil {
			return nil, cursor, fmt.Errorf("audit: read record at offset %d: %w", cursor, readErr)
		}

		// Partial line (no trailing newline) — don't consume it.
		if !complete {
			return events, cursor, nil
		}

		cursor += int64(len(line) + 1)
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}

		var evt Event
		if unmarshalErr := json.Unmarshal(trimmed, &evt); unmarshalErr == nil {
			events = append(events, evt)
		}
	}
}
