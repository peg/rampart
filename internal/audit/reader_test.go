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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadEventsFromOffset_BackwardCompatibleMissingFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.jsonl")
	line := `{"id":"01JTEST000000000000000000","timestamp":"2026-02-12T00:00:00Z","agent":"agent-1","session":"session-1","tool":"exec","request":{"command":"echo hello"},"decision":{"action":"allow","evaluation_time_us":10},"prev_hash":"","hash":"sha256:abc"}` + "\n"
	require.NoError(t, os.WriteFile(path, []byte(line), 0o600))

	events, _, err := ReadEventsFromOffset(path, 0)
	require.NoError(t, err)
	require.Len(t, events, 1)

	require.Empty(t, events[0].SchemaVersion)
	require.Nil(t, events[0].Host)
}

func TestReadEventsFromOffset_LargeRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.jsonl")
	command := strings.Repeat("x", 96*1024)
	line := `{"id":"large","timestamp":"2026-02-12T00:00:00Z","tool":"exec","request":{"command":"` + command + `"},"decision":{"action":"allow"}}` + "\n"
	require.NoError(t, os.WriteFile(path, []byte(line), 0o600))

	events, offset, err := ReadEventsFromOffset(path, 0)
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.Equal(t, command, events[0].Request["command"])
	require.EqualValues(t, len(line), offset)
}

func TestReadEventsFromOffset_RejectsOversizedRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "oversized.jsonl")
	record := append([]byte(strings.Repeat("x", MaxRecordBytes+1)), '\n')
	require.NoError(t, os.WriteFile(path, record, 0o600))

	events, offset, err := ReadEventsFromOffset(path, 0)
	require.ErrorContains(t, err, "record exceeds")
	require.Nil(t, events)
	require.Zero(t, offset)
}
