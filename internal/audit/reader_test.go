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
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
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

func TestReadEventsFromOffset_SkipsChainContinuationHeaders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rotated.jsonl")
	header := `{"chain_continue":"sha256:aaa","prev_file":"2026-10-12.jsonl"}` + "\n"
	first := `{"id":"01JEVENT00000000000000001","timestamp":"2026-10-13T00:00:01Z","tool":"exec","decision":{"action":"allow"}}` + "\n"
	second := `{"id":"01JEVENT00000000000000002","timestamp":"2026-10-13T00:00:02Z","tool":"read","decision":{"action":"deny"}}` + "\n"
	require.NoError(t, os.WriteFile(path, []byte(header+first+second), 0o600))

	events, offset, err := ReadEventsFromOffset(path, 0)
	require.NoError(t, err)
	require.Len(t, events, 2, "the header is chain bookkeeping, not an event")
	require.Equal(t, "01JEVENT00000000000000001", events[0].ID)
	require.Equal(t, "01JEVENT00000000000000002", events[1].ID)
	for _, event := range events {
		require.False(t, event.Timestamp.IsZero())
	}
	require.EqualValues(t, len(header+first+second), offset, "the header is still consumed so tailing does not reread it")

	// Resuming from after the header must behave identically.
	resumed, _, err := ReadEventsFromOffset(path, int64(len(header)))
	require.NoError(t, err)
	require.Len(t, resumed, 2)
}

func TestReadEventsFromOffset_OnlyRealHeadersAreSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lookalikes.jsonl")
	// An event that merely mentions the header's field names is an event.
	mention := `{"id":"01JEVENT0000000000000000A","timestamp":"2026-10-13T00:00:01Z","tool":"exec","request":{"command":"echo \"chain_continue\" prev_file"},"decision":{"action":"allow"}}` + "\n"
	// The verifier requires both top-level fields; one alone is not a header.
	onlyOne := `{"chain_continue":"sha256:aaa","id":"01JEVENT0000000000000000B","timestamp":"2026-10-13T00:00:02Z","tool":"exec","decision":{"action":"allow"}}` + "\n"
	require.NoError(t, os.WriteFile(path, []byte(mention+onlyOne), 0o600))

	events, _, err := ReadEventsFromOffset(path, 0)
	require.NoError(t, err)
	require.Len(t, events, 2)
}

func TestReadEventsFromOffset_AfterRotationReturnsOnlyWrittenEvents(t *testing.T) {
	dir := t.TempDir()
	sink, err := NewJSONLSink(dir,
		WithFsync(false),
		WithRotateSize(500),
		WithAnchorInterval(0),
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sink.Close() })

	const written = 5
	for i := 0; i < written; i++ {
		require.NoError(t, sink.Write(sampleEvent("exec")))
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	require.NoError(t, err)
	sort.Strings(files)
	require.GreaterOrEqual(t, len(files), 2, "the small rotation size must produce rotated files with headers")

	total := 0
	for _, file := range files {
		events, _, err := ReadEventsFromOffset(file, 0)
		require.NoError(t, err)
		for _, event := range events {
			require.NotEmpty(t, event.ID, "%s returned a blank record", file)
			require.False(t, event.Timestamp.IsZero(), "%s returned a record without a timestamp", file)
			total++
		}
	}
	require.Equal(t, written, total)
}
