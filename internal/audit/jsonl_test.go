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
	"encoding/json"
	"io"
	"log/slog"
	"sort"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type chainHeader struct {
	ChainContinue string `json:"chain_continue"`
	PrevFile      string `json:"prev_file"`
}

func TestJSONLSinkWrite_ValidJSONLine(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "writes event as json line"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			sink, err := NewJSONLSink(dir, WithFsync(false))
			require.NoError(t, err)
			t.Cleanup(func() { _ = sink.Close() })

			event := sampleEvent("exec")
			require.NoError(t, sink.Write(event))

			lines := readJSONLLines(t, sink.filePath())
			require.Len(t, lines, 1)

			var parsed Event
			require.NoError(t, json.Unmarshal([]byte(lines[0]), &parsed))
			assert.NotEmpty(t, parsed.Hash)
			assert.Equal(t, "exec", parsed.Tool)
		})
	}
}

func TestJSONLSinkWrite_HashChainValid(t *testing.T) {
	dir := t.TempDir()
	sink, err := NewJSONLSink(dir, WithFsync(false))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sink.Close() })

	for i := 0; i < 3; i++ {
		require.NoError(t, sink.Write(sampleEvent("exec")))
	}

	lines := readJSONLLines(t, sink.filePath())
	require.Len(t, lines, 3)

	prev := ""
	for i, line := range lines {
		var event Event
		require.NoError(t, json.Unmarshal([]byte(line), &event))
		assert.Equal(t, prev, event.PrevHash, "line %d prev_hash mismatch", i)
		ok, err := event.VerifyHash()
		require.NoError(t, err)
		assert.True(t, ok, "line %d hash should verify", i)
		prev = event.Hash
	}
}

func TestJSONLSinkWrite_TamperDetected(t *testing.T) {
	dir := t.TempDir()
	sink, err := NewJSONLSink(dir, WithFsync(false))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sink.Close() })

	require.NoError(t, sink.Write(sampleEvent("exec")))
	require.NoError(t, sink.Write(sampleEvent("read")))

	lines := readJSONLLines(t, sink.filePath())
	require.Len(t, lines, 2)

	var event Event
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &event))
	event.Request["command"] = "rm -rf /"

	ok, err := event.VerifyHash()
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestJSONLSinkWrite_AnchorEveryN(t *testing.T) {
	dir := t.TempDir()
	sink, err := NewJSONLSink(dir, WithFsync(false), WithAnchorInterval(2))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sink.Close() })

	require.NoError(t, sink.Write(sampleEvent("exec")))
	require.NoError(t, sink.Write(sampleEvent("exec")))
	require.NoError(t, sink.Write(sampleEvent("exec")))

	anchorPath := filepath.Join(dir, anchorFilename)
	data, err := os.ReadFile(anchorPath)
	require.NoError(t, err)

	var anchor ChainAnchor
	require.NoError(t, json.Unmarshal(data, &anchor))
	assert.EqualValues(t, 2, anchor.EventCount)
	assert.Equal(t, sink.currentFile, anchor.File)
	assert.NotEmpty(t, anchor.Hash)
}

func TestJSONLSinkWrite_ConcurrentNoCorruption(t *testing.T) {
	dir := t.TempDir()
	sink, err := NewJSONLSink(dir, WithFsync(false))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sink.Close() })

	const workers = 8
	const perWorker = 25

	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func(worker int) {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				e := sampleEvent("exec")
				e.Request["worker"] = worker
				e.Request["index"] = j
				require.NoError(t, sink.Write(e))
			}
		}(i)
	}
	wg.Wait()

	lines := readJSONLLines(t, sink.filePath())
	require.Len(t, lines, workers*perWorker)

	for _, line := range lines {
		var event Event
		require.NoError(t, json.Unmarshal([]byte(line), &event))
		ok, err := event.VerifyHash()
		require.NoError(t, err)
		assert.True(t, ok)
	}
}

func TestJSONLSinkWrite_RotationCreatesNewFileWithChainContinuation(t *testing.T) {
	dir := t.TempDir()
	// Each event is ~460 bytes JSON + newline. Set rotate at 500 so rotation
	// triggers after every single event, guaranteeing multiple files.
	sink, err := NewJSONLSink(dir,
		WithFsync(false),
		WithRotateSize(500),
		WithAnchorInterval(0),
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sink.Close() })

	// Write enough events to trigger multiple rotations.
	for i := 0; i < 5; i++ {
		require.NoError(t, sink.Write(sampleEvent("exec")))
	}

	// Should have multiple JSONL files now.
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	require.NoError(t, err)
	sort.Strings(files) // ensure deterministic order
	assert.GreaterOrEqual(t, len(files), 2, "expected at least 2 rotated files, got %d", len(files))

	// Every file after the first should start with a chain continuation header.
	for i, f := range files {
		if i == 0 {
			continue
		}

		lines := readJSONLLines(t, f)
		require.NotEmpty(t, lines, "rotated file %s is empty", f)

		var header chainHeader
		require.NoError(t, json.Unmarshal([]byte(lines[0]), &header), "first line of %s is not valid chain header", f)
		assert.NotEmpty(t, header.ChainContinue, "chain_continue should reference previous hash in %s", f)
		assert.NotEmpty(t, header.PrevFile, "prev_file should be set in %s", f)
	}

	// Verify the full chain is valid across all files — collect all events in order.
	var allEvents []Event
	for _, f := range files {
		lines := readJSONLLines(t, f)
		for _, line := range lines {
			var event Event
			if err := json.Unmarshal([]byte(line), &event); err != nil {
				continue // skip chain continuation headers (they don't unmarshal to Event)
			}
			if event.ID == "" {
				continue // chain continuation header, not an event
			}
			allEvents = append(allEvents, event)
		}
	}
	require.Len(t, allEvents, 5)

	prev := ""
	for i, event := range allEvents {
		assert.Equal(t, prev, event.PrevHash, "event %d prev_hash mismatch across rotation", i)
		ok, verifyErr := event.VerifyHash()
		require.NoError(t, verifyErr)
		assert.True(t, ok, "event %d hash should verify", i)
		prev = event.Hash
	}
}

func TestJSONLSinkWrite_ClosedSinkReturnsError(t *testing.T) {
	dir := t.TempDir()
	sink, err := NewJSONLSink(dir,
		WithFsync(false),
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
	)
	require.NoError(t, err)
	require.NoError(t, sink.Close())

	err = sink.Write(sampleEvent("exec"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

func TestNewEventID_ValidULID(t *testing.T) {
	for i := 0; i < 50; i++ {
		id := NewEventID()
		parsed, err := ulid.Parse(id)
		require.NoError(t, err)
		assert.Equal(t, id, parsed.String())
	}
}

func BenchmarkWrite(b *testing.B) {
	dir := b.TempDir()
	sink, err := NewJSONLSink(dir,
		WithFsync(false),
		WithAnchorInterval(1000000),
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
	)
	require.NoError(b, err)
	b.Cleanup(func() { _ = sink.Close() })

	event := sampleEvent("exec")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e := event
		e.ID = ""
		require.NoError(b, sink.Write(e))
	}
}

func sampleEvent(tool string) Event {
	return Event{
		ID:        "",
		Timestamp: time.Now().UTC(),
		Agent:     "agent-1",
		Session:   "session-1",
		Tool:      tool,
		Request: map[string]any{
			"command": "echo hello",
		},
		Decision: EventDecision{
			Action:          "allow",
			EvalTimeUS:      42,
			Message:         "ok",
			MatchedPolicies: []string{"allow-safe"},
		},
		Response: &ToolResponse{DurationMS: 5},
	}
}

func readJSONLLines(t *testing.T, path string) []string {
	t.Helper()

	file, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = file.Close() }()

	var lines []string
	s := bufio.NewScanner(file)
	for s.Scan() {
		line := s.Text()
		if line != "" {
			lines = append(lines, line)
		}
	}
	require.NoError(t, s.Err())
	return lines
}
