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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestVerifyHash_LegacyEventWithoutSchemaAndHost(t *testing.T) {
	type legacyEvent struct {
		ID        string         `json:"id"`
		Timestamp time.Time      `json:"timestamp"`
		Agent     string         `json:"agent"`
		Session   string         `json:"session"`
		Tool      string         `json:"tool"`
		Request   map[string]any `json:"request"`
		Decision  EventDecision  `json:"decision"`
		PrevHash  string         `json:"prev_hash"`
		Hash      string         `json:"hash"`
	}

	legacy := legacyEvent{
		ID:        "01JTEST000000000000000100",
		Timestamp: time.Date(2026, 2, 12, 10, 0, 0, 0, time.UTC),
		Agent:     "agent-1",
		Session:   "session-1",
		Tool:      "exec",
		Request:   map[string]any{"command": "echo hello", "rounded_sequence": float64(9007199254740993), "decimal": 0.1, "exponent": 1e30},
		Decision:  EventDecision{Action: "allow", EvalTimeUS: 7},
		PrevHash:  "",
	}

	forHash := legacy
	forHash.Hash = ""
	data, err := json.Marshal(forHash)
	require.NoError(t, err)

	sum := sha256.Sum256(append([]byte(legacy.PrevHash), data...))
	legacy.Hash = "sha256:" + hex.EncodeToString(sum[:])

	line, err := json.Marshal(legacy)
	require.NoError(t, err)

	var parsed Event
	require.NoError(t, json.Unmarshal(line, &parsed))
	require.Empty(t, parsed.SchemaVersion)
	require.Nil(t, parsed.Host)
	// Older float64 ingress already rounded this value before writing. Preserve
	// those valid historical bytes; never claim to recover the original input.
	require.Equal(t, json.Number("9007199254740992"), parsed.Request["rounded_sequence"])
	roundTrip, err := json.Marshal(parsed)
	require.NoError(t, err)
	require.Equal(t, line, roundTrip)

	ok, err := parsed.VerifyHash()
	require.NoError(t, err)
	require.True(t, ok)
}

func TestEventDecodePreservesExactNumbersForHashVerification(t *testing.T) {
	event := Event{
		Request: map[string]any{
			"sequence": json.Number("9007199254740993"),
			"nested":   []any{json.Number("0.1234567890123456789"), json.Number("1e20"), json.Number("1e400")},
		},
		ApprovalOwner: map[string]any{"sequence": json.Number("9007199254740993")},
	}
	require.NoError(t, event.ComputeHash())
	data, err := json.Marshal(event)
	require.NoError(t, err)
	var decoded Event
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Equal(t, event.Request, decoded.Request)
	require.Equal(t, event.ApprovalOwner, decoded.ApprovalOwner)
	valid, err := decoded.VerifyHash()
	require.NoError(t, err)
	require.True(t, valid)

	// A neighboring integer must not verify via the same rounded float. Keep
	// the original hash while changing one exact security-bearing value.
	tampered := bytes.Replace(data, []byte(`"sequence":9007199254740993`), []byte(`"sequence":9007199254740992`), 1)
	require.NotEqual(t, data, tampered)
	require.NoError(t, json.Unmarshal(tampered, &decoded))
	valid, err = decoded.VerifyHash()
	require.NoError(t, err)
	require.False(t, valid)
}

// The hash covers the typed event, so stored bytes the typed event drops must
// fail verification rather than leave a valid hash on a changed record.
func TestVerifyHashRejectsContentTheHashDoesNotCover(t *testing.T) {
	event := Event{
		ID:        "01JTESTUNCOVERED000000000",
		Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Agent:     "test",
		Tool:      "exec",
		Request:   map[string]any{"command": "git status", "Mixed": "kept", "items": []any{map[string]any{"k": 1}}},
		Decision:  EventDecision{Action: "allow", Message: "ok"},
	}
	if err := event.ComputeHash(); err != nil {
		t.Fatal(err)
	}
	line, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	clean := string(line)
	verify := func(t *testing.T, record string) bool {
		t.Helper()
		var decoded Event
		if err := json.Unmarshal([]byte(record), &decoded); err != nil {
			t.Fatalf("decode: %v", err)
		}
		ok, err := decoded.VerifyHash()
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !verify(t, clean) {
		t.Fatal("an unmodified record must verify")
	}
	if !verify(t, " "+strings.Replace(clean, `,"tool":`, `, "tool": `, 1)) {
		t.Fatal("whitespace outside values is not content and must still verify")
	}

	for name, record := range map[string]string{
		"unknown top-level field":  strings.Replace(clean, `"tool":"exec"`, `"tool":"exec","note":"added"`, 1),
		"unknown decision field":   strings.Replace(clean, `"action":"allow"`, `"action":"allow","approved_by":"x"`, 1),
		"duplicate top-level key":  strings.Replace(clean, `"tool":"exec"`, `"tool":"read","tool":"exec"`, 1),
		"duplicate request key":    strings.Replace(clean, `"command":"git status"`, `"command":"other","command":"git status"`, 1),
		"case variant schema key":  strings.Replace(clean, `"tool":"exec"`, `"Tool":"exec"`, 1),
		"case variant duplicate":   strings.Replace(clean, `"tool":"exec"`, `"TOOL":"read","tool":"exec"`, 1),
		"escaped duplicate key":    strings.Replace(clean, `"tool":"exec"`, `"\u0074ool":"read","tool":"exec"`, 1),
		"nested request duplicate": strings.Replace(clean, `{"k":1}`, `{"k":2,"k":1}`, 1),
		"folded non-ASCII key":     strings.Replace(clean, `"decision":`, `"decision":{"action":"deny"},"deciſion":`, 1),
		"escaped folded key":       strings.Replace(clean, `"decision":`, `"decision":{"action":"deny"},"deci\u017fion":`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if record == clean {
				t.Fatal("mutation did not apply")
			}
			if verify(t, record) {
				t.Fatalf("record verified with uncovered content: %s", record)
			}
		})
	}
}
