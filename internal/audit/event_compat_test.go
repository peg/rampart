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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
		Request:   map[string]any{"command": "echo hello"},
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

	ok, err := parsed.VerifyHash()
	require.NoError(t, err)
	require.True(t, ok)
}
