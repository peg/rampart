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

package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peg/rampart/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupLearnTestServer(t *testing.T) (*httptest.Server, string, string) {
	t.Helper()

	srv, token, _ := setupTestServer(t, testPolicyYAML, "enforce")

	// Override HOME (Linux/macOS) and USERPROFILE (Windows) so user-overrides.yaml goes to a temp dir.
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("USERPROFILE", tmpHome)

	ts := httptest.NewServer(srv.handler())
	t.Cleanup(ts.Close)

	return ts, token, tmpHome
}

func postLearn(t *testing.T, ts *httptest.Server, token, body string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/rules/learn", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestLearnRule_CreatesRule(t *testing.T) {
	ts, token, tmpHome := setupLearnTestServer(t)

	body := `{"tool":"exec","args":"sudo apt-get install nmap","decision":"allow","source":"openclaw-approval","agent":"main","session":"abc123"}`
	resp := postLearn(t, ts, token, body)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var result learnResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))

	assert.Equal(t, "sudo apt-get install *", result.Pattern)
	assert.Equal(t, "exec", result.Tool)
	assert.Equal(t, "allow", result.Decision)
	assert.Equal(t, "openclaw-approval", result.Source)
	assert.Contains(t, result.RuleName, "user-allow-")

	// Verify file was written.
	overridesPath := filepath.Join(tmpHome, ".rampart", "policies", "user-overrides.yaml")
	data, err := os.ReadFile(overridesPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), result.RuleName)
	assert.Contains(t, string(data), "sudo apt-get install *")
}

func TestLearnRule_Duplicate409(t *testing.T) {
	ts, token, _ := setupLearnTestServer(t)

	body := `{"tool":"exec","args":"sudo apt-get install nmap","decision":"allow","source":"openclaw-approval"}`

	// First call — 201.
	resp1 := postLearn(t, ts, token, body)
	assert.Equal(t, http.StatusCreated, resp1.StatusCode)

	// Second call with same args — 409.
	resp2 := postLearn(t, ts, token, body)
	assert.Equal(t, http.StatusConflict, resp2.StatusCode)

	var result learnResponse
	require.NoError(t, json.NewDecoder(resp2.Body).Decode(&result))
	assert.Equal(t, "sudo apt-get install *", result.Pattern)
}

func TestLearnRule_MissingFields(t *testing.T) {
	ts, token, _ := setupLearnTestServer(t)

	tests := []struct {
		name string
		body string
	}{
		{"missing tool", `{"args":"ls","decision":"allow"}`},
		{"missing args", `{"tool":"exec","decision":"allow"}`},
		{"missing both", `{"decision":"allow"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := postLearn(t, ts, token, tt.body)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})
	}
}

func TestLearnRule_InvalidDecision(t *testing.T) {
	ts, token, _ := setupLearnTestServer(t)

	body := `{"tool":"exec","args":"ls","decision":"maybe"}`
	resp := postLearn(t, ts, token, body)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestLearnRule_CorrectGlob(t *testing.T) {
	tests := []struct {
		args    string
		pattern string
	}{
		{"sudo apt-get install nmap", "sudo apt-get install *"},
		{"sudo apt-get install nmap --dry-run 2>&1 | head -1", "sudo apt-get install nmap *"},
		{"docker run nginx", "docker run *"},
		{"ls", "ls"},
		{"cat /etc/hosts", "cat /etc/hosts *"},
	}

	for _, tt := range tests {
		t.Run(tt.args, func(t *testing.T) {
			got := policy.BuildAllowPattern(tt.args)
			assert.Equal(t, tt.pattern, got)
		})
	}
}

func TestLearnRule_NoAuth(t *testing.T) {
	ts, _, _ := setupLearnTestServer(t)

	body := `{"tool":"exec","args":"ls","decision":"allow"}`
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/rules/learn", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	// No Authorization header.

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
