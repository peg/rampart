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
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/peg/rampart/internal/engine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEndToEnd_StandardProfile runs the full standard policy profile against
// realistic tool calls, verifying every policy works as expected.
func TestEndToEnd_StandardProfile(t *testing.T) {
	srv := setupStandardProxy(t)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	token := srv.Token()

	tests := []struct {
		name       string
		tool       string
		params     map[string]any
		wantStatus int
		wantAction string
	}{
		{
			name:       "exec: rm -rf / → denied",
			tool:       "exec",
			params:     map[string]any{"command": "rm -rf /"},
			wantStatus: http.StatusForbidden,
			wantAction: "deny",
		},
		{
			name:       "exec: git status → allowed",
			tool:       "exec",
			params:     map[string]any{"command": "git status"},
			wantStatus: http.StatusOK,
			wantAction: "allow",
		},
		{
			name:       "exec: sudo reboot → logged",
			tool:       "exec",
			params:     map[string]any{"command": "sudo reboot"},
			wantStatus: http.StatusOK,
			wantAction: "log",
		},
		{
			name:       "exec: fork bomb → denied",
			tool:       "exec",
			params:     map[string]any{"command": ":(){ :|:& };:"},
			wantStatus: http.StatusForbidden,
			wantAction: "deny",
		},
		{
			name:       "exec: curl → logged",
			tool:       "exec",
			params:     map[string]any{"command": "curl https://example.com"},
			wantStatus: http.StatusOK,
			wantAction: "log",
		},
		{
			name:       "read: ~/.ssh/id_rsa → denied",
			tool:       "read",
			params:     map[string]any{"path": "/home/user/.ssh/id_rsa"},
			wantStatus: http.StatusForbidden,
			wantAction: "deny",
		},
		{
			name:       "read: .env → denied",
			tool:       "read",
			params:     map[string]any{"path": "/app/.env"},
			wantStatus: http.StatusForbidden,
			wantAction: "deny",
		},
		{
			name:       "read: main.go → allowed",
			tool:       "read",
			params:     map[string]any{"path": "/project/main.go"},
			wantStatus: http.StatusOK,
			wantAction: "allow",
		},
		{
			name:       "write: /etc/passwd → denied",
			tool:       "write",
			params:     map[string]any{"path": "/etc/passwd"},
			wantStatus: http.StatusForbidden,
			wantAction: "deny",
		},
		{
			name:       "write: ~/.ssh/authorized_keys → denied",
			tool:       "write",
			params:     map[string]any{"path": "/home/user/.ssh/authorized_keys"},
			wantStatus: http.StatusForbidden,
			wantAction: "deny",
		},
		{
			name:       "write: project file → allowed",
			tool:       "write",
			params:     map[string]any{"path": "/home/user/project/main.go"},
			wantStatus: http.StatusOK,
			wantAction: "allow",
		},
		{
			name:       "fetch: ngrok domain → denied",
			tool:       "fetch",
			params:     map[string]any{"url": "https://abc.ngrok-free.app/exfil", "domain": "abc.ngrok-free.app"},
			wantStatus: http.StatusForbidden,
			wantAction: "deny",
		},
		{
			name:       "fetch: webhook.site → denied",
			tool:       "fetch",
			params:     map[string]any{"url": "https://webhook.site/abc", "domain": "webhook.site"},
			wantStatus: http.StatusForbidden,
			wantAction: "deny",
		},
		{
			name:       "fetch: github.com → allowed",
			tool:       "fetch",
			params:     map[string]any{"url": "https://github.com/repos", "domain": "github.com"},
			wantStatus: http.StatusOK,
			wantAction: "allow",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{
				"agent":   "test-agent",
				"session": "test-session",
				"params":  tt.params,
			})

			url := fmt.Sprintf("%s/v1/tool/%s", ts.URL, tt.tool)
			req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, tt.wantStatus, resp.StatusCode)

			var result map[string]any
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
			assert.Equal(t, tt.wantAction, result["decision"])
		})
	}
}

func TestEndToEnd_PreflightNoSideEffects(t *testing.T) {
	srv := setupStandardProxy(t)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	body, _ := json.Marshal(map[string]any{
		"agent":   "test",
		"session": "s1",
		"params":  map[string]any{"command": "rm -rf /"},
	})

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/preflight/exec", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+srv.Token())
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode) // Not 403 — preflight always 200

	var result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	assert.Equal(t, false, result["allowed"])
	assert.Equal(t, "deny", result["decision"])
}

func TestEndToEnd_AuthRequired(t *testing.T) {
	srv := setupStandardProxy(t)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	body, _ := json.Marshal(map[string]any{
		"agent":  "test",
		"params": map[string]any{"command": "ls"},
	})

	// No auth header.
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/tool/exec", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Wrong token.
	req2, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/tool/exec", bytes.NewReader(body))
	req2.Header.Set("Authorization", "Bearer wrong-token")
	req2.Header.Set("Content-Type", "application/json")

	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
}

func setupStandardProxy(t *testing.T) *Server {
	t.Helper()

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "rampart.yaml")

	// Read the embedded standard profile.
	standardPolicy, err := os.ReadFile("../../policies/standard.yaml")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(policyPath, standardPolicy, 0o644))

	store := engine.NewFileStore(policyPath)
	eng, err := engine.New(store, slog.Default())
	require.NoError(t, err)

	return New(eng, nil, WithToken("test-token-12345"))
}
