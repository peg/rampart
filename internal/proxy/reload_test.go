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

const reloadPolicyYAML = `
version: "1"
default_action: allow
policies:
  - name: block-rm
    match:
      tool: exec
    rules:
      - action: deny
        when:
          command_matches: ["rm -rf *"]
        message: "destructive command blocked"
  - name: allow-git
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["git *"]
        message: "git allowed"
`

const reloadPolicyYAMLUpdated = `
version: "1"
default_action: allow
policies:
  - name: block-rm
    match:
      tool: exec
    rules:
      - action: deny
        when:
          command_matches: ["rm -rf *"]
        message: "destructive command blocked"
  - name: allow-git
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["git *"]
        message: "git allowed"
  - name: block-curl
    match:
      tool: exec
    rules:
      - action: deny
        when:
          command_matches: ["curl *"]
        message: "curl blocked"
`

// setupReloadTestServer creates a test server backed by a temp policy file,
// returning the server, token, policy file path, and a closer function.
func setupReloadTestServer(t *testing.T, configYAML string) (*Server, string, string) {
	t.Helper()

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	require.NoError(t, os.WriteFile(policyPath, []byte(configYAML), 0o644))

	store := engine.NewFileStore(policyPath)
	eng, err := engine.New(store, slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil)))
	require.NoError(t, err)

	token := "reload-test-token"
	srv := New(
		eng,
		nil,
		WithMode("enforce"),
		WithToken(token),
		WithLogger(slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))),
	)

	return srv, token, policyPath
}

// TestHandlePolicyReload_Success verifies a successful reload returns the
// expected JSON structure with correct counts.
func TestHandlePolicyReload_Success(t *testing.T) {
	srv, token, _ := setupReloadTestServer(t, reloadPolicyYAML)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/policy/reload", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body := decodeBody(t, resp)
	assert.Equal(t, true, body["success"])
	assert.Equal(t, float64(2), body["policies_loaded"])
	assert.Equal(t, float64(2), body["rules_total"])
	assert.NotNil(t, body["reload_time_ms"])
}

// TestHandlePolicyReload_UpdatesLivePolicy verifies that after modifying the
// policy file and calling reload, the new policy count is reflected.
func TestHandlePolicyReload_UpdatesLivePolicy(t *testing.T) {
	srv, token, policyPath := setupReloadTestServer(t, reloadPolicyYAML)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	// Verify initial state: 2 policies.
	assert.Equal(t, 2, srv.engine.PolicyCount())

	// Update the policy file with a new policy (3 policies).
	require.NoError(t, os.WriteFile(policyPath, []byte(reloadPolicyYAMLUpdated), 0o644))

	// Trigger reload via the API.
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/policy/reload", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body := decodeBody(t, resp)
	assert.Equal(t, true, body["success"])
	// Updated policy has 3 policies and 3 rules.
	assert.Equal(t, float64(3), body["policies_loaded"])
	assert.Equal(t, float64(3), body["rules_total"])

	// Verify the engine itself was updated.
	assert.Equal(t, 3, srv.engine.PolicyCount())
}

// TestHandlePolicyReload_RequiresAuth ensures the endpoint returns 401
// when no auth token is provided.
func TestHandlePolicyReload_RequiresAuth(t *testing.T) {
	srv, _, _ := setupReloadTestServer(t, reloadPolicyYAML)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/policy/reload", nil)
	require.NoError(t, err)
	// No Authorization header.

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestHandlePolicyReload_InvalidToken ensures the endpoint returns 401
// with a wrong token.
func TestHandlePolicyReload_InvalidToken(t *testing.T) {
	srv, _, _ := setupReloadTestServer(t, reloadPolicyYAML)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/policy/reload", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer wrong-token")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestHandlePolicyReload_InvalidPolicy verifies that reloading an invalid
// policy file returns 500 and the engine retains the old (valid) config.
func TestHandlePolicyReload_InvalidPolicy(t *testing.T) {
	srv, token, policyPath := setupReloadTestServer(t, reloadPolicyYAML)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	initialCount := srv.engine.PolicyCount()
	require.Equal(t, 2, initialCount)

	// Write a syntactically broken YAML.
	require.NoError(t, os.WriteFile(policyPath, []byte("{{invalid yaml::{{"), 0o644))

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/policy/reload", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

	body := decodeBody(t, resp)
	assert.Equal(t, false, body["success"])
	assert.NotEmpty(t, body["error"])

	// Engine must still have the original policy loaded.
	assert.Equal(t, 2, srv.engine.PolicyCount())
}

// TestReloadClient_Success verifies the ReloadPolicy client function against
// a real httptest.Server.
func TestReloadClient_Success(t *testing.T) {
	srv, token, _ := setupReloadTestServer(t, reloadPolicyYAML)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	result, err := ReloadPolicy(ts.URL, token)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.True(t, result.Success)
	assert.Equal(t, 2, result.PoliciesLoaded)
	assert.Equal(t, 2, result.RulesTotal)
	assert.GreaterOrEqual(t, result.ReloadTimeMs, int64(0))
}

// TestReloadClient_WrongToken verifies the client returns an error on 401.
func TestReloadClient_WrongToken(t *testing.T) {
	srv, _, _ := setupReloadTestServer(t, reloadPolicyYAML)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	_, err := ReloadPolicy(ts.URL, "wrong-token")
	require.Error(t, err)
}

// TestReloadClient_UnreachableServer verifies the client returns an error
// when the server is not running.
func TestReloadClient_UnreachableServer(t *testing.T) {
	_, err := ReloadPolicy("http://127.0.0.1:19999", "some-token")
	require.Error(t, err)
}

// TestHandlePolicyReload_ReturnedResponseFields checks that all documented
// response fields are present.
func TestHandlePolicyReload_ReturnedResponseFields(t *testing.T) {
	srv, token, _ := setupReloadTestServer(t, reloadPolicyYAML)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/policy/reload", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	body := decodeBody(t, resp)
	assert.Contains(t, body, "success")
	assert.Contains(t, body, "policies_loaded")
	assert.Contains(t, body, "rules_total")
	assert.Contains(t, body, "reload_time_ms")
}

// TestEngineStats verifies Engine.Stats() returns consistent data.
func TestEngineStats(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	require.NoError(t, os.WriteFile(policyPath, []byte(reloadPolicyYAML), 0o644))

	store := engine.NewFileStore(policyPath)
	eng, err := engine.New(store, slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil)))
	require.NoError(t, err)

	stats := eng.Stats()
	assert.Equal(t, 2, stats.PolicyCount)
	assert.Equal(t, 2, stats.RuleCount)
	assert.False(t, stats.LastReload.IsZero())

	// Consistency: Stats() agrees with individual methods.
	assert.Equal(t, eng.PolicyCount(), stats.PolicyCount)
	assert.Equal(t, eng.RuleCount(), stats.RuleCount)
	assert.Equal(t, eng.LastLoadedAt(), stats.LastReload)
}
