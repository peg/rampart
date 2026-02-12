package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peg/rampart/internal/engine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupWebhookServer(t *testing.T, webhookURL string, failOpen bool) (*Server, string) {
	t.Helper()

	failOpenStr := "true"
	if !failOpen {
		failOpenStr = "false"
	}

	yaml := fmt.Sprintf(`
version: "1"
default_action: allow
policies:
  - name: webhook-policy
    match:
      tool: exec
    rules:
      - action: webhook
        when:
          command_matches: ["*dangerous*"]
        webhook:
          url: "%s"
          timeout: 2s
          fail_open: %s
`, webhookURL, failOpenStr)

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0o644))

	store := engine.NewFileStore(path)
	eng, err := engine.New(store, nil)
	require.NoError(t, err)

	token := "test-token-123"
	srv := New(eng, nil, WithToken(token), WithMode("enforce"))
	return srv, token
}

func TestWebhookActionAllow(t *testing.T) {
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req webhookActionRequest
		require.NoError(t, json.Unmarshal(body, &req))
		assert.Equal(t, "exec", req.Tool)
		assert.Equal(t, "test-agent", req.Agent)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(webhookActionResponse{Decision: "allow"})
	}))
	defer webhook.Close()

	srv, token := setupWebhookServer(t, webhook.URL, true)

	body := `{"agent":"test-agent","session":"s1","params":{"command":"dangerous deploy"}}`
	req := httptest.NewRequest("POST", "/v1/tool/exec", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	srv.handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "allow", resp["decision"])
}

func TestWebhookActionDeny(t *testing.T) {
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(webhookActionResponse{Decision: "deny", Reason: "too dangerous"})
	}))
	defer webhook.Close()

	srv, token := setupWebhookServer(t, webhook.URL, true)

	body := `{"agent":"test-agent","session":"s1","params":{"command":"dangerous deploy"}}`
	req := httptest.NewRequest("POST", "/v1/tool/exec", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	srv.handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "deny", resp["decision"])
	assert.Equal(t, "too dangerous", resp["message"])
}

func TestWebhookActionTimeoutFailOpen(t *testing.T) {
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second) // longer than 2s timeout
	}))
	defer webhook.Close()

	srv, token := setupWebhookServer(t, webhook.URL, true)

	body := `{"agent":"test-agent","session":"s1","params":{"command":"dangerous op"}}`
	req := httptest.NewRequest("POST", "/v1/tool/exec", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	srv.handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "allow", resp["decision"])
	assert.Contains(t, resp["message"], "failing open")
}

func TestWebhookActionTimeoutFailClosed(t *testing.T) {
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer webhook.Close()

	srv, token := setupWebhookServer(t, webhook.URL, false)

	body := `{"agent":"test-agent","session":"s1","params":{"command":"dangerous op"}}`
	req := httptest.NewRequest("POST", "/v1/tool/exec", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	srv.handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "deny", resp["decision"])
	assert.Contains(t, resp["message"], "failing closed")
}

func TestWebhookActionServerError(t *testing.T) {
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer webhook.Close()

	srv, token := setupWebhookServer(t, webhook.URL, true)

	body := `{"agent":"test-agent","session":"s1","params":{"command":"dangerous op"}}`
	req := httptest.NewRequest("POST", "/v1/tool/exec", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	srv.handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "allow", resp["decision"])
	assert.Contains(t, resp["message"], "failing open")
}

func TestWebhookActionPayloadFormat(t *testing.T) {
	var received webhookActionRequest

	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &received)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(webhookActionResponse{Decision: "allow"})
	}))
	defer webhook.Close()

	srv, token := setupWebhookServer(t, webhook.URL, true)

	body := `{"agent":"claude-code","session":"abc123","params":{"command":"dangerous rm -rf /"}}`
	req := httptest.NewRequest("POST", "/v1/tool/exec", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	srv.handler().ServeHTTP(w, req)

	assert.Equal(t, "exec", received.Tool)
	assert.Equal(t, "claude-code", received.Agent)
	assert.Equal(t, "abc123", received.Session)
	assert.Equal(t, "webhook-policy", received.Policy)
	assert.NotEmpty(t, received.Timestamp)
}

func TestWebhookNonMatchingCommandSkipsWebhook(t *testing.T) {
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("webhook should not be called for non-matching commands")
	}))
	defer webhook.Close()

	srv, token := setupWebhookServer(t, webhook.URL, true)

	body := `{"agent":"test-agent","session":"s1","params":{"command":"ls -la"}}`
	req := httptest.NewRequest("POST", "/v1/tool/exec", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	srv.handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "allow", resp["decision"])
}
