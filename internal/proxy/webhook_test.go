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
	"sync/atomic"
	"testing"
	"time"

	"github.com/peg/rampart/internal/approval"
	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/internal/signing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type webhookActionRequest struct {
	Tool      string         `json:"tool"`
	Params    map[string]any `json:"params"`
	Agent     string         `json:"agent"`
	Session   string         `json:"session"`
	Policy    string         `json:"policy"`
	Timestamp string         `json:"timestamp"`
}

type webhookActionResponse struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

func TestApprovalNotificationIsSuppressedWithoutSignedResolveURL(t *testing.T) {
	var calls atomic.Int32
	webhook := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	defer webhook.Close()

	srv := New(nil, nil,
		WithToken("test-token"),
		WithNotify(&engine.NotifyConfig{URL: webhook.URL, Platform: "webhook", On: []string{"ask"}}),
	)
	srv.listenAddr = "127.0.0.1:9090"
	now := time.Now().UTC()
	srv.sendApprovalWebhook(
		engine.ToolCall{Tool: "exec", Params: map[string]any{"command": "echo test"}, Timestamp: now},
		engine.Decision{Action: engine.ActionAsk},
		&approval.Request{ID: "approval-1", CreatedAt: now, ExpiresAt: now.Add(time.Minute)},
	)
	assert.Zero(t, calls.Load(), "approval notification must not emit an unusable unsigned link")
}

// MCP calls reach policy as a generic tool type; reviewers deciding them must
// see the server tool name in the notification and the pending list.
func TestPendingMCPApprovalNamesServerTool(t *testing.T) {
	received := make(chan map[string]any, 1)
	webhook := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		_ = json.NewDecoder(r.Body).Decode(&payload)
		received <- payload
	}))
	defer webhook.Close()

	srv := New(nil, nil,
		WithToken("test-token"),
		WithSigner(signing.NewSigner([]byte("0123456789abcdef0123456789abcdef"))),
		WithResolveBaseURL("https://approve.example.com"),
		WithNotify(&engine.NotifyConfig{URL: webhook.URL, Platform: "webhook", On: []string{"ask"}}),
	)
	call := engine.ToolCall{
		Tool:      "mcp-destructive",
		Params:    map[string]any{"mcp_method": "tools/call", "mcp_tool": "delete_repo", "path": "org/repo?token=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		Timestamp: time.Now().UTC(),
	}
	decision := engine.Decision{Action: engine.ActionAsk}
	pending, err := srv.approvals.Create(call, decision)
	require.NoError(t, err)
	srv.sendApprovalWebhook(call, decision, pending)

	select {
	case payload := <-received:
		assert.Equal(t, "mcp-destructive", payload["tool"])
		assert.Equal(t, "delete_repo — org/repo?token=[REDACTED]", payload["command"])
		assert.NotEmpty(t, payload["resolve_url"])
	case <-time.After(2 * time.Second):
		t.Fatal("approval notification was not sent")
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/approvals", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	var list struct {
		Approvals []struct {
			Command string `json:"command"`
		} `json:"approvals"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &list))
	require.Len(t, list.Approvals, 1)
	assert.Equal(t, "delete_repo — org/repo?token=[REDACTED]", list.Approvals[0].Command)
}

// A client with its own notification channel relies on "notified" to know
// whether this server told reviewers about the approval it queued.
func TestCreateApprovalReportsWhetherReviewersWereNotified(t *testing.T) {
	webhook := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer webhook.Close()
	notifyAsk := WithNotify(&engine.NotifyConfig{URL: webhook.URL, Platform: "webhook", On: []string{"ask"}})
	signer := WithSigner(signing.NewSigner([]byte("0123456789abcdef0123456789abcdef")))
	baseURL := WithResolveBaseURL("https://approve.example.com")

	for _, tc := range []struct {
		name string
		opts []Option
		want bool
	}{
		{"notify configured with a signed link", []Option{notifyAsk, signer, baseURL}, true},
		{"no notify configured", []Option{signer, baseURL}, false},
		{"notify does not cover approvals", []Option{WithNotify(&engine.NotifyConfig{URL: webhook.URL, Platform: "webhook", On: []string{"deny"}}), signer, baseURL}, false},
		{"no signed link available", []Option{notifyAsk, baseURL}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := New(nil, nil, append([]Option{WithToken("test-token")}, tc.opts...)...)
			t.Cleanup(srv.approvals.Close)
			body := `{"action_version":1,"tool":"mcp","agent":"test","session":"s","params":{"mcp_tool":"canary_marker"},"message":"review"}`
			req := httptest.NewRequest(http.MethodPost, "/v1/approvals", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer test-token")
			rr := httptest.NewRecorder()
			srv.handler().ServeHTTP(rr, req)
			require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
			var created map[string]any
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &created))
			assert.Equal(t, tc.want, created["notified"])
		})
	}
}

func TestNotificationDispatchIsBounded(t *testing.T) {
	srv := New(nil, nil)
	started := make(chan struct{}, maxConcurrentNotifications)
	release := make(chan struct{})
	for range maxConcurrentNotifications {
		srv.enqueueNotification("test", func() {
			started <- struct{}{}
			<-release
		})
		<-started
	}

	var overflowRan atomic.Bool
	srv.enqueueNotification("overflow", func() { overflowRan.Store(true) })
	assert.False(t, overflowRan.Load(), "delivery above the concurrency limit must be dropped")
	close(release)
}

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
	assert.Equal(t, true, resp["allowed"])
	assert.Equal(t, "allow", resp["decision"])
}

func TestWebhookAction_FinalAuditFailureFailsClosed(t *testing.T) {
	webhookCalls := 0
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		webhookCalls++
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(webhookActionResponse{Decision: "allow"}))
	}))
	defer webhook.Close()

	srv, token := setupWebhookServer(t, webhook.URL, true)
	failing := &failOnWriteSink{failAt: 2}
	srv.sink = failing

	body := `{"agent":"test-agent","session":"s1","params":{"command":"dangerous deploy"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/tool/exec", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	srv.handler().ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "audit storage is unavailable")
	assert.Equal(t, 1, webhookCalls)
	assert.Equal(t, 2, failing.count(), "initial webhook and final allow decisions should both be attempted")
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
	assert.Equal(t, false, resp["allowed"])
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
	assert.Equal(t, true, resp["allowed"])
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
	assert.Equal(t, false, resp["allowed"])
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
	assert.Equal(t, true, resp["allowed"])
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

func TestWebhookMisconfiguredDenies(t *testing.T) {
	// When webhook config is nil or has empty URL, should deny (fail closed).
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	require.NoError(t, os.WriteFile(path, []byte("default_action: allow\npolicies: []\n"), 0o644))
	store := engine.NewFileStore(path)
	eng, err := engine.New(store, nil)
	require.NoError(t, err)

	srv := New(eng, nil, WithToken("tok"), WithMode("enforce"))
	call := engine.ToolCall{Tool: "exec", Params: map[string]any{"command": "test"}}

	// nil config
	d := srv.executeWebhookAction(call, engine.Decision{WebhookConfig: nil})
	assert.Equal(t, engine.ActionDeny, d.Action)
	assert.Contains(t, d.Message, "misconfigured")

	// empty URL
	d = srv.executeWebhookAction(call, engine.Decision{WebhookConfig: &engine.WebhookActionConfig{URL: ""}})
	assert.Equal(t, engine.ActionDeny, d.Action)
	assert.Contains(t, d.Message, "misconfigured")
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
