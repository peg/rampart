package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
