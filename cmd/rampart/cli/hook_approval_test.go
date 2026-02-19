package cli

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHookApprovalClient_Approved(t *testing.T) {
	var pollCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/approvals":
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{
				"id":         "test-123",
				"status":     "pending",
				"expires_at": time.Now().Add(5 * time.Minute).Format(time.RFC3339),
			})
		case r.Method == "GET" && r.URL.Path == "/v1/approvals/test-123":
			n := pollCount.Add(1)
			status := "pending"
			if n >= 3 {
				status = "approved"
			}
			json.NewEncoder(w).Encode(map[string]any{
				"id":     "test-123",
				"status": status,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := &hookApprovalClient{
		serveURL: srv.URL,
		token:    "test-token",
		logger:   testLogger(),
	}

	result := client.requestApproval("exec", "kubectl delete pod foo", "claude-code", "/tmp", "", "needs approval", 10*time.Second)
	if result != hookAllow {
		t.Fatalf("expected hookAllow, got %d", result)
	}
}

func TestHookApprovalClient_Denied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/approvals":
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{
				"id":         "test-456",
				"status":     "pending",
				"expires_at": time.Now().Add(5 * time.Minute).Format(time.RFC3339),
			})
		case r.Method == "GET" && r.URL.Path == "/v1/approvals/test-456":
			json.NewEncoder(w).Encode(map[string]any{
				"id":     "test-456",
				"status": "denied",
			})
		}
	}))
	defer srv.Close()

	client := &hookApprovalClient{
		serveURL: srv.URL,
		token:    "test-token",
		logger:   testLogger(),
	}

	result := client.requestApproval("exec", "rm -rf /tmp/stuff", "claude-code", "/tmp", "", "dangerous", 10*time.Second)
	if result != hookDeny {
		t.Fatalf("expected hookDeny, got %d", result)
	}
}

func TestHookApprovalClient_Unreachable(t *testing.T) {
	client := &hookApprovalClient{
		serveURL: "http://127.0.0.1:19999", // nothing listening
		token:    "test-token",
		logger:   testLogger(),
	}

	result := client.requestApproval("exec", "echo hi", "claude-code", "/tmp", "", "test", 2*time.Second)
	if result != hookAsk {
		t.Fatalf("expected hookAsk (fallback), got %d", result)
	}
}

func TestHookApprovalClient_FallbackOnUnreachablePort1(t *testing.T) {
	// Use port 1 which is almost certainly unreachable.
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	client := &hookApprovalClient{
		serveURL: "http://localhost:1",
		token:    "test-token",
		logger:   logger,
	}

	result := client.requestApproval("exec", "echo hi", "claude-code", "/tmp", "", "test", 5*time.Second)
	if result != hookAsk {
		t.Fatalf("expected hookAsk (native prompt fallback), got %d", result)
	}

	// Verify warning was logged about serve being unreachable.
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "serve unreachable") {
		t.Fatalf("expected log warning about serve unreachable, got: %s", logOutput)
	}
}

func TestHookApprovalClient_AutoDiscoverApproved(t *testing.T) {
	// Simulates auto-discovered serve that is reachable — should work normally.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/approvals":
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{
				"id":         "auto-1",
				"status":     "pending",
				"expires_at": time.Now().Add(5 * time.Minute).Format(time.RFC3339),
			})
		case r.Method == "GET" && r.URL.Path == "/v1/approvals/auto-1":
			json.NewEncoder(w).Encode(map[string]any{
				"id":     "auto-1",
				"status": "approved",
			})
		}
	}))
	defer srv.Close()

	client := &hookApprovalClient{
		serveURL:       srv.URL,
		token:          "test-token",
		logger:         testLogger(),
		autoDiscovered: true,
	}

	result := client.requestApproval("exec", "kubectl apply -f deploy.yaml", "claude-code", "/tmp", "", "needs approval", 10*time.Second)
	if result != hookAllow {
		t.Fatalf("expected hookAllow, got %d", result)
	}
}

func TestHookApprovalClient_AutoDiscoverUnreachableSilent(t *testing.T) {
	// When auto-discovered and unreachable, should NOT print warning to stderr,
	// and should log at DEBUG level, not WARN.
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	client := &hookApprovalClient{
		serveURL:       "http://localhost:1",
		token:          "test-token",
		logger:         logger,
		autoDiscovered: true,
	}

	result := client.requestApproval("exec", "echo hi", "claude-code", "/tmp", "", "test", 5*time.Second)
	if result != hookAsk {
		t.Fatalf("expected hookAsk (silent fallback), got %d", result)
	}

	logOutput := logBuf.String()
	// Should have DEBUG-level log about auto-discovered serve being unreachable.
	if !strings.Contains(logOutput, "auto-discovered serve unreachable") {
		t.Fatalf("expected debug log about auto-discovered serve, got: %s", logOutput)
	}
	// Should NOT have WARN-level log.
	if strings.Contains(logOutput, "level=WARN") {
		t.Fatalf("auto-discovered unreachable should not log at WARN level, got: %s", logOutput)
	}
}

func TestHookApprovalClient_ExplicitUnreachableShowsWarning(t *testing.T) {
	// When explicitly configured and unreachable, should still show warning.
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	client := &hookApprovalClient{
		serveURL:       "http://localhost:1",
		token:          "test-token",
		logger:         logger,
		autoDiscovered: false,
	}

	result := client.requestApproval("exec", "echo hi", "claude-code", "/tmp", "", "test", 5*time.Second)
	if result != hookAsk {
		t.Fatalf("expected hookAsk, got %d", result)
	}

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "level=WARN") {
		t.Fatalf("explicit unreachable should log at WARN level, got: %s", logOutput)
	}
}

func TestHookApprovalClient_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/approvals":
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{
				"id":         "test-789",
				"status":     "pending",
				"expires_at": time.Now().Add(5 * time.Minute).Format(time.RFC3339),
			})
		case r.Method == "GET" && r.URL.Path == "/v1/approvals/test-789":
			// Always return pending
			json.NewEncoder(w).Encode(map[string]any{
				"id":     "test-789",
				"status": "pending",
			})
		}
	}))
	defer srv.Close()

	client := &hookApprovalClient{
		serveURL: srv.URL,
		token:    "test-token",
		logger:   testLogger(),
	}

	start := time.Now()
	result := client.requestApproval("exec", "echo hi", "claude-code", "/tmp", "", "test", 2*time.Second)
	elapsed := time.Since(start)

	if result != hookDeny {
		t.Fatalf("expected hookDeny on timeout, got %d", result)
	}
	if elapsed < 1*time.Second || elapsed > 4*time.Second {
		t.Fatalf("timeout took %s, expected ~2s", elapsed)
	}
}
