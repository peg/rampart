package cli

import (
	"bytes"
	"context"
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

	"github.com/spf13/cobra"
)

// --- ExitCode (root.go) ---

type exitCodeErr struct {
	code int
	msg  string
}

func (e *exitCodeErr) Error() string    { return e.msg }
func (e *exitCodeErr) ExitCode() int    { return e.code }

func TestExitCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, 0},
		{"plain error", fmt.Errorf("boom"), 1},
		{"exit code 42", &exitCodeErr{42, "custom"}, 42},
		{"exit code 0 fallback", &exitCodeErr{0, "zero"}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExitCode(tt.err); got != tt.want {
				t.Errorf("ExitCode() = %d, want %d", got, tt.want)
			}
		})
	}
}

// --- extractToolResponse (hook.go) ---

func TestExtractToolResponse(t *testing.T) {
	tests := []struct {
		name string
		resp map[string]any
		want string
	}{
		{"stdout only", map[string]any{"stdout": "hello"}, "hello"},
		{"stdout+stderr", map[string]any{"stdout": "out", "stderr": "err"}, "out\nerr"},
		{"content", map[string]any{"content": "body"}, "body"},
		{"output", map[string]any{"output": "data"}, "data"},
		{"fallback to other keys", map[string]any{"result": "val"}, "val"},
		{"empty strings ignored", map[string]any{"stdout": "", "result": "ok"}, "ok"},
		{"non-string ignored", map[string]any{"count": 42}, ""},
		{"empty map", map[string]any{}, ""},
		{"priority order", map[string]any{"stdout": "a", "content": "b"}, "a\nb"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractToolResponse(tt.resp)
			if got != tt.want {
				t.Errorf("extractToolResponse() = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- isPreloadRuntimeReady (preload.go) ---

func TestIsPreloadRuntimeReady(t *testing.T) {
	t.Run("healthy", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		if !isPreloadRuntimeReady(context.Background(), srv.URL) {
			t.Error("expected true for healthy server")
		}
	})

	t.Run("unhealthy", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()
		if isPreloadRuntimeReady(context.Background(), srv.URL) {
			t.Error("expected false for unhealthy server")
		}
	})

	t.Run("unreachable", func(t *testing.T) {
		if isPreloadRuntimeReady(context.Background(), "http://127.0.0.1:1") {
			t.Error("expected false for unreachable server")
		}
	})
}

// --- waitForProxyReady (wrap.go) ---

func TestWaitForProxyReady(t *testing.T) {
	t.Run("immediately ready", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()
		if err := waitForProxyReady(context.Background(), srv.URL); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("context cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := waitForProxyReady(ctx, "http://127.0.0.1:1")
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("timeout", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()
		err := waitForProxyReady(context.Background(), srv.URL)
		if err == nil || !strings.Contains(err.Error(), "timeout") {
			t.Fatalf("expected timeout error, got: %v", err)
		}
	})
}

// --- resolveApproval (approve.go) ---

func testCobraCmd(ctx context.Context) *cobra.Command {
	cmd := &cobra.Command{Use: "test"}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetContext(ctx)
	return cmd
}

func TestResolveApproval(t *testing.T) {
	t.Run("no token", func(t *testing.T) {
		t.Setenv("RAMPART_TOKEN", "")
		cmd := testCobraCmd(context.Background())
		err := resolveApproval(cmd, "http://localhost", "", "abc12345678", true)
		if err == nil || !strings.Contains(err.Error(), "token required") {
			t.Fatalf("expected token error, got: %v", err)
		}
	})

	t.Run("success approved", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("expected POST, got %s", r.Method)
			}
			if !strings.Contains(r.URL.Path, "/v1/approvals/") {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			auth := r.Header.Get("Authorization")
			if auth != "Bearer testtoken" {
				t.Errorf("unexpected auth: %s", auth)
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		cmd := testCobraCmd(context.Background())
		err := resolveApproval(cmd, srv.URL, "testtoken", "abc12345678", true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("server error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "internal error")
		}))
		defer srv.Close()

		cmd := testCobraCmd(context.Background())
		err := resolveApproval(cmd, srv.URL, "testtoken", "abc12345678", false)
		if err == nil || !strings.Contains(err.Error(), "500") {
			t.Fatalf("expected 500 error, got: %v", err)
		}
	})
}

// --- listPending (approve.go) ---

func TestListPending(t *testing.T) {
	t.Run("no token", func(t *testing.T) {
		t.Setenv("RAMPART_TOKEN", "")
		cmd := testCobraCmd(context.Background())
		err := listPending(cmd, "http://localhost", "")
		if err == nil || !strings.Contains(err.Error(), "token required") {
			t.Fatalf("expected token error, got: %v", err)
		}
	})

	t.Run("no approvals", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{"approvals": []any{}})
		}))
		defer srv.Close()

		cmd := testCobraCmd(context.Background())
		err := listPending(cmd, srv.URL, "tok")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("with approvals", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{
				"approvals": []map[string]any{
					{
						"id":         "abcdef1234567890",
						"tool":       "exec",
						"command":    "rm -rf /",
						"agent":      "claude",
						"message":    "dangerous",
						"status":     "pending",
						"created_at": time.Now().Format(time.RFC3339),
						"expires_at": time.Now().Add(5 * time.Minute).Format(time.RFC3339),
					},
				},
			})
		}))
		defer srv.Close()

		cmd := testCobraCmd(context.Background())
		err := listPending(cmd, srv.URL, "tok")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// --- initializeMCPConnection / getToolsList (mcp_scan.go) ---

func TestInitializeMCPConnection(t *testing.T) {
	// Create a pipe pair simulating a child process
	pr, pw := io.Pipe()
	stdinR, stdinW := io.Pipe()

	// Mock server: read request, write response
	go func() {
		buf := make([]byte, 4096)
		n, _ := stdinR.Read(buf)
		_ = n // consume the initialize request

		// Write initialize response
		resp := `{"jsonrpc":"2.0","id":"1","result":{"protocolVersion":"2024-11-05"}}` + "\n"
		pw.Write([]byte(resp))
	}()

	err := initializeMCPConnection(stdinW, pr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetToolsList(t *testing.T) {
	pr, pw := io.Pipe()
	stdinR, stdinW := io.Pipe()

	go func() {
		buf := make([]byte, 4096)
		stdinR.Read(buf)

		resp := map[string]any{
			"jsonrpc": "2.0",
			"id":      "2",
			"result": map[string]any{
				"tools": []map[string]any{
					{"name": "read_file", "description": "Read a file"},
					{"name": "write_file", "description": "Write a file"},
				},
			},
		}
		data, _ := json.Marshal(resp)
		pw.Write(append(data, '\n'))
	}()

	tools, err := getToolsList(stdinW, pr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}
	if tools[0].Name != "read_file" {
		t.Errorf("expected read_file, got %s", tools[0].Name)
	}
}

func TestGetToolsList_NoResponse(t *testing.T) {
	// Use a bytes.Reader that returns EOF immediately
	emptyReader := bytes.NewReader(nil)

	// stdinW that discards writes
	stdinW := &nopWriteCloser{io.Discard}

	_, err := getToolsList(stdinW, emptyReader)
	if err == nil {
		t.Fatal("expected error for no response")
	}
}

type nopWriteCloser struct{ io.Writer }

func (n *nopWriteCloser) Close() error { return nil }

// --- loadLogEvents (log.go) ---

func TestLoadLogEvents(t *testing.T) {
	t.Run("empty dir", func(t *testing.T) {
		dir := t.TempDir()
		events, err := loadLogEvents(dir, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(events) != 0 {
			t.Errorf("expected 0 events, got %d", len(events))
		}
	})

	t.Run("today only no files", func(t *testing.T) {
		dir := t.TempDir()
		events, err := loadLogEvents(dir, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(events) != 0 {
			t.Errorf("expected 0 events, got %d", len(events))
		}
	})

	t.Run("today with file", func(t *testing.T) {
		dir := t.TempDir()
		today := time.Now().UTC().Format("2006-01-02")
		event := map[string]any{
			"id": "evt1", "ts": time.Now().UTC().Format(time.RFC3339),
			"tool": "exec", "agent": "claude",
			"decision": map[string]any{"action": "allow", "matched_policies": []string{"default"}, "evaluation_time_us": 10},
		}
		data, _ := json.Marshal(event)
		os.WriteFile(filepath.Join(dir, "audit-"+today+".jsonl"), append(data, '\n'), 0o644)

		events, err := loadLogEvents(dir, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(events) != 1 {
			t.Errorf("expected 1 event, got %d", len(events))
		}
	})

	t.Run("latest file", func(t *testing.T) {
		dir := t.TempDir()
		event := map[string]any{
			"id": "evt1", "ts": time.Now().UTC().Format(time.RFC3339),
			"tool": "exec", "agent": "claude",
			"decision": map[string]any{"action": "allow", "matched_policies": []string{"default"}, "evaluation_time_us": 10},
		}
		data, _ := json.Marshal(event)
		os.WriteFile(filepath.Join(dir, "audit-2025-01-01.jsonl"), append(data, '\n'), 0o644)

		events, err := loadLogEvents(dir, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(events) != 1 {
			t.Errorf("expected 1 event, got %d", len(events))
		}
	})
}

// --- writeJSONEvents / writePrettyEvents (log.go) ---

// --- runReport (report.go) ---

func TestRunReport(t *testing.T) {
	t.Run("invalid duration", func(t *testing.T) {
		err := runReport(&reportOptions{last: "invalid"})
		if err == nil || !strings.Contains(err.Error(), "invalid duration") {
			t.Fatalf("expected invalid duration error, got: %v", err)
		}
	})

	t.Run("empty audit dir", func(t *testing.T) {
		dir := t.TempDir()
		err := runReport(&reportOptions{
			last:     "24h",
			auditDir: dir,
			output:   filepath.Join(dir, "report.html"),
		})
		if err == nil || !strings.Contains(err.Error(), "no audit events") {
			t.Fatalf("expected no events error, got: %v", err)
		}
	})
}

// --- followAuditFile (audit.go) ---

func TestFollowAuditFile_ContextCancel(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "audit.jsonl")
	os.WriteFile(f, []byte{}, 0o644)

	ctx, cancel := context.WithCancel(context.Background())
	cmd := testCobraCmd(ctx)

	done := make(chan error, 1)
	go func() {
		done <- followAuditFile(cmd, dir, f, true)
	}()

	// Cancel immediately
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("followAuditFile did not return after context cancel")
	}
}

// --- patchOpenClawTools (setup.go) ---

func TestPatchOpenClawTools(t *testing.T) {
	dir := t.TempDir()
	toolFile := filepath.Join(dir, "read.js")
	os.WriteFile(toolFile, []byte("original content"), 0o644)

	cmd := testCobraCmd(context.Background())
	err := patchOpenClawTools(cmd, "http://localhost:8080", "testtoken")
	_ = err
}
