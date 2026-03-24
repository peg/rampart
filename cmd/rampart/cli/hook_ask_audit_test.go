package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func TestHookActionAsk_NoAudit_DoesNotRegisterServeApproval(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)

	const policy = `version: "1"
policies:
  - name: test-ask-no-audit
    match:
      tool: ["exec"]
    rules:
      - action: ask
        message: "approve this command?"
`
	configPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(configPath, []byte(policy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	var createCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/healthz":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/approvals":
			createCount.Add(1)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "a1", "status": "pending"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	payload := map[string]any{
		"hook_event_name": "PreToolUse",
		"session_id":      "sess-audit-off-001",
		"tool_use_id":     "toolu_audit_off_001",
		"tool_name":       "Bash",
		"tool_input":      map[string]any{"command": "sudo apt install git"},
	}
	stdinJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	opts := &rootOptions{configPath: configPath}
	stdout, _, hookErr := runHookWithStdin(t, opts, string(stdinJSON), "--mode", "enforce", "--serve-url", srv.URL)
	if hookErr != nil {
		t.Fatalf("hook RunE error: %v", hookErr)
	}
	if createCount.Load() != 0 {
		t.Fatalf("expected no serve approval registration for ask without audit, got %d", createCount.Load())
	}

	var out hookOutput
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("unmarshal hook output: %v (stdout=%q)", err, stdout)
	}
	if out.HookSpecificOutput == nil || out.HookSpecificOutput.PermissionDecision != "ask" {
		t.Fatalf("expected permissionDecision=ask, got %+v", out.HookSpecificOutput)
	}
}

func TestHookActionAskAudit_UsesNativeAskAndRegistersAudit(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)

	const policy = `version: "1"
policies:
  - name: test-ask-audit
    match:
      tool: ["exec"]
    rules:
      - action: ask
        ask:
          audit: true
        message: "approval required"
`
	configPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(configPath, []byte(policy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	var createCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/healthz":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/approvals":
			createCount.Add(1)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "ap-alias-1", "status": "pending"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	payload := map[string]any{
		"hook_event_name": "PreToolUse",
		"session_id":      "sess-audit-on-001",
		"tool_use_id":     "toolu_audit_on_001",
		"tool_name":       "Bash",
		"tool_input":      map[string]any{"command": "sudo apt install git"},
	}
	stdinJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	opts := &rootOptions{configPath: configPath}
	stdout, _, hookErr := runHookWithStdin(t, opts, string(stdinJSON), "--mode", "enforce", "--serve-url", srv.URL)
	if hookErr != nil {
		t.Fatalf("hook RunE error: %v", hookErr)
	}
	if createCount.Load() != 1 {
		t.Fatalf("expected exactly 1 serve approval registration for ask+audit, got %d", createCount.Load())
	}

	var out hookOutput
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("unmarshal hook output: %v (stdout=%q)", err, stdout)
	}
	if out.HookSpecificOutput == nil || out.HookSpecificOutput.PermissionDecision != "ask" {
		t.Fatalf("expected permissionDecision=ask, got %+v", out.HookSpecificOutput)
	}
	if !strings.Contains(out.HookSpecificOutput.PermissionDecisionReason, "approval required") {
		t.Fatalf("expected ask reason to include message, got %q", out.HookSpecificOutput.PermissionDecisionReason)
	}
}

func TestHookActionAskAudit_PostToolUse_ResolvesApproved(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)

	const policy = `version: "1"
policies:
  - name: test-ask-audit-on
    match:
      tool: ["exec"]
    rules:
      - action: ask
        ask:
          audit: true
        message: "approve this command?"
`
	configPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(configPath, []byte(policy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	var createCount atomic.Int32
	var resolveCount atomic.Int32
	var lastResolveBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/healthz":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/approvals":
			createCount.Add(1)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "ap-audit-1", "status": "pending"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/approvals/ap-audit-1/resolve":
			resolveCount.Add(1)
			_ = json.NewDecoder(r.Body).Decode(&lastResolveBody)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "ap-audit-1", "status": "approved"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	opts := &rootOptions{configPath: configPath}
	prePayload := map[string]any{
		"hook_event_name": "PreToolUse",
		"session_id":      "sess-audit-approve-001",
		"tool_use_id":     "toolu_audit_approve_001",
		"tool_name":       "Bash",
		"tool_input":      map[string]any{"command": "sudo apt install git"},
	}
	preJSON, _ := json.Marshal(prePayload)
	if _, _, err := runHookWithStdin(t, opts, string(preJSON), "--mode", "enforce", "--serve-url", srv.URL); err != nil {
		t.Fatalf("pre hook error: %v", err)
	}
	if createCount.Load() != 1 {
		t.Fatalf("expected one create call, got %d", createCount.Load())
	}

	postPayload := map[string]any{
		"hook_event_name": "PostToolUse",
		"session_id":      "sess-audit-approve-001",
		"tool_use_id":     "toolu_audit_approve_001",
		"tool_name":       "Bash",
		"tool_input":      map[string]any{"command": "sudo apt install git"},
		"tool_response":   map[string]any{"stdout": "ok"},
	}
	postJSON, _ := json.Marshal(postPayload)
	if _, _, err := runHookWithStdin(t, opts, string(postJSON), "--mode", "enforce", "--serve-url", srv.URL); err != nil {
		t.Fatalf("post hook error: %v", err)
	}
	if resolveCount.Load() != 1 {
		t.Fatalf("expected one resolve call, got %d", resolveCount.Load())
	}
	want := map[string]any{"approved": true, "resolved_by": "hook-posttooluse"}
	if !reflect.DeepEqual(lastResolveBody, want) {
		t.Fatalf("resolve body = %#v, want %#v", lastResolveBody, want)
	}
}
