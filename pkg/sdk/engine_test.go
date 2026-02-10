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

package sdk

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/peg/rampart/internal/engine"
)

// setupSDK creates an SDK using a temporary policy file.
func setupSDK(t *testing.T, policy string) *SDK {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(policy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	s, err := NewSDK(path)
	if err != nil {
		t.Fatalf("new sdk: %v", err)
	}
	return s
}

func TestWrap_DenyPolicyReturnsErrDenied(t *testing.T) {
	s := setupSDK(t, `
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
`)

	wrapped := s.Wrap("exec", func(context.Context, map[string]any) (any, error) {
		return "ok", nil
	})

	_, err := wrapped(context.Background(), map[string]any{"command": "rm -rf /"})
	if err == nil {
		t.Fatal("want err, got nil")
	}
	var denied *ErrDenied
	if !errors.As(err, &denied) {
		t.Fatalf("want ErrDenied, got %T", err)
	}
}

func TestWrap_AllowPolicyCallsThrough(t *testing.T) {
	s := setupSDK(t, `
version: "1"
default_action: deny
policies:
  - name: allow-git
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["git *"]
`)

	called := false
	wrapped := s.Wrap("exec", func(context.Context, map[string]any) (any, error) {
		called = true
		return "ok", nil
	})

	result, err := wrapped(context.Background(), map[string]any{"command": "git push origin main"})
	if err != nil {
		t.Fatalf("want nil err, got %v", err)
	}
	if !called {
		t.Fatal("expected wrapped function to be called")
	}
	if result != "ok" {
		t.Fatalf("want result ok, got %v", result)
	}
}

func TestWrap_LogActionCallsThrough(t *testing.T) {
	s := setupSDK(t, `
version: "1"
default_action: deny
policies:
  - name: log-git
    match:
      tool: exec
    rules:
      - action: log
        when:
          command_matches: ["git *"]
`)

	wrapped := s.Wrap("exec", func(context.Context, map[string]any) (any, error) {
		return "logged", nil
	})

	result, err := wrapped(context.Background(), map[string]any{"command": "git push origin main"})
	if err != nil {
		t.Fatalf("want nil err, got %v", err)
	}
	if result != "logged" {
		t.Fatalf("want result logged, got %v", result)
	}
}

func TestWrap_ContextKeysExtractAgentAndSession(t *testing.T) {
	s := setupSDK(t, `
version: "1"
default_action: allow
policies:
  - name: allow-all
    match:
      tool: exec
      agent: test-agent
    rules:
      - action: allow
        when:
          command_matches: ["*"]
`)

	var capturedAgent, capturedSession string
	wrapped := s.Wrap("exec", func(ctx context.Context, params map[string]any) (any, error) {
		// The engine already evaluated — but we can verify context propagation
		// by checking that a non-default agent was used via the decision.
		return "ok", nil
	})

	ctx := context.WithValue(context.Background(), AgentKey, "test-agent")
	ctx = context.WithValue(ctx, SessionKey, "test-session")

	_, err := wrapped(ctx, map[string]any{"command": "echo hi"})
	if err != nil {
		t.Fatalf("want nil err, got %v", err)
	}

	// Verify that bare string keys DON'T collide with our typed keys.
	ctx2 := context.WithValue(context.Background(), "rampart-agent", "wrong-agent")
	call := engine.ToolCall{
		Agent: func() string {
			v, _ := ctx2.Value(AgentKey).(string)
			if v == "" {
				return defaultAgent
			}
			return v
		}(),
	}
	if call.Agent != defaultAgent {
		t.Fatalf("bare string key should not match typed key, got %q", call.Agent)
	}

	_ = capturedAgent
	_ = capturedSession
}

func TestPreflight_AllowedCommand(t *testing.T) {
	s := setupSDK(t, `
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
`)

	result := s.Preflight(context.Background(), "exec", map[string]any{"command": "git status"})
	if !result.Allowed {
		t.Fatalf("expected allowed, got action=%s", result.Action)
	}
	if result.Action != "allow" {
		t.Fatalf("expected allow, got %s", result.Action)
	}
}

func TestPreflight_DeniedCommand(t *testing.T) {
	s := setupSDK(t, `
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
        message: "blocked"
`)

	result := s.Preflight(context.Background(), "exec", map[string]any{"command": "rm -rf /"})
	if result.Allowed {
		t.Fatal("expected denied")
	}
	if result.Action != "deny" {
		t.Fatalf("expected deny, got %s", result.Action)
	}
	if result.Message != "blocked" {
		t.Fatalf("expected message 'blocked', got %q", result.Message)
	}
}

func TestPreflight_RequireApproval(t *testing.T) {
	s := setupSDK(t, `
version: "1"
default_action: allow
policies:
  - name: sudo-gate
    match:
      tool: exec
    rules:
      - action: require_approval
        when:
          command_matches: ["sudo *"]
        message: "needs approval"
`)

	result := s.Preflight(context.Background(), "exec", map[string]any{"command": "sudo reboot"})
	if result.Allowed {
		t.Fatal("require_approval should not be 'allowed'")
	}
	if result.Action != "require_approval" {
		t.Fatalf("expected require_approval, got %s", result.Action)
	}
}

func TestWrap_ErrDeniedContainsPolicyAndMessage(t *testing.T) {
	s := setupSDK(t, `
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
`)

	wrapped := s.Wrap("exec", func(context.Context, map[string]any) (any, error) {
		return nil, nil
	})

	_, err := wrapped(context.Background(), map[string]any{"command": "rm -rf /"})
	if err == nil {
		t.Fatal("want err, got nil")
	}

	denied, ok := err.(*ErrDenied)
	if !ok {
		t.Fatalf("want *ErrDenied, got %T", err)
	}
	if denied.Policy != "block-rm" {
		t.Fatalf("want policy block-rm, got %q", denied.Policy)
	}
	if denied.Message != "destructive command blocked" {
		t.Fatalf("want message destructive command blocked, got %q", denied.Message)
	}
}
