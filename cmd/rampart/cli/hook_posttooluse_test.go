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

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// denyPolicy is a minimal policy that denies exec tool calls with a specific message.
const denyPolicyWithMessage = `version: "1"
policies:
  - name: block-destructive
    match:
      tool: ["exec"]
    rules:
      - action: deny
        when:
          command_matches:
            - "rm -rf **"
        message: "Destructive file deletion is not allowed"
`

// TestPostToolUseFailure_DenyReasonSurfaced verifies that when a PostToolUseFailure
// event fires for a previously denied command, the additionalContext includes the
// specific deny reason and policy name from the policy engine re-evaluation.
func TestPostToolUseFailure_DenyReasonSurfaced(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)

	configPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(configPath, []byte(denyPolicyWithMessage), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	payload := map[string]any{
		"hook_event_name": "PostToolUseFailure",
		"session_id":      "sess-posttooluse-001",
		"tool_use_id":     "toolu_posttooluse_001",
		"tool_name":       "Bash",
		"tool_input":      map[string]any{"command": "rm -rf /tmp/testdir"},
	}
	stdinJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	opts := &rootOptions{configPath: configPath}
	stdout, _, hookErr := runHookWithStdin(t, opts, string(stdinJSON), "--mode", "enforce")
	if hookErr != nil {
		t.Fatalf("hook RunE error: %v", hookErr)
	}

	var out hookOutput
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("unmarshal hook output: %v (stdout=%q)", err, stdout)
	}
	if out.HookSpecificOutput == nil {
		t.Fatal("expected non-nil HookSpecificOutput")
	}
	ctx := out.HookSpecificOutput.AdditionalContext
	if ctx == "" {
		t.Fatal("additionalContext must not be empty")
	}

	// The specific deny reason from the policy should appear.
	if !strings.Contains(ctx, "Destructive file deletion is not allowed") {
		t.Errorf("additionalContext missing deny reason; got:\n%s", ctx)
	}

	// The matched policy name should appear.
	if !strings.Contains(ctx, "block-destructive") {
		t.Errorf("additionalContext missing policy name; got:\n%s", ctx)
	}

	// The blocked prefix should appear.
	if !strings.Contains(ctx, "⛔ Blocked") {
		t.Errorf("additionalContext missing ⛔ Blocked prefix; got:\n%s", ctx)
	}

	// The general guidance should still be present.
	if !strings.Contains(ctx, "Do not attempt alternative approaches") {
		t.Errorf("additionalContext missing general guidance; got:\n%s", ctx)
	}
}

// TestPostToolUseFailure_NoContextForAllowedCommand verifies that when the
// PostToolUseFailure event is for a command that wouldn't be denied by Rampart
// (e.g. tool failed for an unrelated reason like grep exit 1), no additionalContext
// is injected — injecting "blocked by security policy" guidance for non-Rampart
// failures misleads the agent into thinking it was blocked when it wasn't.
func TestPostToolUseFailure_NoContextForAllowedCommand(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)

	// Policy that allows everything — simulates an ordinary tool failure.
	allowAll := `version: "1"
default_action: allow
policies: []
`
	configPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(configPath, []byte(allowAll), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	payload := map[string]any{
		"hook_event_name": "PostToolUseFailure",
		"session_id":      "sess-posttooluse-002",
		"tool_name":       "Bash",
		"tool_input":      map[string]any{"command": "echo hello"},
	}
	stdinJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	opts := &rootOptions{configPath: configPath}
	stdout, _, hookErr := runHookWithStdin(t, opts, string(stdinJSON), "--mode", "enforce")
	if hookErr != nil {
		t.Fatalf("hook RunE error: %v", hookErr)
	}

	var out hookOutput
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("unmarshal hook output: %v (stdout=%q)", err, stdout)
	}
	// When re-evaluation returns allow, no additionalContext should be injected.
	if out.HookSpecificOutput != nil && out.HookSpecificOutput.AdditionalContext != "" {
		t.Errorf("expected no additionalContext for non-Rampart failure; got:\n%s",
			out.HookSpecificOutput.AdditionalContext)
	}
}
