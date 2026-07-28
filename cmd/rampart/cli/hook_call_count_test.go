// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestHookCallCountPersistsAcrossInvocations(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	configPath := filepath.Join(home, "policy.yaml")
	policy := `version: "1"
default_action: allow
policies:
  - name: deny-second-exec
    match:
      tool: ["exec"]
    rules:
      - action: deny
        message: "exec call limit reached"
        when:
          call_count:
            gte: 2
            window: "1h"
`
	if err := os.WriteFile(configPath, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}

	run := func(toolUseID string) hookOutput {
		t.Helper()
		payload := map[string]any{
			"hook_event_name": "PreToolUse",
			"session_id":      "call-count-session",
			"tool_use_id":     toolUseID,
			"tool_name":       "Bash",
			"tool_input":      map[string]any{"command": "printf safe"},
		}
		stdin, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		stdout, stderr, err := runHookWithStdin(t, &rootOptions{configPath: configPath}, string(stdin), "--mode", "enforce")
		if err != nil {
			t.Fatalf("hook invocation: %v", err)
		}
		if stderr != "" {
			t.Fatalf("hook stderr = %q, want empty", stderr)
		}
		var output hookOutput
		if err := json.Unmarshal([]byte(stdout), &output); err != nil {
			t.Fatalf("decode hook output %q: %v", stdout, err)
		}
		return output
	}

	first := run("call-count-1")
	if first.HookSpecificOutput == nil || first.HookSpecificOutput.PermissionDecision != "allow" {
		t.Fatalf("first decision = %#v, want allow", first.HookSpecificOutput)
	}

	// runHookWithStdin constructs and executes an entirely new hook command and
	// engine. The second decision can only observe the first call via the
	// persistent sidecar shared by one-shot hook processes.
	second := run("call-count-2")
	if second.HookSpecificOutput == nil || second.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("second decision = %#v, want deny", second.HookSpecificOutput)
	}
	if _, err := os.Stat(filepath.Join(home, ".rampart", "hook-call-counts.json")); err != nil {
		t.Fatalf("persistent call-count sidecar: %v", err)
	}
}
