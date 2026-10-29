// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Rampart only narrows what Claude Code permits: a policy allow, and every
// decision in monitor mode, leave Claude Code's own permission rules and
// prompts in force instead of answering "allow" for the user.
func TestClaudeCodeHookDefersAllowToHostPermissions(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	configPath := filepath.Join(home, "policy.yaml")
	policy := `version: "1"
default_action: allow
policies:
  - name: deny-marker
    match:
      tool: ["exec"]
    rules:
      - action: deny
        message: "marker denied"
        when:
          command_matches: ["printf rampart-deny-marker"]
`
	if err := os.WriteFile(configPath, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(command, mode string) hookOutput {
		t.Helper()
		stdin, err := json.Marshal(map[string]any{
			"hook_event_name": "PreToolUse",
			"session_id":      "defer-session",
			"tool_use_id":     "toolu_defer",
			"tool_name":       "Bash",
			"tool_input":      map[string]any{"command": command},
		})
		if err != nil {
			t.Fatal(err)
		}
		stdout, _, err := runHookWithStdin(t, &rootOptions{configPath: configPath}, string(stdin), "--mode", mode)
		if err != nil {
			t.Fatalf("hook: %v", err)
		}
		var output hookOutput
		if err := json.Unmarshal([]byte(stdout), &output); err != nil {
			t.Fatalf("decode %q: %v", stdout, err)
		}
		return output
	}

	if got := run("printf safe", "enforce"); got.HookSpecificOutput != nil {
		t.Fatalf("policy allow = %#v, want no host decision", got.HookSpecificOutput)
	}
	if got := run("printf rampart-deny-marker", "enforce"); got.HookSpecificOutput == nil || got.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("policy deny = %#v, want deny", got.HookSpecificOutput)
	}
	if got := run("printf rampart-deny-marker", "monitor"); got.HookSpecificOutput != nil {
		t.Fatalf("monitor mode = %#v, want no host decision", got.HookSpecificOutput)
	}
}
