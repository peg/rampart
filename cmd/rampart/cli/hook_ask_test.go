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
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peg/rampart/internal/session"
)

// askPolicy is a minimal Rampart policy YAML that produces ActionAsk for exec tool calls.
const askPolicy = `version: "1"
policies:
  - name: test-ask-policy
    match:
      tool: ["exec"]
    rules:
      - action: ask
        message: "approve this command?"
`

// runHookWithStdin executes the hook command with the given stdin JSON and extra flags.
// It returns stdout, stderr, and any error.
func runHookWithStdin(t *testing.T, opts *rootOptions, stdinJSON string, args ...string) (string, string, error) {
	t.Helper()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := newHookCmd(opts)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	cmd.SetIn(strings.NewReader(stdinJSON))
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

// TestParseClaudeCodeInput_SessionAndToolUseID verifies that session_id and
// tool_use_id from the Claude Code hook payload are propagated into the parse result.
func TestParseClaudeCodeInput_SessionAndToolUseID(t *testing.T) {
	payload := map[string]any{
		"hook_event_name": "PreToolUse",
		"session_id":      "sess-abc123",
		"tool_use_id":     "toolu_01XyzAbc",
		"tool_name":       "Bash",
		"tool_input":      map[string]any{"command": "sudo apt install git"},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	result, err := parseClaudeCodeInput(strings.NewReader(string(data)), testLogger())
	if err != nil {
		t.Fatalf("parseClaudeCodeInput error: %v", err)
	}

	if result.SessionID != "sess-abc123" {
		t.Errorf("SessionID = %q, want sess-abc123", result.SessionID)
	}
	if result.ToolUseID != "toolu_01XyzAbc" {
		t.Errorf("ToolUseID = %q, want toolu_01XyzAbc", result.ToolUseID)
	}
	if result.HookEventName != "PreToolUse" {
		t.Errorf("HookEventName = %q, want PreToolUse", result.HookEventName)
	}
	if result.Tool != "exec" {
		t.Errorf("Tool = %q, want exec", result.Tool)
	}
}

// TestParseClaudeCodeInput_SessionIDEmpty verifies that missing session_id and
// tool_use_id do not cause errors — they remain empty strings.
func TestParseClaudeCodeInput_SessionIDEmpty(t *testing.T) {
	payload := map[string]any{
		"tool_name":  "Bash",
		"tool_input": map[string]any{"command": "echo hi"},
	}
	data, _ := json.Marshal(payload)

	result, err := parseClaudeCodeInput(strings.NewReader(string(data)), testLogger())
	if err != nil {
		t.Fatalf("parseClaudeCodeInput error: %v", err)
	}
	if result.SessionID != "" {
		t.Errorf("SessionID = %q, want empty", result.SessionID)
	}
	if result.ToolUseID != "" {
		t.Errorf("ToolUseID = %q, want empty", result.ToolUseID)
	}
}

// TestHookActionAsk_WritesSessionState verifies the full PreToolUse ActionAsk path:
//  1. The hook emits permissionDecision:"ask" in the output JSON.
//  2. A session state file is created under ~/.rampart/session-state/ with
//     the pending ask recorded.
func TestHookActionAsk_WritesSessionState(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)

	// Write policy YAML.
	configPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(configPath, []byte(askPolicy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	// Build a PreToolUse hook input JSON.
	const sessionID = "sess-ask-001"
	const toolUseID = "toolu_ask_001"
	payload := map[string]any{
		"hook_event_name": "PreToolUse",
		"session_id":      sessionID,
		"tool_use_id":     toolUseID,
		"tool_name":       "Bash",
		"tool_input":      map[string]any{"command": "sudo apt install git"},
	}
	stdinJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	// Execute the hook command.
	opts := &rootOptions{configPath: configPath}
	stdout, _, hookErr := runHookWithStdin(t, opts, string(stdinJSON), "--mode", "enforce")
	if hookErr != nil {
		t.Fatalf("hook RunE error: %v", hookErr)
	}

	// Verify stdout contains permissionDecision:"ask".
	var out hookOutput
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("unmarshal hook output: %v (stdout=%q)", err, stdout)
	}
	if out.HookSpecificOutput == nil {
		t.Fatal("expected non-nil HookSpecificOutput")
	}
	if out.HookSpecificOutput.PermissionDecision != "ask" {
		t.Errorf("PermissionDecision = %q, want ask", out.HookSpecificOutput.PermissionDecision)
	}
	if !strings.Contains(out.HookSpecificOutput.PermissionDecisionReason, "approve this command?") {
		t.Errorf("PermissionDecisionReason = %q, want to contain 'approve this command?'",
			out.HookSpecificOutput.PermissionDecisionReason)
	}

	// Verify session state file was written.
	stateDir := filepath.Join(dir, ".rampart", "session-state")
	stateFile := filepath.Join(stateDir, sessionID+".json")

	// Give the write a short moment (it should be synchronous, but be defensive).
	var stateData []byte
	for i := 0; i < 10; i++ {
		stateData, err = os.ReadFile(stateFile)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("session state file not found at %s: %v", stateFile, err)
	}

	var state map[string]any
	if err := json.Unmarshal(stateData, &state); err != nil {
		t.Fatalf("unmarshal session state: %v", err)
	}
	pendingAsks, ok := state["pending_asks"].(map[string]any)
	if !ok {
		t.Fatalf("expected pending_asks map in session state, got: %T", state["pending_asks"])
	}
	ask, ok := pendingAsks[toolUseID]
	if !ok {
		t.Errorf("expected pending ask for tool_use_id %q in session state; keys: %v",
			toolUseID, keysOf(pendingAsks))
	}
	askMap, _ := ask.(map[string]any)
	if askMap["tool"] != "exec" {
		t.Errorf("pending_asks[%q].tool = %v, want exec", toolUseID, askMap["tool"])
	}
}

// TestHookPostToolUse_ObservesApproval verifies that a PostToolUse event with a
// matching tool_use_id moves the pending ask to session_approvals in the session
// state file.
func TestHookPostToolUse_ObservesApproval(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)

	// Write an allow-all policy (we don't need ActionAsk for PostToolUse observation;
	// the observation is independent of the current evaluation result).
	allowPolicy := `version: "1"
default_action: allow
policies: []
`
	configPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(configPath, []byte(allowPolicy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	const sessionID = "sess-obs-001"
	const toolUseID = "toolu_obs_001"

	// Pre-populate the session state with a pending ask using the session package.
	stateDir := filepath.Join(dir, ".rampart", "session-state")
	mgr := session.NewManager(stateDir, sessionID, testLogger())
	if err := mgr.RecordAsk(toolUseID, "exec", "sudo apt install git", "sudo apt install git",
		"test-ask-policy", "approve this command?"); err != nil {
		t.Fatalf("RecordAsk: %v", err)
	}

	// Build a PostToolUse hook input JSON with tool_response (tool ran → user approved).
	payload := map[string]any{
		"hook_event_name": "PostToolUse",
		"session_id":      sessionID,
		"tool_use_id":     toolUseID,
		"tool_name":       "Bash",
		"tool_input":      map[string]any{"command": "sudo apt install git"},
		"tool_response":   map[string]any{"stdout": "Setting up git...\nProcessing...\n"},
	}
	stdinJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	// Execute the hook command.
	opts := &rootOptions{configPath: configPath}
	_, _, hookErr := runHookWithStdin(t, opts, string(stdinJSON), "--mode", "enforce")
	if hookErr != nil {
		t.Fatalf("hook RunE error: %v", hookErr)
	}

	// Verify session state: pending_asks should be empty, session_approvals should have an entry.
	stateFile := filepath.Join(stateDir, sessionID+".json")
	stateData, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatalf("read session state file: %v", err)
	}

	var state map[string]any
	if err := json.Unmarshal(stateData, &state); err != nil {
		t.Fatalf("unmarshal session state: %v", err)
	}

	// pending_asks should no longer contain the observed tool_use_id.
	pendingAsks, _ := state["pending_asks"].(map[string]any)
	if _, stillPending := pendingAsks[toolUseID]; stillPending {
		t.Errorf("expected pending ask %q to be removed after observation, but it's still present", toolUseID)
	}

	// session_approvals should have an entry for the pattern.
	sessionApprovals, ok := state["session_approvals"].(map[string]any)
	if !ok || len(sessionApprovals) == 0 {
		t.Fatalf("expected session_approvals to be non-empty after observation; state: %s", stateData)
	}

	// Find the approval record with approval_count == 1.
	found := false
	for key, v := range sessionApprovals {
		rec, _ := v.(map[string]any)
		count, _ := rec["approval_count"].(float64)
		if count == 1 {
			found = true
			t.Logf("approval record key=%q, tool=%v, pattern=%v, count=%v", key, rec["tool"], rec["pattern"], count)
		}
	}
	if !found {
		t.Errorf("expected an approval record with approval_count=1; session_approvals=%v", sessionApprovals)
	}
}

// TestHookActionAsk_NoSessionID verifies that ActionAsk still emits the ask output
// even when session_id or tool_use_id are absent — session state write is skipped
// gracefully (no panic, no error).
func TestHookActionAsk_NoSessionID(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)

	configPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(configPath, []byte(askPolicy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	// Build a PreToolUse input without session_id or tool_use_id.
	payload := map[string]any{
		"hook_event_name": "PreToolUse",
		// session_id intentionally absent
		// tool_use_id intentionally absent
		"tool_name":  "Bash",
		"tool_input": map[string]any{"command": "sudo apt install git"},
	}
	stdinJSON, _ := json.Marshal(payload)

	opts := &rootOptions{configPath: configPath}
	stdout, _, hookErr := runHookWithStdin(t, opts, string(stdinJSON), "--mode", "enforce")
	if hookErr != nil {
		t.Fatalf("hook RunE error: %v", hookErr)
	}

	// Should still emit permissionDecision:"ask".
	var out hookOutput
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("unmarshal hook output: %v (stdout=%q)", err, stdout)
	}
	if out.HookSpecificOutput == nil || out.HookSpecificOutput.PermissionDecision != "ask" {
		t.Errorf("expected permissionDecision=ask without session_id, got: %+v", out.HookSpecificOutput)
	}

	// No session state directory should have been created (no sessionID to key on).
	stateDir := filepath.Join(dir, ".rampart", "session-state")
	entries, err := os.ReadDir(stateDir)
	if err == nil && len(entries) > 0 {
		// filter out temp files
		var jsonFiles []string
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".json") {
				jsonFiles = append(jsonFiles, e.Name())
			}
		}
		if len(jsonFiles) > 0 {
			t.Errorf("expected no session state JSON files without session_id, found: %v", jsonFiles)
		}
	}
}

// keysOf returns the keys of a map[string]any for diagnostic messages.
func keysOf(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
