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

	"github.com/peg/rampart/internal/audit"
)

func TestRunStatus(t *testing.T) {
	var buf bytes.Buffer
	err := runStatus(&buf, false)
	if err != nil {
		t.Fatalf("runStatus returned error: %v", err)
	}
	out := buf.String()
	// Verify the box header is present (either box-drawing or plain).
	if !strings.Contains(out, "RAMPART") {
		t.Error("missing RAMPART header in status output")
	}
	// Verify the status line is present.
	if !strings.Contains(out, "Status") {
		t.Error("missing Status row in status output")
	}
}

func TestStatusCmdDefaultHumanOutput(t *testing.T) {
	stdout, _, err := runCLI(t, "status")
	if err != nil {
		t.Fatalf("status returned error: %v", err)
	}
	if !strings.Contains(stdout, "RAMPART") {
		t.Fatalf("expected human status box output, got: %s", stdout)
	}
	var payload map[string]any
	if jsonErr := json.Unmarshal([]byte(stdout), &payload); jsonErr == nil {
		t.Fatal("default status output should not be JSON")
	}
}

func TestStatusCmdJSONOutput(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)

	policyDir := filepath.Join(home, ".rampart", "policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "status.yaml"), []byte("version: \"1\"\ndefault_action: allow\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	auditDir := filepath.Join(home, ".rampart", "audit")
	if err := os.MkdirAll(auditDir, 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	allowEvent := audit.Event{
		ID:        "01JTEST000000000000000001",
		Timestamp: now.Add(-1 * time.Minute),
		Agent:     "agent-1",
		Session:   "session-1",
		Tool:      "exec",
		Request:   map[string]any{"command": "echo ok"},
		Decision:  audit.EventDecision{Action: "allow", EvalTimeUS: 1},
		Hash:      "sha256:allow",
	}
	denyEvent := audit.Event{
		ID:        "01JTEST000000000000000002",
		Timestamp: now,
		Agent:     "agent-1",
		Session:   "session-1",
		Tool:      "exec",
		Request:   map[string]any{"command": "rm -rf /tmp/demo"},
		Decision:  audit.EventDecision{Action: "deny", EvalTimeUS: 1},
		PrevHash:  allowEvent.Hash,
		Hash:      "sha256:deny",
	}
	allowLine, err := json.Marshal(allowEvent)
	if err != nil {
		t.Fatal(err)
	}
	denyLine, err := json.Marshal(denyEvent)
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(auditDir, now.Format("2006-01-02")+".jsonl")
	content := string(allowLine) + "\n" + string(denyLine) + "\n"
	if err := os.WriteFile(logPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, _, err := runCLI(t, "status", "--json")
	if err != nil {
		t.Fatalf("status --json returned error: %v", err)
	}

	var got statusJSONOutput
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("status --json output is not valid JSON: %v\noutput: %s", err, stdout)
	}

	if got.SchemaVersion != statusSchemaVersion {
		t.Fatalf("schema_version=%q, want %q", got.SchemaVersion, statusSchemaVersion)
	}
	if got.GeneratedAt.IsZero() {
		t.Fatal("generated_at should be set")
	}
	if got.BuildVersion == "" {
		t.Fatal("build_version should be set")
	}
	if got.Mode != "monitor" {
		t.Fatalf("mode=%q, want monitor", got.Mode)
	}
	if got.DefaultAction != "allow" {
		t.Fatalf("default_action=%q, want allow", got.DefaultAction)
	}
	if got.Today.Allow != 1 || got.Today.Deny != 1 || got.Today.Pending != 0 {
		t.Fatalf("today counts mismatch: %+v", got.Today)
	}
	if got.LastDeny == nil {
		t.Fatal("last_deny should be present")
	}
	if got.LastDeny.Tool != "exec" {
		t.Fatalf("last_deny.tool=%q, want exec", got.LastDeny.Tool)
	}
	if !strings.Contains(got.LastDeny.Command, "rm -rf") {
		t.Fatalf("last_deny.command=%q, want command summary", got.LastDeny.Command)
	}
}

func TestDetectProtectedAgents_CodexWrapper(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	wrapperPath := filepath.Join(home, ".local", "bin", "codex")
	if err := os.MkdirAll(filepath.Dir(wrapperPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wrapperPath, []byte("#!/bin/sh\nexec rampart preload -- /usr/bin/codex \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	agents := detectProtectedAgents()
	found := false
	for _, agent := range agents {
		if agent == "Codex (wrapper)" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected Codex wrapper detection, got %v", agents)
	}
}

func TestDetectProtectedAgents_IgnoresPlainCodexBinary(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	wrapperPath := filepath.Join(home, ".local", "bin", "codex")
	if err := os.MkdirAll(filepath.Dir(wrapperPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wrapperPath, []byte("#!/bin/sh\nexec /usr/bin/codex \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	for _, agent := range detectProtectedAgents() {
		if agent == "Codex (wrapper)" {
			t.Fatalf("plain codex binary should not be reported as protected: %v", agent)
		}
	}
}

func TestDetectProtectedAgents_OpenClawPluginRequiresAllowedAndEnabled(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	pluginDir := filepath.Join(home, ".openclaw", "extensions", "rampart")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(home, ".openclaw", "openclaw.json")

	mustWrite := func(content string) {
		t.Helper()
		if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	contains := func(want string) bool {
		t.Helper()
		for _, agent := range detectProtectedAgents() {
			if agent == want {
				return true
			}
		}
		return false
	}
	containsOpenClaw := func() bool {
		t.Helper()
		for _, agent := range detectProtectedAgents() {
			if strings.HasPrefix(agent, "OpenClaw (") {
				return true
			}
		}
		return false
	}

	mustWrite(`{"plugins":{"allow":[]}}`)
	if containsOpenClaw() {
		t.Fatal("OpenClaw should not be reported when plugins.allow is missing rampart")
	}

	mustWrite(`{"plugins":{"allow":["rampart"],"entries":{"rampart":{"enabled":false}}}}`)
	if containsOpenClaw() {
		t.Fatal("OpenClaw should not be reported when plugins.entries.rampart.enabled=false")
	}

	mustWrite(`{"plugins":{"allow":["rampart"],"entries":{"rampart":{"enabled":true}}}}`)
	if !contains("OpenClaw (plugin)") {
		t.Fatal("expected plugin to be reported when installed, allowed, and enabled")
	}
}

func TestDetectProtectedAgents_OpenClawLegacyBridgeRequiresTopLevelBridgeConfig(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	configPath := filepath.Join(home, ".openclaw", "openclaw.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(`{"plugins":{"entries":{"rampart":{"enabled":true}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, agent := range detectProtectedAgents() {
		if strings.HasPrefix(agent, "OpenClaw (") {
			t.Fatalf("plugin metadata alone should not be reported as legacy bridge: %v", agent)
		}
	}

	if err := os.WriteFile(configPath, []byte(`{"rampart":{"url":"http://127.0.0.1:9090"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, agent := range detectProtectedAgents() {
		if agent == "OpenClaw (bridge)" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected legacy bridge config to be reported")
	}
}

func TestExtractEventCommand(t *testing.T) {
	ev := &audit.Event{
		Tool:    "exec",
		Request: map[string]any{"command": "ls -la"},
	}
	got := extractEventCommand(ev)
	if got != "ls -la" {
		t.Errorf("extractEventCommand = %q, want %q", got, "ls -la")
	}
}

func TestExtractEventCommandTruncation(t *testing.T) {
	long := strings.Repeat("x", 100)
	ev := &audit.Event{
		Tool:    "exec",
		Request: map[string]any{"command": long},
	}
	got := extractEventCommand(ev)
	if len(got) > 61 {
		t.Errorf("expected truncation, got len=%d", len(got))
	}
}

func TestExtractEventCommandFallback(t *testing.T) {
	ev := &audit.Event{
		Tool:    "read",
		Request: map[string]any{"path": "/etc/passwd"},
	}
	got := extractEventCommand(ev)
	if got != "read" {
		t.Errorf("expected tool name fallback, got %q", got)
	}
}

func TestIsUnknownOrEmpty(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"", true},
		{"unknown", true},
		{"UNKNOWN", true},
		{"(unknown)", true},
		{"exec ls", false},
	}
	for _, tt := range tests {
		if got := isUnknownOrEmpty(tt.input); got != tt.want {
			t.Errorf("isUnknownOrEmpty(%q)=%v want %v", tt.input, got, tt.want)
		}
	}
}
