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
	"fmt"
	"io"
	"net"
	"net/http"
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

func TestStatusCmd_NoServer(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	t.Chdir(home)
	t.Setenv("PATH", home)
	for _, key := range []string{"CLAUDE_CONFIG_DIR", "HERMES_HOME", "COPILOT_HOME", "APPDATA", "LOCALAPPDATA", "ProgramData"} {
		t.Setenv(key, filepath.Join(home, key))
	}
	t.Setenv("OPENCLAW_STATE_DIR", filepath.Join(home, ".openclaw"))
	t.Setenv("OPENCLAW_CONFIG_PATH", filepath.Join(home, ".openclaw", "openclaw.json"))
	t.Setenv("RAMPART_OPENCLAW_BIN", filepath.Join(home, "missing-openclaw"))
	t.Setenv("RAMPART_URL", "http://127.0.0.1:1")

	// Simulate unavailable service endpoints, including fallback ports, without
	// probing any service on the machine running the test.
	probes := 0
	oldClient := rampartHTTPClient
	rampartHTTPClient = &http.Client{Transport: redirectTestTransport(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet || req.URL.Path != "/healthz" {
			t.Errorf("unexpected status request: %s %s", req.Method, req.URL.Path)
		}
		probes++
		return nil, net.ErrClosed
	})}
	t.Cleanup(func() { rampartHTTPClient = oldClient })

	stdout, stderr, err := runCLI(t, "status", "--json")
	if err != nil {
		t.Fatalf("offline status returned an error: %v", err)
	}
	var got statusJSONOutput
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("decode offline status: %v; output: %s", err, stdout)
	}
	if probes == 0 || got.SchemaVersion != statusSchemaVersion || got.ServerRunning {
		t.Fatalf("offline status: probes=%d schema=%q server_running=%t", probes, got.SchemaVersion, got.ServerRunning)
	}
	if stderr != "" {
		t.Fatalf("offline status wrote stderr: %s", stderr)
	}
}

func TestStatusCmdJSONOutput(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	oldClient := rampartHTTPClient
	rampartHTTPClient = &http.Client{Transport: redirectTestTransport(func(req *http.Request) (*http.Response, error) {
		return statusTestHealthResponse(req, "enforce"), nil
	})}
	t.Cleanup(func() { rampartHTTPClient = oldClient })

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
	askEvent := audit.Event{
		ID:        "01JTEST000000000000000003",
		Timestamp: now.Add(time.Second),
		Agent:     "agent-1",
		Session:   "session-1",
		Tool:      "exec",
		Request:   map[string]any{"command": "git push origin main"},
		Decision:  audit.EventDecision{Action: "ask", EvalTimeUS: 1},
		PrevHash:  denyEvent.Hash,
		Hash:      "sha256:ask",
	}
	allowLine, err := json.Marshal(allowEvent)
	if err != nil {
		t.Fatal(err)
	}
	denyLine, err := json.Marshal(denyEvent)
	if err != nil {
		t.Fatal(err)
	}
	askLine, err := json.Marshal(askEvent)
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(auditDir, now.Format("2006-01-02")+".jsonl")
	content := string(allowLine) + "\n" + string(denyLine) + "\n" + string(askLine) + "\n"
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
	if got.Mode != "enforce" {
		t.Fatalf("mode=%q, want enforce even with default_action=allow", got.Mode)
	}
	if got.DefaultAction != "allow" {
		t.Fatalf("default_action=%q, want allow", got.DefaultAction)
	}
	if got.Today.Allow != 1 || got.Today.Deny != 1 || got.Today.Pending != 1 {
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

func TestStatusUsesServiceModeIndependentlyOfPolicyDefault(t *testing.T) {
	for _, mode := range []string{"monitor", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			home := t.TempDir()
			testSetHome(t, home)
			t.Setenv("PATH", home)
			t.Setenv("RAMPART_URL", "http://127.0.0.1:19090")
			policyDir := filepath.Join(home, ".rampart", "policies")
			if err := os.MkdirAll(policyDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(policyDir, "policy.yaml"), []byte("version: \"1\"\ndefault_action: deny\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			oldClient := rampartHTTPClient
			rampartHTTPClient = &http.Client{Transport: redirectTestTransport(func(req *http.Request) (*http.Response, error) {
				return statusTestHealthResponse(req, mode), nil
			})}
			t.Cleanup(func() { rampartHTTPClient = oldClient })

			snapshot := collectStatusSnapshot(time.Now().UTC())
			if !snapshot.serverRunning || snapshot.mode != mode || snapshot.defaultAction != "deny" {
				t.Fatalf("running=%t mode=%q default=%q", snapshot.serverRunning, snapshot.mode, snapshot.defaultAction)
			}
		})
	}
}

func TestStatusUnavailableConfiguredEndpointInvalidatesServiceReceipt(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	t.Setenv("PATH", home)
	t.Setenv("RAMPART_URL", "http://127.0.0.1:19099")
	hooksPath := filepath.Join(home, ".cursor", "hooks.json")
	if err := installCursorHooks(hooksPath, currentCursorHookCommand(), false); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if err := writeVerificationReceipt(passingAssuranceReport("cursor", now)); err != nil {
		t.Fatal(err)
	}

	var probes []string
	oldClient := rampartHTTPClient
	rampartHTTPClient = &http.Client{Transport: redirectTestTransport(func(req *http.Request) (*http.Response, error) {
		probes = append(probes, req.URL.Host)
		if req.URL.Host == "127.0.0.1:19099" {
			return nil, net.ErrClosed
		}
		// A different healthy daemon must not replace the unavailable endpoint.
		return statusTestHealthResponse(req, "enforce"), nil
	})}
	t.Cleanup(func() { rampartHTTPClient = oldClient })

	snapshot := collectStatusSnapshot(now)
	if snapshot.serverRunning || snapshot.mode != "unknown" {
		t.Fatalf("unavailable endpoint: running=%t mode=%q", snapshot.serverRunning, snapshot.mode)
	}
	if len(probes) != 2 || probes[0] != "127.0.0.1:19099" || probes[1] != "127.0.0.1:19099" {
		t.Fatalf("status probed endpoints other than its configured service: %v", probes)
	}
	status, ok := findAssuranceStatus(snapshot.integrations, "cursor")
	if !ok || status.AssuranceLevel == assuranceAdapterVerified || status.StaleReason != "Rampart policy service is unavailable" {
		t.Fatalf("unavailable Cursor assurance = %#v, found=%t", status, ok)
	}
}

func statusTestHealthResponse(req *http.Request, mode string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Request:    req,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(fmt.Sprintf(`{"service":"rampart","status":"ok","mode":%q,"uptime_seconds":1,"version":"1.9.0","commit":"test-commit","instance_id":"test-service-instance-0001"}`, mode))),
	}
}

func TestDetectProtectedAgents_CodexHooks(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	hooksPath := filepath.Join(home, ".codex", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(hooksPath), 0o700); err != nil {
		t.Fatal(err)
	}
	command, commandWindows := currentCodexHookCommands()
	if err := installCodexHooks(hooksPath, command, commandWindows, false); err != nil {
		t.Fatal(err)
	}

	agents := detectProtectedAgents()
	found := false
	for _, agent := range agents {
		if agent == "Codex (hooks)" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected Codex lifecycle hook detection, got %v", agents)
	}
}

func TestDetectProtectedAgents_GeminiHooks(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	if err := installGeminiHooks(filepath.Join(home, ".gemini", "settings.json"), currentGeminiHookCommand(), false); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, agent := range detectProtectedAgents() {
		if agent == "Gemini CLI (hooks)" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected Gemini CLI lifecycle hook detection, got %v", detectProtectedAgents())
	}
}

func TestDetectProtectedAgents_CopilotHooks(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	path := filepath.Join(home, ".copilot", "hooks", copilotRampartHookFile)
	bashCommand, powershellCommand := currentCopilotHookCommands()
	if err := installCopilotHooks(path, bashCommand, powershellCommand, false); err != nil {
		t.Fatal(err)
	}
	for _, agent := range detectProtectedAgents() {
		if agent == "GitHub Copilot CLI / VS Code (hooks)" {
			return
		}
	}
	t.Fatalf("expected shared Copilot lifecycle hook detection, got %v", detectProtectedAgents())
}

func TestDetectProtectedAgents_CopilotDisabledHooksNotProtected(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	t.Setenv("COPILOT_HOME", "")
	path := filepath.Join(home, ".copilot", "hooks", copilotRampartHookFile)
	bashCommand, powershellCommand := currentCopilotHookCommands()
	if err := installCopilotHooks(path, bashCommand, powershellCommand, false); err != nil {
		t.Fatal(err)
	}
	settings := testReadJSONMap(t, path)
	settings["disableAllHooks"] = true
	data, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, agent := range detectProtectedAgents() {
		if agent == "GitHub Copilot CLI / VS Code (hooks)" {
			t.Fatal("status reported Copilot protected while user hooks are disabled")
		}
	}
}

func TestDetectProtectedAgents_AntigravityPlugin(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	if err := installAntigravityPlugin(antigravityPluginDir(home), currentAntigravityHookCommand(), false); err != nil {
		t.Fatal(err)
	}
	for _, agent := range detectProtectedAgents() {
		if agent == "Antigravity CLI / IDE (plugin)" {
			return
		}
	}
	t.Fatalf("expected Antigravity plugin detection, got %v", detectProtectedAgents())
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
		if strings.Contains(agent, "Codex") {
			t.Fatalf("plain codex binary should not be reported as protected: %v", agent)
		}
	}
}

func TestDetectProtectedAgents_HermesPluginEnabled(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	writeHermesRampartPluginFixture(t, home, "plugins:\n  enabled:\n    - rampart\n")

	found := false
	for _, agent := range detectProtectedAgents() {
		if agent == "Hermes Agent (plugin)" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected Hermes Agent plugin detection, got %v", detectProtectedAgents())
	}
}

func TestDetectProtectedAgents_HermesPluginDisabled(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	writeHermesRampartPluginFixture(t, home, "plugins:\n  enabled:\n    - rampart\n  disabled:\n    - rampart\n")

	for _, agent := range detectProtectedAgents() {
		if agent == "Hermes Agent (plugin)" {
			t.Fatalf("disabled Hermes plugin should not be reported as protected: %v", agent)
		}
	}
}

func writeHermesRampartPluginFixture(t *testing.T, home, config string) {
	t.Helper()
	pluginDir := filepath.Join(home, ".hermes", "plugins", "rampart")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := "name: rampart\nversion: 1.2.0\nprovides_hooks:\n  - pre_tool_call\n"
	if err := os.WriteFile(filepath.Join(pluginDir, "plugin.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(home, ".hermes", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDetectProtectedAgents_OpenClawPluginRequiresAllowedAndEnabled(t *testing.T) {
	home := t.TempDir()
	testSetHome(t, home)
	testSetOpenClawBinary(t, home)
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

	mustWrite(`{"plugins":{"entries":{"rampart":{"enabled":true}}}}`)
	if !contains("OpenClaw (plugin)") {
		t.Fatal("expected plugin to be reported when plugins.allow is absent")
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
