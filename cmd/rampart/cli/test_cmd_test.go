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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peg/rampart/internal/engine"
)

func TestRunTestDeny(t *testing.T) {
	// Write a policy that denies rm commands.
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "rampart.yaml")
	err := os.WriteFile(policyFile, []byte(`
default_action: allow
policies:
  - name: block-destructive
    match:
      tool: "exec"
    rules:
      - action: deny
        message: Destructive command blocked
        when:
          command_matches:
            - "rm -rf *"
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	opts := &rootOptions{configPath: policyFile}

	runErr := runTest(&out, &errOut, opts, "rm -rf /", "exec", true, false)

	// Should return exit code 1.
	if runErr == nil {
		t.Fatal("expected error for denied command")
	}
	var ec interface{ ExitCode() int }
	if e, ok := runErr.(interface{ ExitCode() int }); ok {
		ec = e
	}
	if ec == nil || ec.ExitCode() != 1 {
		t.Fatalf("expected exit code 1, got error: %v", runErr)
	}

	output := out.String()
	if !strings.Contains(output, "DENY") {
		t.Errorf("expected DENY in output, got: %s", output)
	}
	if !strings.Contains(output, "Destructive command blocked") {
		t.Errorf("expected message in output, got: %s", output)
	}
	if !strings.Contains(output, "block-destructive") {
		t.Errorf("expected policy name in output, got: %s", output)
	}
}

func TestRunTestIncludesDurableUserOverrides(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("USERPROFILE", tmpHome)
	policyDir := filepath.Join(tmpHome, ".rampart", "policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "standard.yaml"), []byte(`
version: "1"
default_action: deny
policies:
  - name: block-destructive
    match:
      tool: exec
    rules:
      - action: ask
        message: Secure delete requires approval
        when:
          command_matches: ["shred **"]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "user-overrides.yaml"), []byte(`
version: "1"
default_action: deny
policies:
  - name: user-allow-shred-help
    match:
      tool: exec
    rules:
      - action: allow
        message: User allow (always) via openclaw-approval
        when:
          command_matches: ["shred --help"]
`), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	opts := &rootOptions{configPath: "rampart.yaml"}

	runErr := runTest(&out, &errOut, opts, "shred --help", "exec", true, true)
	if runErr != nil {
		t.Fatalf("expected no error for durable override, got: %v", runErr)
	}

	var got bareCmdJSONResult
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("parse json output: %v\n%s", err, out.String())
	}
	if got.Action != "allow" {
		t.Fatalf("expected durable override to make rampart test return allow, got %#v", got)
	}
	if len(got.MatchedPolicies) != 1 || got.MatchedPolicies[0] != "user-allow-shred-help" {
		t.Fatalf("expected only durable override policy, got %#v", got.MatchedPolicies)
	}
}

func TestRunTestAllow(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "rampart.yaml")
	err := os.WriteFile(policyFile, []byte(`
default_action: allow
policies:
  - name: block-destructive
    match:
      tool: "exec"
    rules:
      - action: deny
        message: Destructive command blocked
        when:
          command_matches:
            - "rm -rf *"
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	opts := &rootOptions{configPath: policyFile}

	runErr := runTest(&out, &errOut, opts, "git status", "exec", true, false)
	if runErr != nil {
		t.Fatalf("expected no error for allowed command, got: %v", runErr)
	}

	output := out.String()
	if !strings.Contains(output, "ALLOW") {
		t.Errorf("expected ALLOW in output, got: %s", output)
	}
}

func TestRunTestReadTool(t *testing.T) {
	skipOnWindows(t, "Unix paths in test")
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "rampart.yaml")
	err := os.WriteFile(policyFile, []byte(`
default_action: allow
policies:
  - name: block-sensitive-reads
    match:
      tool: "read"
    rules:
      - action: deny
        message: Sensitive file access blocked
        when:
          path_matches:
            - "/etc/shadow"
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	opts := &rootOptions{configPath: policyFile}

	runErr := runTest(&out, &errOut, opts, "/etc/shadow", "read", true, false)
	if runErr == nil {
		t.Fatal("expected error for denied read")
	}

	output := out.String()
	if !strings.Contains(output, "DENY") {
		t.Errorf("expected DENY in output, got: %s", output)
	}
}

func TestDiagnosticCommandsUseCanonicalToolCalls(t *testing.T) {
	dir := t.TempDir()
	dangerousPath := filepath.ToSlash(filepath.Join(dir, "private", "credentials.key"))
	dangerousURL := "https://webhook.site/danger/collect.yaml"
	policyFile := filepath.Join(dir, "rampart.yaml")
	policy := fmt.Sprintf(`
version: "1"
default_action: allow
policies:
  - {name: block-command, match: {tool: exec}, rules: [{action: deny, when: {command_matches: ["rm -rf *"]}}]}
  - {name: block-path, match: {tool: [read, write, edit]}, rules: [{action: deny, when: {path_matches: [%q]}}]}
  - {name: block-url, match: {tool: [fetch, web_fetch, http]}, rules: [{action: deny, when: {url_matches: [%q], domain_matches: [webhook.site], path_matches: [/danger/collect.yaml]}}]}
  - {name: block-browser-param, match: {tool: browser}, rules: [{action: deny, when: {tool_param_matches: {url: "https://webhook.site/*"}}}]}
`, dangerousPath, dangerousURL)
	if err := os.WriteFile(policyFile, []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	call, err := newDiagnosticToolCall("fetch", dangerousURL, "diagnostic-agent", "diagnostic-session", now)
	if err != nil || call.Agent != "diagnostic-agent" || call.Session != "diagnostic-session" || !call.Timestamp.Equal(now) ||
		call.URL() != dangerousURL || call.Domain() != "webhook.site" ||
		call.Param("scheme") != "https" || call.Param("path") != "/danger/collect.yaml" || call.Input["url"] != dangerousURL {
		t.Fatalf("canonical URL call not preserved and enriched: call=%#v err=%v", call, err)
	}
	tests := []struct {
		tool       string
		argument   string
		wantPolicy string
	}{
		{tool: "exec", argument: "rm -rf /"},
		{tool: "read", argument: dangerousPath},
		{tool: "write", argument: dangerousPath},
		{tool: "edit", argument: dangerousPath},
		{tool: "fetch", argument: dangerousURL},
		{tool: "web_fetch", argument: dangerousURL},
		{tool: "http", argument: dangerousURL},
		{tool: "browser", argument: dangerousURL, wantPolicy: "block-browser-param"},
	}

	for _, tc := range tests {
		t.Run(tc.tool, func(t *testing.T) {
			testCmd := newTestCmd(&rootOptions{configPath: policyFile})
			var testOut, testErr bytes.Buffer
			testCmd.SetOut(&testOut)
			testCmd.SetErr(&testErr)
			testCmd.SetArgs([]string{tc.argument, "--tool", tc.tool, "--no-color"})
			runErr := testCmd.Execute()
			if runErr == nil || !strings.Contains(testOut.String(), "DENY") {
				t.Fatalf("test diagnostic did not deny: err=%v output=%s", runErr, testOut.String())
			}
			if tc.wantPolicy != "" && !strings.Contains(testOut.String(), tc.wantPolicy) {
				t.Fatalf("test diagnostic did not match %s: %s", tc.wantPolicy, testOut.String())
			}

			explain := newPolicyExplainCmd(&rootOptions{configPath: policyFile})
			var explainOut strings.Builder
			explain.SetOut(&explainOut)
			explain.SetArgs([]string{tc.argument, "--tool", tc.tool})
			if err := explain.Execute(); err != nil {
				t.Fatalf("explain diagnostic: %v", err)
			}
			if !strings.Contains(explainOut.String(), "Final decision: DENY") {
				t.Fatalf("explain diagnostic did not deny: %s", explainOut.String())
			}
			if tc.wantPolicy != "" && !strings.Contains(explainOut.String(), tc.wantPolicy) {
				t.Fatalf("explain diagnostic did not match %s: %s", tc.wantPolicy, explainOut.String())
			}
		})
	}

	if _, err := newDiagnosticToolCall("mcp", "danger", "", "", now); err == nil {
		t.Fatal("expected unsupported MCP tool to be rejected")
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{500 * time.Microsecond, "500μs"},
		{6 * time.Microsecond, "6μs"},
		{100 * time.Microsecond, "100μs"},
		{1500 * time.Microsecond, "1ms"},
	}
	for _, tt := range tests {
		got := formatDuration(tt.d)
		if got != tt.want {
			t.Errorf("formatDuration(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestPrintTestResultNoColor(t *testing.T) {
	var buf bytes.Buffer
	d := engine.Decision{
		Action:          engine.ActionDeny,
		MatchedPolicies: []string{"test-policy"},
		Message:         "blocked",
		EvalDuration:    5 * time.Microsecond,
	}
	printTestResult(&buf, d, true)
	output := buf.String()

	// No ANSI escape codes when noColor=true.
	if strings.Contains(output, "\033[") {
		t.Errorf("expected no ANSI codes with noColor, got: %s", output)
	}
	if !strings.Contains(output, "DENY") {
		t.Errorf("expected DENY, got: %s", output)
	}
}

func TestPrintTestResultColor(t *testing.T) {
	var buf bytes.Buffer
	d := engine.Decision{
		Action:       engine.ActionAllow,
		Message:      "ok",
		EvalDuration: 3 * time.Microsecond,
	}
	printTestResult(&buf, d, false)
	output := buf.String()

	// Should contain ANSI green.
	if !strings.Contains(output, "\033[32m") {
		t.Errorf("expected green ANSI code, got: %s", output)
	}
}
