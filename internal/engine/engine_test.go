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

package engine

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writePolicy writes a YAML policy file to a temp directory and returns
// a configured Engine. Fails the test on any error.
func setupEngine(t *testing.T, yaml string) *Engine {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	store := NewFileStore(path)
	engine, err := New(store, nil)
	if err != nil {
		t.Fatalf("create engine: %v", err)
	}
	return engine
}

// execCall creates a ToolCall for an exec command.
func execCall(agent, command string) ToolCall {
	return ToolCall{
		ID:        "test-001",
		Agent:     agent,
		Session:   "test-session",
		Tool:      "exec",
		Params:    map[string]any{"command": command},
		Timestamp: time.Now(),
	}
}

func TestEvaluate_SingleDenyRule(t *testing.T) {
	e := setupEngine(t, `
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

	got := e.Evaluate(execCall("main", "rm -rf /"))
	if got.Action != ActionDeny {
		t.Errorf("want deny, got %s", got.Action)
	}
	if got.Message != "destructive command blocked" {
		t.Errorf("want denial message, got %q", got.Message)
	}
}

func TestEvaluate_RejectsConflictingSecurityAliases(t *testing.T) {
	e := setupEngine(t, `
version: "1"
default_action: allow
policies: []
`)

	tests := []struct {
		name string
		call ToolCall
	}{
		{
			name: "params and input command",
			call: ToolCall{Tool: "exec",
				Params: map[string]any{"command": "echo safe"},
				Input:  map[string]any{"command": "rm -rf /"}},
		},
		{
			name: "command aliases",
			call: ToolCall{Tool: "exec", Params: map[string]any{
				"command": "echo safe", "cmd": "rm -rf /",
			}},
		},
		{
			name: "path aliases",
			call: ToolCall{Tool: "write", Params: map[string]any{
				"file_path": "/tmp/safe", "path": "/etc/shadow",
			}},
		},
		{
			name: "working directory aliases",
			call: ToolCall{Tool: "exec", WorkDir: "/tmp/safe", Params: map[string]any{
				"cwd": "/etc",
			}},
		},
		{
			name: "url aliases",
			call: ToolCall{Tool: "fetch", Params: map[string]any{
				"url": "https://github.com", "uri": "https://webhook.site/steal",
			}},
		},
		{
			name: "non string command",
			call: ToolCall{Tool: "exec", Params: map[string]any{
				"command": []string{"echo", "safe"},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := e.Evaluate(tt.call)
			require.Equal(t, ActionDeny, decision.Action)
			require.Contains(t, decision.Message, "ambiguous tool input")
		})
	}

	t.Run("identical duplicate is compatible", func(t *testing.T) {
		decision := e.Evaluate(ToolCall{
			Tool:   "exec",
			Params: map[string]any{"command": "git status"},
			Input:  map[string]any{"command": "git status"},
		})
		require.Equal(t, ActionAllow, decision.Action)
	})
}

func TestEvaluate_DerivesDomainFromURL(t *testing.T) {
	e := setupEngine(t, `
version: "1"
default_action: allow
policies:
  - name: block-exfil-domain
    match:
      tool: fetch
    rules:
      - action: deny
        when:
          domain_matches: ["webhook.site"]
`)
	decision := e.Evaluate(ToolCall{Tool: "fetch", Params: map[string]any{
		"url":    "https://webhook.site/collect",
		"domain": "github.com",
	}})
	require.Equal(t, ActionDeny, decision.Action)
	require.Equal(t, "webhook.site", (ToolCall{Params: map[string]any{
		"url": "https://webhook.site/collect", "domain": "github.com",
	}}).Domain())
}

func TestEvaluate_ConsumesValidatedSecurityAliases(t *testing.T) {
	e := setupEngine(t, `
version: "1"
default_action: allow
policies:
  - name: block-command-alias
    match:
      tool: exec
    rules:
      - action: deny
        when:
          command_matches: ["rm -rf *"]
  - name: block-path-alias
    match:
      tool: write
    rules:
      - action: deny
        when:
          path_matches: ["/etc/**"]
  - name: block-url-alias
    match:
      tool: fetch
    rules:
      - action: deny
        when:
          domain_matches: ["webhook.site"]
`)

	tests := []ToolCall{
		{
			Tool:   "exec",
			Params: map[string]any{"command": "   "},
			Input:  map[string]any{"cmd": "rm -rf /"},
		},
		{Tool: "write", Params: map[string]any{"target": "/etc/shadow"}},
		{Tool: "fetch", Input: map[string]any{"href": "https://webhook.site/collect"}},
	}
	for _, call := range tests {
		decision := e.Evaluate(call)
		require.Equal(t, ActionDeny, decision.Action, "call: %#v; decision: %#v", call, decision)
	}
}

func TestEvaluate_SingleAllowRule(t *testing.T) {
	e := setupEngine(t, `
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
        message: "git commands allowed"
`)

	got := e.Evaluate(execCall("main", "git push origin main"))
	if got.Action != ActionAllow {
		t.Errorf("want allow, got %s", got.Action)
	}
}

func TestEvaluate_DenyWinsOverAllow(t *testing.T) {
	e := setupEngine(t, `
version: "1"
default_action: allow
policies:
  - name: allow-all
    priority: 100
    match:
      tool: exec
    rules:
      - action: allow
        when:
          default: true
  - name: block-rm
    priority: 10
    match:
      tool: exec
    rules:
      - action: deny
        when:
          command_matches: ["rm -rf *"]
        message: "blocked"
`)

	got := e.Evaluate(execCall("main", "rm -rf /"))
	if got.Action != ActionDeny {
		t.Errorf("deny should win over allow, got %s", got.Action)
	}
}

func TestEvaluate_DurableUserOverrideWinsBeforeAsk(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "standard.yaml"), []byte(`
version: "1"
default_action: deny
policies:
  - name: block-destructive
    match:
      tool: exec
    rules:
      - action: deny
        when:
          command_matches: ["rm -rf *"]
        message: "Destructive command blocked"
      - action: ask
        when:
          command_matches: ["shred **"]
        message: "Secure delete requires approval"
  - name: user-allow-name-alone-is-not-durable
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["shred --version"]
        message: "ordinary allow"
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "user-overrides.yaml"), []byte(`
version: "1"
default_action: deny
policies:
  - name: user-allow-shred-help
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["shred --help"]
        message: "User allow (always) via openclaw-approval"
  - name: user-allow-rm-root
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["rm -rf /"]
        message: "User allow (always) via openclaw-approval"
`), 0o644))

	eng, err := New(NewDirStore(dir, nil), nil)
	require.NoError(t, err)

	got := eng.Evaluate(execCall("main", "shred --help"))
	require.Equal(t, ActionAllow, got.Action)
	assert.Equal(t, []string{"user-allow-shred-help"}, got.MatchedPolicies)
	assert.Equal(t, "User allow (always) via openclaw-approval", got.Message)

	stillAsk := eng.Evaluate(execCall("main", "shred --help | head -n 1"))
	require.Equal(t, ActionAsk, stillAsk.Action)
	assert.Contains(t, stillAsk.MatchedPolicies, "block-destructive")
	assert.NotContains(t, stillAsk.MatchedPolicies, "user-allow-shred-help")

	nameAloneIsNotDurable := eng.Evaluate(execCall("main", "shred --version"))
	require.Equal(t, ActionAsk, nameAloneIsNotDurable.Action)
	assert.Contains(t, nameAloneIsNotDurable.MatchedPolicies, "user-allow-name-alone-is-not-durable")
	assert.Contains(t, nameAloneIsNotDurable.MatchedPolicies, "block-destructive")

	denyStillWins := eng.Evaluate(execCall("main", "rm -rf /"))
	require.Equal(t, ActionDeny, denyStillWins.Action)
	assert.Contains(t, denyStillWins.MatchedPolicies, "block-destructive")
}

func TestEvaluate_DefaultDeny(t *testing.T) {
	e := setupEngine(t, `
version: "1"
default_action: deny
policies: []
`)

	got := e.Evaluate(execCall("main", "anything"))
	if got.Action != ActionDeny {
		t.Errorf("want default deny, got %s", got.Action)
	}
}

func TestEvaluate_DefaultAllow(t *testing.T) {
	e := setupEngine(t, `
version: "1"
default_action: allow
policies: []
`)

	got := e.Evaluate(execCall("main", "anything"))
	if got.Action != ActionAllow {
		t.Errorf("want default allow, got %s", got.Action)
	}
}

func TestEvaluate_AgentIdentityMatching(t *testing.T) {
	e := setupEngine(t, `
version: "1"
default_action: allow
policies:
  - name: ops-only
    match:
      agent: "ops-*"
      tool: exec
    rules:
      - action: deny
        when:
          command_matches: ["kubectl delete *"]
        message: "ops agents cannot delete"
`)

	// ops-deploy should match "ops-*" and be denied.
	got := e.Evaluate(execCall("ops-deploy", "kubectl delete namespace prod"))
	if got.Action != ActionDeny {
		t.Errorf("ops-deploy should be denied, got %s", got.Action)
	}

	// dev-agent should NOT match "ops-*" and fall through to default allow.
	got = e.Evaluate(execCall("dev-agent", "kubectl delete namespace prod"))
	if got.Action != ActionAllow {
		t.Errorf("dev-agent should be allowed (no matching policy), got %s", got.Action)
	}
}

func TestEvaluate_LogAction(t *testing.T) {
	e := setupEngine(t, `
version: "1"
default_action: allow
policies:
  - name: log-sudo
    match:
      tool: exec
    rules:
      - action: log
        when:
          command_matches: ["sudo *"]
        message: "sudo usage flagged for review"
`)

	got := e.Evaluate(execCall("main", "sudo apt update"))
	if got.Action != ActionWatch {
		t.Errorf("want log, got %s", got.Action)
	}
}

func TestEvaluate_CommandGlobMatching(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		command string
		want    bool
	}{
		{"exact match", "git push", "git push", true},
		{"wildcard suffix", "git *", "git push origin main", true},
		{"wildcard no match", "git *", "npm test", false},
		{"rm -rf wildcard", "rm -rf *", "rm -rf /", true},
		{"rm -rf no match", "rm -rf *", "rm file.txt", false},
		{"star matches all", "*", "anything at all", true},
		{"empty pattern", "", "anything", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchGlob(tt.pattern, tt.command)
			if got != tt.want {
				t.Errorf("MatchGlob(%q, %q) = %v, want %v", tt.pattern, tt.command, got, tt.want)
			}
		})
	}
}

func TestEvaluate_DisabledPolicy(t *testing.T) {
	e := setupEngine(t, `
version: "1"
default_action: allow
policies:
  - name: disabled-deny
    enabled: false
    match:
      tool: exec
    rules:
      - action: deny
        when:
          default: true
`)

	got := e.Evaluate(execCall("main", "rm -rf /"))
	if got.Action != ActionAllow {
		t.Errorf("disabled policy should not match, got %s", got.Action)
	}
}

func TestEvaluate_ToolGlobMatching(t *testing.T) {
	e := setupEngine(t, `
version: "1"
default_action: allow
policies:
  - name: block-all-exec
    match:
      tool: exec
    rules:
      - action: deny
        when:
          default: true
`)

	// exec tool should match.
	got := e.Evaluate(ToolCall{
		ID: "t1", Agent: "main", Tool: "exec",
		Params: map[string]any{"command": "ls"},
	})
	if got.Action != ActionDeny {
		t.Errorf("exec should be denied, got %s", got.Action)
	}

	// read tool should NOT match.
	got = e.Evaluate(ToolCall{
		ID: "t2", Agent: "main", Tool: "read",
		Params: map[string]any{"path": "/etc/passwd"},
	})
	if got.Action != ActionAllow {
		t.Errorf("read should be allowed (no matching policy), got %s", got.Action)
	}
}

func TestReload_UpdatesActivePolicies(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	// Start with allow-all.
	initial := `
version: "1"
default_action: allow
policies: []
`
	if err := os.WriteFile(path, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}

	store := NewFileStore(path)
	engine, err := New(store, nil)
	if err != nil {
		t.Fatal(err)
	}

	got := engine.Evaluate(execCall("main", "rm -rf /"))
	if got.Action != ActionAllow {
		t.Errorf("before reload: want allow, got %s", got.Action)
	}

	// Update to deny-all.
	updated := `
version: "1"
default_action: deny
policies: []
`
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := engine.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}

	got = engine.Evaluate(execCall("main", "rm -rf /"))
	if got.Action != ActionDeny {
		t.Errorf("after reload: want deny, got %s", got.Action)
	}
}

func TestPeriodicReloadLifecycleIsConcurrentSafe(t *testing.T) {
	engine := setupEngine(t, `
version: "1"
default_action: allow
policies: []
`)

	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if i%2 == 0 {
				engine.StartPeriodicReload(time.Hour)
				return
			}
			engine.Stop()
		}()
	}
	wg.Wait()
	engine.Stop()
}

func TestValidation_DuplicatePolicyName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	yaml := `
version: "1"
default_action: allow
policies:
  - name: same-name
    rules: []
  - name: same-name
    rules: []
`
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	store := NewFileStore(path)
	_, err := New(store, nil)
	if err == nil {
		t.Error("expected error for duplicate policy name")
	}
}

func TestValidation_InvalidAction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	yaml := `
version: "1"
default_action: allow
policies:
  - name: bad-action
    rules:
      - action: explode
        when:
          default: true
`
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	store := NewFileStore(path)
	_, err := New(store, nil)
	if err == nil {
		t.Error("expected error for invalid action")
	}
}

func TestEvaluateResponse(t *testing.T) {
	e := setupEngine(t, `
version: "1"
default_action: allow
policies:
  - name: block-credential-leaks
    match:
      tool: ["exec", "read"]
    rules:
      - action: deny
        when:
          response_matches:
            - "AKIA[0-9A-Z]{16}"
            - "-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
        message: "Sensitive credential detected in response"
  - name: block-jwt
    match:
      tool: ["exec"]
    rules:
      - action: deny
        when:
          response_matches:
            - "eyJ[a-zA-Z0-9_-]+\\.eyJ[a-zA-Z0-9_-]+"
          response_not_matches:
            - "example\\.invalid"
        message: "JWT token detected in response"
`)

	tests := []struct {
		name        string
		tool        string
		output      string
		wantAction  Action
		wantMessage string
	}{
		{
			name:        "aws key denied",
			tool:        "exec",
			output:      "creds=AKIA1234567890ABCDEF",
			wantAction:  ActionDeny,
			wantMessage: "Sensitive credential detected in response",
		},
		{
			name:        "ssh private key denied",
			tool:        "read",
			output:      "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n",
			wantAction:  ActionDeny,
			wantMessage: "Sensitive credential detected in response",
		},
		{
			name:       "no secrets allowed",
			tool:       "exec",
			output:     "build complete",
			wantAction: ActionAllow,
		},
		{
			name:       "response_not_matches exclusion allows",
			tool:       "exec",
			output:     "token=eyJabcDEF12.eyJxyzABC99 example.invalid",
			wantAction: ActionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := ToolCall{
				ID:        "response-1",
				Agent:     "main",
				Session:   "s1",
				Tool:      tt.tool,
				Params:    map[string]any{"command": "echo test"},
				Timestamp: time.Now(),
			}

			got := e.EvaluateResponse(call, tt.output)
			assert.Equal(t, tt.wantAction, got.Action)
			if tt.wantMessage != "" {
				assert.Equal(t, tt.wantMessage, got.Message)
			}
		})
	}
}

func TestEvaluateResponseApprovalActionFailsClosed(t *testing.T) {
	e := setupEngine(t, `
version: "1"
default_action: allow
policies:
  - name: suspicious-response
    match:
      tool: fetch
    rules:
      - action: ask
        when:
          response_matches: ["ignore previous instructions"]
        message: "suspicious response"
`)

	got := e.EvaluateResponse(
		ToolCall{Agent: "test", Tool: "fetch"},
		"ignore previous instructions",
	)
	if got.Action != ActionDeny {
		t.Fatalf("response action = %s, want deny", got.Action)
	}
	if got.Message != "suspicious response" {
		t.Fatalf("response message = %q", got.Message)
	}
}

func TestValidation_InvalidResponseRegex(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	yaml := `
version: "1"
default_action: allow
policies:
  - name: bad-response-regex
    match:
      tool: exec
    rules:
      - action: deny
        when:
          response_matches: ["("]
`
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0o644))

	store := NewFileStore(path)
	_, err := New(store, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "engine:")
	assert.Contains(t, err.Error(), "invalid response regex")
}

func TestValidation_RejectsNestedQuantifierResponseRegex(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	yaml := `
version: "1"
default_action: allow
policies:
  - name: bad-response-regex
    match:
      tool: exec
    rules:
      - action: deny
        when:
          response_matches: ["(a+)+$"]
`
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0o644))

	store := NewFileStore(path)
	_, err := New(store, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nested quantifiers")
}

func TestValidation_RejectsOverlongResponseRegex(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	longPattern := strings.Repeat("a", maxResponseRegexPatternLength+1)

	yaml := `
version: "1"
default_action: allow
policies:
  - name: long-response-regex
    match:
      tool: exec
    rules:
      - action: deny
        when:
          response_matches: ["` + longPattern + `"]
`
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0o644))

	store := NewFileStore(path)
	_, err := New(store, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pattern too long")
}

// BenchmarkEvaluate measures the hot path: evaluating a single tool call
// against a realistic set of policies. Target: <0.1ms p99.
func BenchmarkEvaluate(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	// Realistic policy set: 5 policies, mix of allow/deny/log.
	yaml := `
version: "1"
default_action: allow
policies:
  - name: protect-credentials
    priority: 10
    match:
      agent: "*"
      tool: exec
    rules:
      - action: deny
        when:
          command_matches: ["cat ~/.ssh/*", "cat ~/.aws/*"]
  - name: block-destructive
    priority: 20
    match:
      tool: exec
    rules:
      - action: deny
        when:
          command_matches: ["rm -rf *", "dd if=/dev/zero *"]
  - name: log-sudo
    priority: 50
    match:
      tool: exec
    rules:
      - action: log
        when:
          command_matches: ["sudo *"]
  - name: allow-git
    priority: 100
    match:
      agent: "dev-*"
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["git *"]
  - name: allow-npm
    priority: 100
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["npm *"]
`
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		b.Fatal(err)
	}

	store := NewFileStore(path)
	engine, err := New(store, nil)
	if err != nil {
		b.Fatal(err)
	}

	call := execCall("dev-agent", "git push origin main")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		engine.Evaluate(call)
	}
}

func TestEvaluateResponse_FailsClosedOnLargeBody(t *testing.T) {
	e := setupEngine(t, `
version: "1"
default_action: allow
policies:
  - name: block-credential-leaks
    match:
      tool: ["exec"]
    rules:
      - action: deny
        when:
          response_matches:
            - "AKIA[0-9A-Z]{16}"
        message: "credential detected"
`)

	// Build a response where the secret is beyond 1MB.
	padding := strings.Repeat("x", 1<<20) // exactly 1MB of padding
	secret := "AKIA1234567890ABCDEF"
	largeResponse := padding + secret

	call := ToolCall{
		ID:        "trunc-test",
		Agent:     "main",
		Session:   "s1",
		Tool:      "exec",
		Params:    map[string]any{"command": "cat big.txt"},
		Timestamp: time.Now(),
	}

	// A prefix-only scan could miss the secret, so oversized responses fail closed.
	got := e.EvaluateResponse(call, largeResponse)
	assert.Equal(t, ActionDeny, got.Action, "oversized response should fail closed")
	assert.Contains(t, got.Message, "exceeds")

	// Secret within the cap should still be detected.
	smallResponse := "prefix AKIA1234567890ABCDEF suffix"
	got2 := e.EvaluateResponse(call, smallResponse)
	assert.Equal(t, ActionDeny, got2.Action, "secret within cap should be detected")
}

func TestEvaluateResponse_LargeBodyWithoutApplicableResponseRuleIsAllowed(t *testing.T) {
	e := setupEngine(t, `
version: "1"
default_action: allow
policies:
  - name: command-only
    match:
      tool: exec
    rules:
      - action: deny
        when:
          command_matches: ["rm *"]
`)
	call := execCall("main", "cat big.txt")
	got := e.EvaluateResponse(call, strings.Repeat("x", maxResponseMatchSize+1))
	assert.Equal(t, ActionAllow, got.Action)
}

func TestEvaluate_FailsClosedOnOversizedMatchInputs(t *testing.T) {
	e := setupEngine(t, `
version: "1"
default_action: allow
policies:
  - name: durable-prefix
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["safe *"]
`)

	boundary := strings.Repeat("a", maxGlobInputLen)
	assert.Equal(t, ActionAllow, e.Evaluate(execCall("main", boundary)).Action)

	oversized := "safe " + strings.Repeat("a", maxGlobInputLen) + " && rm -rf /"
	decision := e.Evaluate(execCall("main", oversized))
	assert.Equal(t, ActionDeny, decision.Action)
	assert.Contains(t, decision.Message, "exceeds")
}

func TestEvaluate_FailsClosedOnOversizedReferencedToolParameter(t *testing.T) {
	e := setupEngine(t, `
version: "1"
default_action: allow
policies:
  - name: inspect-query
    match:
      tool: search
    rules:
      - action: deny
        when:
          tool_param_matches:
            query: "**secret**"
`)
	call := ToolCall{
		Agent: "main",
		Tool:  "search",
		Input: map[string]any{"query": strings.Repeat("x", maxGlobInputLen+1)},
	}
	assert.Equal(t, ActionDeny, e.Evaluate(call).Action)

	// Large content that no policy matches is not rejected merely because it is
	// carried alongside a bounded, policy-relevant parameter.
	call.Input = map[string]any{
		"query":   "ordinary",
		"content": strings.Repeat("x", maxGlobInputLen+1),
	}
	assert.Equal(t, ActionAllow, e.Evaluate(call).Action)
}

func TestEvaluateResponse_RegexMatchTimeout(t *testing.T) {
	e := setupEngine(t, `
version: "1"
default_action: allow
policies:
  - name: timeout-check
    match:
      tool: ["exec"]
    rules:
      - action: deny
        when:
          response_matches:
            - "secret"
        message: "secret detected"
`)

	regexMatchMu.Lock()
	regexMatchFunc = func(re *regexp.Regexp, value string) bool {
		time.Sleep(200 * time.Millisecond)
		return re.MatchString(value)
	}
	regexMatchMu.Unlock()
	t.Cleanup(func() {
		regexMatchMu.Lock()
		regexMatchFunc = nil
		regexMatchMu.Unlock()
	})

	call := ToolCall{
		ID:        "timeout-test",
		Agent:     "main",
		Session:   "s1",
		Tool:      "exec",
		Params:    map[string]any{"command": "echo test"},
		Timestamp: time.Now(),
	}

	start := time.Now()
	got := e.EvaluateResponse(call, "secret")
	elapsed := time.Since(start)

	assert.Equal(t, ActionDeny, got.Action, "timeout should fail closed — deny rule fires")
	assert.GreaterOrEqual(t, elapsed, 90*time.Millisecond)
	assert.Less(t, elapsed, 190*time.Millisecond)
}

func TestEvaluateResponse_ExclusionRegexTimeoutFailsClosed(t *testing.T) {
	e := setupEngine(t, `
version: "1"
default_action: allow
policies:
  - name: timeout-check
    match:
      tool: ["exec"]
    rules:
      - action: deny
        when:
          response_matches: ["secret"]
          response_not_matches: ["documented-example"]
        message: "secret detected"
`)

	regexMatchMu.Lock()
	regexMatchFunc = func(re *regexp.Regexp, value string) bool {
		if re.String() == "documented-example" {
			time.Sleep(200 * time.Millisecond)
		}
		return re.MatchString(value)
	}
	regexMatchMu.Unlock()
	t.Cleanup(func() {
		regexMatchMu.Lock()
		regexMatchFunc = nil
		regexMatchMu.Unlock()
	})

	got := e.EvaluateResponse(execCall("main", "echo test"), "secret")
	assert.Equal(t, ActionDeny, got.Action, "an exclusion timeout must not suppress a deny rule")
}

func BenchmarkEvaluateResponse10KB(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	yaml := `
version: "1"
default_action: allow
policies:
  - name: block-credential-leaks
    match:
      tool: ["exec", "read"]
    rules:
      - action: deny
        when:
          response_matches:
            - "AKIA[0-9A-Z]{16}"
            - "-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
            - "ghp_[a-zA-Z0-9]{36}"
`
	require.NoError(b, os.WriteFile(path, []byte(yaml), 0o644))

	store := NewFileStore(path)
	engine, err := New(store, nil)
	require.NoError(b, err)

	payload := strings.Repeat("x", 10*1024)
	call := ToolCall{
		ID:        "bench-response",
		Agent:     "bench",
		Session:   "bench",
		Tool:      "exec",
		Params:    map[string]any{"command": "cat file.txt"},
		Timestamp: time.Now(),
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		engine.EvaluateResponse(call, payload)
	}
}

// TestSessionMatches verifies that session_matches condition filters by session.
func TestSessionMatches(t *testing.T) {
	e := setupEngine(t, `
version: "1"
default_action: allow
policies:
  - name: block-in-prod
    match:
      agent: "*"
    rules:
      - action: deny
        message: "blocked in prod session"
        when:
          command_matches: ["rm *"]
          session_matches: ["*/prod", "production/*"]
`)

	// Session that matches → should be denied
	callProd := ToolCall{
		Agent:   "claude-code",
		Session: "myrepo/prod",
		Tool:    "exec",
		Params:  map[string]any{"command": "rm -rf /tmp/foo"},
	}
	d := e.Evaluate(callProd)
	if d.Action != ActionDeny {
		t.Errorf("session matching: expected deny for session %q, got %s", callProd.Session, d.Action)
	}

	// Session that does not match → should allow
	callDev := ToolCall{
		Agent:   "claude-code",
		Session: "myrepo/staging",
		Tool:    "exec",
		Params:  map[string]any{"command": "rm -rf /tmp/foo"},
	}
	d2 := e.Evaluate(callDev)
	if d2.Action == ActionDeny {
		t.Errorf("session matching: expected allow for session %q, got %s", callDev.Session, d2.Action)
	}
}

// TestSessionNotMatches verifies session_not_matches excludes sessions.
func TestSessionNotMatches(t *testing.T) {
	e := setupEngine(t, `
version: "1"
default_action: allow
policies:
  - name: allow-except-prod
    match:
      agent: "*"
    rules:
      - action: deny
        message: "blocked outside dev"
        when:
          command_matches: ["rm *"]
          session_not_matches: ["*/dev", "*/staging"]
`)

	// Session NOT in the exclusion list → deny applies
	callProd := ToolCall{
		Agent:   "claude-code",
		Session: "myrepo/prod",
		Tool:    "exec",
		Params:  map[string]any{"command": "rm -rf /tmp/foo"},
	}
	d := e.Evaluate(callProd)
	if d.Action != ActionDeny {
		t.Errorf("session_not_matches: expected deny for %q, got %s", callProd.Session, d.Action)
	}

	// Session in the exclusion list → deny does NOT apply
	callDev := ToolCall{
		Agent:   "claude-code",
		Session: "myrepo/dev",
		Tool:    "exec",
		Params:  map[string]any{"command": "rm -rf /tmp/foo"},
	}
	d2 := e.Evaluate(callDev)
	if d2.Action == ActionDeny {
		t.Errorf("session_not_matches: expected allow for %q, got %s", callDev.Session, d2.Action)
	}
}

// TestMatchSessionScope verifies Match.Session scoping at the policy level.
func TestMatchSessionScope(t *testing.T) {
	e := setupEngine(t, `
version: "1"
default_action: allow
policies:
  - name: prod-only-policy
    match:
      agent: "*"
      session: "*/prod"
    rules:
      - action: deny
        message: "prod locked down"
        when:
          default: true
`)

	callProd := ToolCall{
		Agent:   "claude-code",
		Session: "myrepo/prod",
		Tool:    "exec",
		Params:  map[string]any{"command": "echo test"},
	}
	d := e.Evaluate(callProd)
	if d.Action != ActionDeny {
		t.Errorf("Match.Session scope: expected deny for %q, got %s", callProd.Session, d.Action)
	}

	callMain := ToolCall{
		Agent:   "claude-code",
		Session: "myrepo/main",
		Tool:    "exec",
		Params:  map[string]any{"command": "echo test"},
	}
	d2 := e.Evaluate(callMain)
	if d2.Action == ActionDeny {
		t.Errorf("Match.Session scope: expected allow for %q, got %s", callMain.Session, d2.Action)
	}
}

func TestEvaluateWith_PolicyFilter(t *testing.T) {
	// Create two policy files with different profiles.
	dir := t.TempDir()
	standardFile := filepath.Join(dir, "standard.yaml")
	paranoidFile := filepath.Join(dir, "paranoid.yaml")

	standardYAML := `version: "1"
policies:
  - name: standard-allow-echo
    match:
      tool: ["exec"]
    rules:
      - action: allow
        when:
          command_matches: ["echo *"]
        message: "standard allows echo"
`
	paranoidYAML := `version: "1"
policies:
  - name: paranoid-deny-all
    match:
      tool: ["exec"]
    rules:
      - action: deny
        message: "paranoid denies everything"
`
	if err := os.WriteFile(standardFile, []byte(standardYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paranoidFile, []byte(paranoidYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := NewDirStore(dir, logger)
	eng, err := New(store, logger)
	if err != nil {
		t.Fatal(err)
	}

	call := ToolCall{
		Tool:   "exec",
		Params: map[string]any{"command": "echo hello"},
	}

	// No filter: both profiles considered. paranoid deny-all fires (first-match-wins).
	d := eng.EvaluateWith(call, EvalOptions{})
	if d.Action != ActionDeny {
		t.Errorf("unfiltered: expected deny (paranoid fires first), got %s (%s)", d.Action, d.Message)
	}

	// Filter to paranoid: only paranoid-deny-all considered.
	d = eng.EvaluateWith(call, EvalOptions{PolicyFilter: "paranoid"})
	if d.Action != ActionDeny {
		t.Errorf("paranoid filter: expected deny, got %s (%s)", d.Action, d.Message)
	}

	// Filter to standard: only standard-allow-echo considered.
	d = eng.EvaluateWith(call, EvalOptions{PolicyFilter: "standard"})
	if d.Action != ActionAllow {
		t.Errorf("standard filter: expected allow, got %s (%s)", d.Action, d.Message)
	}

	// Filter to nonexistent profile: no policies match, default deny kicks in.
	d = eng.EvaluateWith(call, EvalOptions{PolicyFilter: "nonexistent", DefaultDeny: true})
	if d.Action != ActionDeny {
		t.Errorf("nonexistent filter: expected deny, got %s (%s)", d.Action, d.Message)
	}
}

func TestConfigFingerprintChangesOnRuleEdit(t *testing.T) {
	cfg1 := &Config{
		DefaultAction: "deny",
		Policies: []Policy{{
			Name:  "test",
			Rules: []Rule{{Action: "allow", When: Condition{CommandMatches: []string{"git *"}}}},
		}},
	}
	cfg2 := &Config{
		DefaultAction: "deny",
		Policies: []Policy{{
			Name:  "test",
			Rules: []Rule{{Action: "allow", When: Condition{CommandMatches: []string{"npm *"}}}},
		}},
	}
	// Same policy name, same rule count, different rule content.
	fp1 := mustConfigFingerprint(t, cfg1)
	fp2 := mustConfigFingerprint(t, cfg2)
	assert.NotEqual(t, fp1, fp2, "fingerprint should differ when rule content changes")

	// Same config should produce identical fingerprint.
	fp1b := mustConfigFingerprint(t, cfg1)
	assert.Equal(t, fp1, fp1b, "same config should produce identical fingerprint")
}

func TestConfigFingerprintChangesOnActionChange(t *testing.T) {
	cfg1 := &Config{
		DefaultAction: "deny",
		Policies: []Policy{{
			Name:  "test",
			Rules: []Rule{{Action: "allow", When: Condition{CommandMatches: []string{"rm *"}}}},
		}},
	}
	cfg2 := &Config{
		DefaultAction: "deny",
		Policies: []Policy{{
			Name:  "test",
			Rules: []Rule{{Action: "deny", When: Condition{CommandMatches: []string{"rm *"}}}},
		}},
	}
	fp1 := mustConfigFingerprint(t, cfg1)
	fp2 := mustConfigFingerprint(t, cfg2)
	assert.NotEqual(t, fp1, fp2, "fingerprint should differ when action changes")
}

func TestConfigFingerprintChangesOnDefaultAction(t *testing.T) {
	cfg1 := &Config{
		DefaultAction: "allow",
		Policies: []Policy{{
			Name:  "test",
			Rules: []Rule{{Action: "deny", When: Condition{CommandMatches: []string{"rm *"}}}},
		}},
	}
	cfg2 := &Config{
		DefaultAction: "deny",
		Policies: []Policy{{
			Name:  "test",
			Rules: []Rule{{Action: "deny", When: Condition{CommandMatches: []string{"rm *"}}}},
		}},
	}
	fp1 := mustConfigFingerprint(t, cfg1)
	fp2 := mustConfigFingerprint(t, cfg2)
	assert.NotEqual(t, fp1, fp2, "fingerprint should differ when default action changes")
}

func TestConfigFingerprintCoversAllPolicyBehavior(t *testing.T) {
	enabled := false
	expires := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	failOpen := true
	base := func() *Config {
		return &Config{
			Version:       "1",
			DefaultAction: "deny",
			Policies: []Policy{{
				Name:  "test",
				Match: Match{Agent: "*", Session: "*", Tool: StringOrSlice{"exec"}},
				Rules: []Rule{{Action: "ask", When: Condition{Default: true}}},
			}},
		}
	}
	baseline := mustConfigFingerprint(t, base())

	tests := map[string]func(*Config){
		"policy match": func(cfg *Config) { cfg.Policies[0].Match.Agent = "codex" },
		"priority":     func(cfg *Config) { cfg.Policies[0].Priority = 10 },
		"enabled":      func(cfg *Config) { cfg.Policies[0].Enabled = &enabled },
		"expiry":       func(cfg *Config) { cfg.Policies[0].Rules[0].ExpiresAt = &expires },
		"ask config":   func(cfg *Config) { cfg.Policies[0].Rules[0].Ask.Audit = true },
		"webhook": func(cfg *Config) {
			cfg.Policies[0].Rules[0].Action = "webhook"
			cfg.Policies[0].Rules[0].Webhook = &WebhookActionConfig{URL: "https://example.invalid/hook", FailOpen: &failOpen}
		},
		"notifications": func(cfg *Config) {
			cfg.Notify = &NotifyConfig{URL: "https://example.invalid/notify", Platform: "webhook", On: []string{"deny"}}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := base()
			mutate(cfg)
			assert.NotEqual(t, baseline, mustConfigFingerprint(t, cfg))
		})
	}
}

func mustConfigFingerprint(t *testing.T, cfg *Config) string {
	t.Helper()
	fingerprint, err := configFingerprint(cfg)
	require.NoError(t, err)
	return fingerprint
}
