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
	"strings"
	"testing"
)

// ── ParseAction ──────────────────────────────────────────────────────────────

func TestParseAction_Ask(t *testing.T) {
	a, err := ParseAction("ask")
	if err != nil {
		t.Fatalf("ParseAction(\"ask\") unexpected error: %v", err)
	}
	if a != ActionAsk {
		t.Errorf("ParseAction(\"ask\") = %v, want ActionAsk", a)
	}
}

func TestParseAction_AskString(t *testing.T) {
	if got := ActionAsk.String(); got != "ask" {
		t.Errorf("ActionAsk.String() = %q, want \"ask\"", got)
	}
}

func TestParseAction_AllActions(t *testing.T) {
	// Ensure each action round-trips through ParseAction → String cleanly.
	cases := []struct {
		input  string
		action Action
	}{
		{"allow", ActionAllow},
		{"deny", ActionDeny},
		{"watch", ActionWatch},
		{"require_approval", ActionRequireApproval},
		{"webhook", ActionWebhook},
		{"ask", ActionAsk},
	}
	for _, tc := range cases {
		got, err := ParseAction(tc.input)
		if err != nil {
			t.Errorf("ParseAction(%q) error: %v", tc.input, err)
			continue
		}
		if got != tc.action {
			t.Errorf("ParseAction(%q) = %v, want %v", tc.input, got, tc.action)
		}
		if got.String() != tc.input {
			t.Errorf("Action(%q).String() = %q, want %q", tc.input, got.String(), tc.input)
		}
	}
}

func TestParseAction_Unknown(t *testing.T) {
	_, err := ParseAction("frobnicate")
	if err == nil {
		t.Error("ParseAction(\"frobnicate\") expected error, got nil")
	}
}

// ── Rule.ParseAction ─────────────────────────────────────────────────────────

func TestRuleParseAction_Ask(t *testing.T) {
	r := Rule{Action: "ask"}
	a, err := r.ParseAction()
	if err != nil {
		t.Fatalf("Rule{action:ask}.ParseAction() unexpected error: %v", err)
	}
	if a != ActionAsk {
		t.Errorf("Rule{action:ask}.ParseAction() = %v, want ActionAsk", a)
	}
}

func TestRuleAskAuditEnabled_RequireApprovalAlias(t *testing.T) {
	r := Rule{Action: "require_approval"}
	if !r.AskAuditEnabled() {
		t.Fatal("expected require_approval to be treated as ask+audit")
	}
}

func TestRuleAskAuditEnabled_AskExplicitAudit(t *testing.T) {
	r := Rule{Action: "ask", Ask: AskActionConfig{Audit: true}}
	if !r.AskAuditEnabled() {
		t.Fatal("expected ask.audit=true to enable ask audit")
	}
}

func TestRuleAskAuditEnabled_AskDefaultFalse(t *testing.T) {
	r := Rule{Action: "ask"}
	if r.AskAuditEnabled() {
		t.Fatal("expected ask.audit to default to false")
	}
}

func TestRuleHeadlessOnlyEnabled_AskExplicit(t *testing.T) {
	r := Rule{Action: "ask", Ask: AskActionConfig{HeadlessOnly: true}}
	if !r.HeadlessOnlyEnabled() {
		t.Fatal("expected ask.headless_only=true to enable headless-only mode")
	}
}

func TestRuleHeadlessOnlyEnabled_RequireApprovalFalse(t *testing.T) {
	r := Rule{Action: "require_approval", Ask: AskActionConfig{HeadlessOnly: true}}
	if r.HeadlessOnlyEnabled() {
		t.Fatal("expected require_approval not to enable headless-only mode")
	}
}

// ── Policy evaluation with action: ask ───────────────────────────────────────

func TestEvaluate_ActionAsk_MatchedRule(t *testing.T) {
	e := setupEngine(t, `
version: "1"
default_action: deny
policies:
  - name: ask-sudo
    match:
      agent: "claude-code"
      tool: ["exec"]
    rules:
      - action: ask
        when:
          command_matches: ["sudo *"]
        message: "sudo command — approve or deny?"
`)
	call := ToolCall{
		ID:    "test-ask-001",
		Agent: "claude-code",
		Tool:  "exec",
		Params: map[string]any{
			"command": "sudo apt install git",
		},
	}
	d := e.Evaluate(call)
	if d.Action != ActionAsk {
		t.Errorf("expected ActionAsk, got %s", d.Action)
	}
	if !strings.Contains(d.Message, "approve or deny") {
		t.Errorf("expected message to contain 'approve or deny', got: %q", d.Message)
	}
	if d.HeadlessOnly {
		t.Errorf("expected HeadlessOnly=false by default, got true")
	}
}

func TestEvaluate_ActionAsk_HeadlessOnly(t *testing.T) {
	e := setupEngine(t, `
version: "1"
default_action: deny
policies:
  - name: ask-sudo-headless
    match:
      agent: "claude-code"
      tool: ["exec"]
    rules:
      - action: ask
        ask:
          headless_only: true
        when:
          command_matches: ["sudo *"]
        message: "sudo command — approve or deny?"
`)
	call := ToolCall{
		ID:    "test-ask-headless-001",
		Agent: "claude-code",
		Tool:  "exec",
		Params: map[string]any{
			"command": "sudo apt install git",
		},
	}
	d := e.Evaluate(call)
	if d.Action != ActionAsk {
		t.Errorf("expected ActionAsk, got %s", d.Action)
	}
	if !d.HeadlessOnly {
		t.Errorf("expected HeadlessOnly=true, got false")
	}
}

func TestEvaluate_ActionAsk_NoMatch_DefaultDeny(t *testing.T) {
	e := setupEngine(t, `
version: "1"
default_action: deny
policies:
  - name: ask-sudo
    match:
      agent: "claude-code"
      tool: ["exec"]
    rules:
      - action: ask
        when:
          command_matches: ["sudo *"]
        message: "sudo requires approval"
`)
	// Non-matching command falls through to default_action: deny.
	call := ToolCall{
		ID:    "test-ask-002",
		Agent: "claude-code",
		Tool:  "exec",
		Params: map[string]any{
			"command": "ls -la",
		},
	}
	d := e.Evaluate(call)
	if d.Action != ActionDeny {
		t.Errorf("expected ActionDeny for unmatched command, got %s", d.Action)
	}
}

func TestEvaluate_ActionAsk_NonClaudeCodeAgent(t *testing.T) {
	// action: ask is declared without agent scoping; non-claude-code agents
	// should still receive the engine decision (ActionAsk). Enforcement of the
	// fallback-to-deny behavior is the hook layer's responsibility, but the
	// engine correctly returns ActionAsk so the hook can act on it.
	e := setupEngine(t, `
version: "1"
default_action: deny
policies:
  - name: ask-all-agents
    match:
      tool: ["exec"]
    rules:
      - action: ask
        when:
          command_matches: ["sudo *"]
        message: "sudo requires approval"
`)
	call := ToolCall{
		ID:    "test-ask-003",
		Agent: "cline",
		Tool:  "exec",
		Params: map[string]any{
			"command": "sudo rm -rf /tmp/test",
		},
	}
	d := e.Evaluate(call)
	if d.Action != ActionAsk {
		t.Errorf("expected ActionAsk from engine (hook enforces deny for non-cc agents), got %s", d.Action)
	}
}

func TestEvaluate_ActionAsk_WithAllowFallthrough(t *testing.T) {
	// Ensure action: ask coexists correctly with allow rules for the same
	// policy scope — the first matching rule wins.
	e := setupEngine(t, `
version: "1"
default_action: deny
policies:
  - name: mixed-policy
    match:
      agent: "claude-code"
      tool: ["exec"]
    rules:
      - action: allow
        when:
          command_matches: ["git *"]
        message: "git allowed"
      - action: ask
        when:
          command_matches: ["sudo *"]
        message: "sudo needs approval"
      - action: deny
        when:
          default: true
        message: "default deny"
`)
	gitCall := ToolCall{Agent: "claude-code", Tool: "exec", Params: map[string]any{"command": "git status"}}
	if d := e.Evaluate(gitCall); d.Action != ActionAllow {
		t.Errorf("git command: expected ActionAllow, got %s", d.Action)
	}

	sudoCall := ToolCall{Agent: "claude-code", Tool: "exec", Params: map[string]any{"command": "sudo systemctl restart nginx"}}
	if d := e.Evaluate(sudoCall); d.Action != ActionAsk {
		t.Errorf("sudo command: expected ActionAsk, got %s", d.Action)
	}

	otherCall := ToolCall{Agent: "claude-code", Tool: "exec", Params: map[string]any{"command": "rm -rf /tmp/x"}}
	if d := e.Evaluate(otherCall); d.Action != ActionDeny {
		t.Errorf("other command: expected ActionDeny, got %s", d.Action)
	}
}
