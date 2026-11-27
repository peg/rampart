// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package engine

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const webhookRemovedMsg = `action "webhook" was removed after v1.11.1; use "ask" or "deny" instead`

func TestWebhookActionFailsToLoad(t *testing.T) {
	tests := map[string]string{
		"action with webhook block": `
      - action: webhook
        when: {command_matches: ["rm -rf *"]}
        webhook:
          url: "https://verify.example.invalid/check"
          timeout: 3s
          fail_open: true
`,
		"action without webhook block": `
      - action: webhook
        when: {default: true}
`,
		"webhook block on another action": `
      - action: allow
        when: {default: true}
        webhook: {url: "https://verify.example.invalid/check"}
`,
	}
	for name, rule := range tests {
		t.Run(name, func(t *testing.T) {
			policy := "version: \"1\"\ndefault_action: allow\npolicies:\n  - name: legacy\n    match: {tool: exec}\n    rules:" + rule
			_, err := New(NewMemoryStore([]byte(policy), "test"), nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), webhookRemovedMsg)
		})
	}
}

func TestWebhookActionParseErrors(t *testing.T) {
	_, err := ParseAction("webhook")
	require.Error(t, err)
	assert.Equal(t, webhookRemovedMsg, err.Error())

	_, err = Rule{Action: "webhook"}.ParseAction()
	require.Error(t, err)
	assert.Equal(t, webhookRemovedMsg, err.Error())
}

func TestLint_WebhookActionRemoved(t *testing.T) {
	path := writeTempPolicy(t, `
version: "1"
default_action: deny
policies:
  - name: test
    match:
      tool: exec
    rules:
      - action: webhook
        when:
          command_matches: ["rm *"]
`)
	result := LintPolicyFile(path)
	found := false
	for _, f := range result.Findings {
		if f.Severity == LintError && strings.Contains(f.Message, webhookRemovedMsg) {
			found = true
		}
	}
	assert.True(t, found, "expected removal error, findings: %v", result.Findings)
}

func TestEvaluate_ActionPrecedence(t *testing.T) {
	// Every rule matches; the most restrictive action must win regardless of
	// policy priority order: deny > ask > watch > allow.
	rules := []struct{ name, action string }{
		{"p-allow", "allow"},
		{"p-watch", "watch"},
		{"p-ask", "ask"},
		{"p-deny", "deny"},
	}
	for drop := len(rules); drop >= 1; drop-- {
		want := rules[drop-1].action
		t.Run(want, func(t *testing.T) {
			var b strings.Builder
			b.WriteString("version: \"1\"\ndefault_action: allow\npolicies:\n")
			for i, r := range rules[:drop] {
				// Give the least restrictive actions the highest priority.
				b.WriteString("  - name: " + r.name + "\n")
				b.WriteString("    priority: " + string(rune('1'+i)) + "\n")
				b.WriteString("    match: {tool: exec}\n    rules:\n")
				b.WriteString("      - action: " + r.action + "\n        when: {default: true}\n")
			}
			got := setupEngine(t, b.String()).Evaluate(execCall("main", "rm -rf /tmp/x"))
			assert.Equal(t, want, got.Action.String())
		})
	}
}
