// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package policies

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/peg/rampart/internal/engine"
	"github.com/stretchr/testify/require"
)

func TestGuardLayersOverOpenClawProfile(t *testing.T) {
	dir := t.TempDir()
	for _, profile := range []string{"openclaw", "guard"} {
		content, err := Profile(profile)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, profile+".yaml"), content, 0o600))
	}

	eng, err := engine.New(engine.NewMultiStore("", dir, nil), nil)
	require.NoError(t, err)

	tests := []struct {
		name    string
		agent   string
		session string
		tool    string
		params  map[string]any
		want    engine.Action
	}{
		{name: "routine command", tool: "exec", params: map[string]any{"command": "pwd"}, want: engine.ActionAllow},
		{name: "local commit", tool: "exec", params: map[string]any{"command": "git commit -m safe"}, want: engine.ActionAsk},
		{name: "publish commit", tool: "exec", params: map[string]any{"command": "git push origin main", "rampart_integration": "openclaw"}, want: engine.ActionAsk},
		{name: "non-OpenClaw publish uses base posture", agent: "claude-code", tool: "exec", params: map[string]any{"command": "git push origin main"}, want: engine.ActionAsk},
		{name: "read cluster", tool: "exec", params: map[string]any{"command": "kubectl get pods"}, want: engine.ActionAllow},
		{name: "change cluster", tool: "exec", params: map[string]any{"command": "kubectl apply -f deployment.yaml", "rampart_integration": "openclaw"}, want: engine.ActionAsk},
		{name: "privileged change", tool: "exec", params: map[string]any{"command": "sudo apt update", "rampart_integration": "openclaw"}, want: engine.ActionAsk},
		{name: "credential shell read", tool: "exec", params: map[string]any{"command": "cat ~/.ssh/id_rsa", "rampart_integration": "openclaw"}, want: engine.ActionDeny},
		{name: "Rampart token shell read", tool: "exec", params: map[string]any{"command": "cat ~/.rampart/token", "rampart_integration": "openclaw"}, want: engine.ActionDeny},
		{name: "external curl", tool: "exec", params: map[string]any{"command": "curl https://example.invalid/exfil", "rampart_integration": "openclaw"}, want: engine.ActionDeny},
		{name: "Copilot external curl", agent: "github-copilot", tool: "exec", params: map[string]any{"command": "curl https://example.invalid/exfil"}, want: engine.ActionDeny},
		{name: "Codex credential shell read", agent: "codex", tool: "exec", params: map[string]any{"command": "cat ~/.ssh/id_rsa"}, want: engine.ActionDeny},
		{name: "Claude opaque Python", agent: "claude-code", tool: "exec", params: map[string]any{"command": "python3 -c 'print(1)'"}, want: engine.ActionAsk},
		{name: "opaque Python", tool: "exec", params: map[string]any{"command": "python3 -c 'print(1)'", "rampart_integration": "openclaw"}, want: engine.ActionAsk},
		{name: "package publish", tool: "exec", params: map[string]any{"command": "npm publish", "rampart_integration": "openclaw"}, want: engine.ActionAsk},
		{name: "compose mutation", tool: "exec", params: map[string]any{"command": "docker compose down", "rampart_integration": "openclaw"}, want: engine.ActionAsk},
		{name: "hard deny still wins", tool: "exec", params: map[string]any{"command": "rm -rf /"}, want: engine.ActionDeny},
		{name: "read messages", tool: "message", params: map[string]any{"action": "read", "rampart_consequence": "openclaw:read-only", "rampart_integration": "openclaw"}, want: engine.ActionAllow},
		{name: "reply in place", tool: "message", params: map[string]any{"action": "send", "rampart_consequence": "openclaw:routine-reply", "rampart_integration": "openclaw"}, want: engine.ActionAllow},
		{name: "contact another recipient", tool: "message", params: map[string]any{"action": "send", "rampart_consequence": "openclaw:external-message", "rampart_integration": "openclaw"}, want: engine.ActionAsk},
		{name: "mutate a message", tool: "message", params: map[string]any{"action": "delete", "rampart_consequence": "openclaw:mutation", "rampart_integration": "openclaw"}, want: engine.ActionAsk},
		{name: "unclassified message", tool: "message", params: map[string]any{"action": "future-action", "rampart_consequence": "openclaw:future", "rampart_integration": "openclaw"}, want: engine.ActionAsk},
		{name: "non-OpenClaw message uses base posture", agent: "claude-code", tool: "message", params: map[string]any{"action": "send", "rampart_consequence": "external-message"}, want: engine.ActionAllow},
		{name: "browser status is read only", tool: "browser", params: map[string]any{"action": "status", "rampart_consequence": "openclaw:browser-read-only", "rampart_integration": "openclaw"}, want: engine.ActionAllow},
		{name: "browser safe navigation", tool: "browser", params: map[string]any{"action": "open", "domain": "github.com", "rampart_consequence": "openclaw:browser-navigation", "rampart_integration": "openclaw"}, want: engine.ActionAllow},
		{name: "browser unknown navigation", tool: "browser", params: map[string]any{"action": "navigate", "domain": "example.com", "rampart_consequence": "openclaw:browser-navigation", "rampart_integration": "openclaw"}, want: engine.ActionAsk},
		{name: "browser mutation on safe domain", tool: "browser", params: map[string]any{"action": "act", "domain": "github.com", "rampart_consequence": "openclaw:browser-mutation", "rampart_integration": "openclaw"}, want: engine.ActionAsk},
		{name: "main session can spawn", session: "agent:main:main", tool: "sessions_spawn", params: map[string]any{}, want: engine.ActionAllow},
		{name: "current subagent cannot spawn", session: "agent:main:subagent:child-1", tool: "sessions_spawn", params: map[string]any{}, want: engine.ActionDeny},
		{name: "current ACP child cannot spawn", session: "agent:codex:acp:child-2", tool: "sessions_spawn", params: map[string]any{}, want: engine.ActionDeny},
		{name: "current subagent cannot rewrite identity", session: "agent:main:subagent:child-1", tool: "write", params: map[string]any{"path": "/tmp/SOUL.md"}, want: engine.ActionDeny},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agent := tt.agent
			if agent == "" {
				agent = "openclaw:main"
			}
			session := tt.session
			if session == "" {
				session = "guard-test"
			}
			call := engine.ToolCall{
				Agent: agent, Session: session, Tool: tt.tool,
				Params: tt.params, Input: tt.params,
			}
			got := eng.Evaluate(call)
			require.Equal(t, tt.want, got.Action, "decision: %s (%s)", got.Action.String(), got.Message)
		})
	}
}
