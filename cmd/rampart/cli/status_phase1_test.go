package cli

import "testing"

func TestIsHookBasedOnly(t *testing.T) {
	tests := []struct {
		name      string
		protected []string
		want      bool
	}{
		{name: "claude only", protected: []string{"Claude Code (hooks)"}, want: true},
		{name: "cline only", protected: []string{"Cline (hooks)"}, want: true},
		{name: "codex only", protected: []string{"Codex (hooks)"}, want: true},
		{name: "gemini only", protected: []string{"Gemini CLI (hooks)"}, want: true},
		{name: "copilot only", protected: []string{"GitHub Copilot CLI / VS Code (hooks)"}, want: true},
		{name: "claude and cline", protected: []string{"Claude Code (hooks)", "Cline (hooks)"}, want: true},
		{name: "openclaw plugin is not hook-only", protected: []string{"OpenClaw (plugin)"}, want: false},
		{name: "codex legacy wrapper is not hook-only", protected: []string{"Codex (legacy wrapper)"}, want: false},
		{name: "mixed claude and openclaw", protected: []string{"Claude Code (hooks)", "OpenClaw (plugin)"}, want: false},
		{name: "empty", protected: nil, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isHookBasedOnly(tt.protected)
			if got != tt.want {
				t.Fatalf("isHookBasedOnly(%v) = %v, want %v", tt.protected, got, tt.want)
			}
		})
	}
}
