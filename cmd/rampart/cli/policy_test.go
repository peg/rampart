package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultParams(t *testing.T) {
	if got := defaultParams(nil); got == nil {
		t.Error("nil input should return empty map")
	}
	m := map[string]any{"key": "val"}
	if got := defaultParams(m); got["key"] != "val" {
		t.Error("non-nil input should pass through")
	}
}

func TestNormalizeAgent(t *testing.T) {
	tests := []struct{ input, want string }{
		{"", "*"},
		{"  ", "*"},
		{"claude", "claude"},
	}
	for _, tt := range tests {
		if got := normalizeAgent(tt.input); got != tt.want {
			t.Errorf("normalizeAgent(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestRenderCommand(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]any
		want   string
	}{
		{"nil", nil, ""},
		{"command", map[string]any{"command": "ls"}, "ls"},
		{"path", map[string]any{"path": "/tmp"}, "/tmp"},
		{"url", map[string]any{"url": "https://x.com"}, "https://x.com"},
		{"empty", map[string]any{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := renderCommand(tt.params); got != tt.want {
				t.Errorf("renderCommand() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReadJSONFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "test.json")
	data := []policyTestCall{{Agent: "test", Tool: "exec", Params: map[string]any{"command": "ls"}}}
	raw, _ := json.Marshal(data)
	os.WriteFile(p, raw, 0o644)

	var got []policyTestCall
	if err := readJSONFile(p, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Tool != "exec" {
		t.Errorf("got %+v", got)
	}

	// Non-existent file
	if err := readJSONFile("/nonexistent", &got); err == nil {
		t.Error("expected error for missing file")
	}

	// Invalid JSON
	os.WriteFile(filepath.Join(dir, "bad.json"), []byte("{invalid"), 0o644)
	if err := readJSONFile(filepath.Join(dir, "bad.json"), &got); err == nil {
		t.Error("expected error for bad JSON")
	}
}

func TestPolicyExplainDeny(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "rampart.yaml")
	os.WriteFile(policyFile, []byte(`
version: "1"
default_action: allow
policies:
  - name: block-rm
    match:
      tool: ["exec"]
    rules:
      - action: deny
        message: blocked
        when:
          command_matches:
            - "rm -rf *"
`), 0o644)

	opts := &rootOptions{configPath: policyFile}
	cmd := newPolicyExplainCmd(opts)
	var out strings.Builder
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"rm -rf /"})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(out.String(), "DENY") {
		t.Errorf("expected DENY in output: %s", out.String())
	}
	if !strings.Contains(out.String(), "block-rm") {
		t.Errorf("expected policy name: %s", out.String())
	}
}

func TestPolicyCheck(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "rampart.yaml")
	os.WriteFile(policyFile, []byte(`version: "1"
default_action: allow
policies: []
`), 0o644)

	opts := &rootOptions{configPath: policyFile}
	cmd := newPolicyCheckCmd(opts)
	var out strings.Builder
	cmd.SetOut(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(out.String(), "valid") {
		t.Errorf("expected valid message: %s", out.String())
	}
}
