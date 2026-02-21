package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
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

func TestResolveExplainPolicyPath_ExplicitConfig(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "custom.yaml")
	if err := os.WriteFile(p, []byte("version: \"1\"\npolicies: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	root := NewRootCmd(nil, &strings.Builder{}, &strings.Builder{})
	root.SetArgs([]string{"policy", "explain", "echo hi", "--config", p})
	if err := root.Execute(); err != nil {
		t.Fatalf("expected explain to load explicit config, got: %v", err)
	}
}

func TestResolveExplainPolicyPath_AutoDiscoverStandard(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	policiesDir := filepath.Join(home, ".rampart", "policies")
	if err := os.MkdirAll(policiesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	std := filepath.Join(policiesDir, "standard.yaml")
	if err := os.WriteFile(std, []byte("version: \"1\"\ndefault_action: allow\npolicies: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := &cobra.Command{}
	got, err := resolveExplainPolicyPath(cmd, "rampart.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != std {
		t.Fatalf("expected %s, got %s", std, got)
	}
}

func TestResolveExplainPolicyPath_AutoDiscoverCWD(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	cwdPolicy := filepath.Join(dir, "rampart.yaml")
	if err := os.WriteFile(cwdPolicy, []byte("version: \"1\"\ndefault_action: allow\npolicies: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := &cobra.Command{}
	got, err := resolveExplainPolicyPath(cmd, "rampart.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "rampart.yaml" {
		t.Fatalf("expected rampart.yaml, got %s", got)
	}
}

func TestResolveExplainPolicyPath_NotFound(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	cmd := &cobra.Command{}
	_, err = resolveExplainPolicyPath(cmd, "rampart.yaml")
	if err == nil {
		t.Fatal("expected error when no config exists")
	}
	if !strings.Contains(err.Error(), "no config found") {
		t.Fatalf("unexpected error: %v", err)
	}
}
