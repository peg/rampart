package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConvert_BasicSettings(t *testing.T) {
	settings := `{
		"permissions": {
			"allow": ["Bash(npm run *)"],
			"deny": ["Bash(rm -rf *)"],
			"ask": ["Bash(git push *)"]
		}
	}`
	tmp := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(tmp, []byte(settings), 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := runConvert(&buf, tmp, ""); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	// Deny rules come first
	denyIdx := strings.Index(out, "action: deny")
	approvalIdx := strings.Index(out, "action: require_approval")
	allowIdx := strings.Index(out, "action: allow")
	if denyIdx < 0 || approvalIdx < 0 || allowIdx < 0 {
		t.Fatalf("missing expected actions in output:\n%s", out)
	}
	if denyIdx > approvalIdx || approvalIdx > allowIdx {
		t.Error("rules should be ordered: deny, require_approval, allow")
	}

	if !strings.Contains(out, `"rm -rf *"`) {
		t.Error("missing rm -rf pattern")
	}
	if !strings.Contains(out, `"git push *"`) {
		t.Error("missing git push pattern")
	}
	if !strings.Contains(out, `"npm run *"`) {
		t.Error("missing npm run pattern")
	}
}

func TestConvert_NoPermissions(t *testing.T) {
	settings := `{"permissions": {}}`
	tmp := filepath.Join(t.TempDir(), "settings.json")
	os.WriteFile(tmp, []byte(settings), 0o644)

	var buf bytes.Buffer
	err := runConvert(&buf, tmp, "")
	if err == nil || !strings.Contains(err.Error(), "no permission rules") {
		t.Errorf("expected 'no permission rules' error, got: %v", err)
	}
}

func TestConvert_OutputFile(t *testing.T) {
	settings := `{"permissions": {"deny": ["Bash(rm -rf /)"]}}`
	tmp := filepath.Join(t.TempDir(), "settings.json")
	os.WriteFile(tmp, []byte(settings), 0o644)

	outFile := filepath.Join(t.TempDir(), "output.yaml")
	var buf bytes.Buffer
	if err := runConvert(&buf, tmp, outFile); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "rm -rf /") {
		t.Error("output file missing rule content")
	}
	if !strings.Contains(buf.String(), "Wrote 1 rules") {
		t.Errorf("expected summary message, got: %s", buf.String())
	}
}

func TestParseClaudeRule(t *testing.T) {
	tests := []struct {
		input    string
		wantTool string
		wantSpec string
	}{
		{"Bash", "Bash", ""},
		{"Bash(npm run *)", "Bash", "npm run *"},
		{"Read(./.env)", "Read", "./.env"},
		{"WebFetch(domain:example.com)", "WebFetch", "domain:example.com"},
		{"Edit", "Edit", ""},
		{"Bash(*)", "Bash", "*"},
	}
	for _, tt := range tests {
		tool, spec := parseClaudeRule(tt.input)
		if tool != tt.wantTool || spec != tt.wantSpec {
			t.Errorf("parseClaudeRule(%q) = (%q, %q), want (%q, %q)",
				tt.input, tool, spec, tt.wantTool, tt.wantSpec)
		}
	}
}

func TestConvertSlugify(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"bash-deny-rm -rf *", "bash-deny-rm-rf"},
		{"read-allow-.env", "read-allow-env"},
		{"fetch-deny-evil.com", "fetch-deny-evil-com"},
	}
	for _, tt := range tests {
		got := convertSlugify(tt.input)
		if got != tt.want {
			t.Errorf("convertSlugify(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
