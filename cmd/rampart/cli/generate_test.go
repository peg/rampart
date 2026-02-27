package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peg/rampart/internal/engine"
	"gopkg.in/yaml.v3"
)

func TestIntentTemplateCount(t *testing.T) {
	if len(intentTemplates) < 40 {
		t.Fatalf("expected at least 40 intent templates, got %d", len(intentTemplates))
	}
}

func TestBuildPolicyFromIntent_Examples(t *testing.T) {
	tests := []struct {
		name       string
		intent     string
		action     string
		tools      []string
		assertWhen func(t *testing.T, when engine.Condition)
	}{
		{
			name:   "block curl and wget",
			intent: "block all curl and wget",
			action: "deny",
			tools:  []string{"exec"},
			assertWhen: func(t *testing.T, when engine.Condition) {
				containsValue(t, when.CommandMatches, "curl *")
				containsValue(t, when.CommandMatches, "wget *")
			},
		},
		{
			name:   "require approval npm installs",
			intent: "require approval for npm installs",
			action: "require_approval",
			tools:  []string{"exec"},
			assertWhen: func(t *testing.T, when engine.Condition) {
				containsValue(t, when.CommandMatches, "npm install *")
			},
		},
		{
			name:   "watch writes to etc",
			intent: "watch all file writes to /etc",
			action: "watch",
			tools:  []string{"write", "edit"},
			assertWhen: func(t *testing.T, when engine.Condition) {
				containsValue(t, when.PathMatches, "/etc/**")
			},
		},
		{
			name:   "block env and credential reads",
			intent: "block reading .env and credential files",
			action: "deny",
			tools:  []string{"read"},
			assertWhen: func(t *testing.T, when engine.Condition) {
				containsValue(t, when.PathMatches, "**/.env")
				containsValue(t, when.PathMatches, "**/.aws/credentials")
			},
		},
		{
			name:   "deny python c",
			intent: "deny all python -c exec calls",
			action: "deny",
			tools:  []string{"exec"},
			assertWhen: func(t *testing.T, when engine.Condition) {
				containsValue(t, when.CommandMatches, "python -c *")
			},
		},
		{
			name:   "block rm rf",
			intent: "block rm -rf",
			action: "deny",
			tools:  []string{"exec"},
			assertWhen: func(t *testing.T, when engine.Condition) {
				containsValue(t, when.CommandMatches, "rm -rf *")
			},
		},
		{
			name:   "require approval sudo",
			intent: "require approval for sudo",
			action: "require_approval",
			tools:  []string{"exec"},
			assertWhen: func(t *testing.T, when engine.Condition) {
				containsValue(t, when.CommandMatches, "sudo **")
			},
		},
		{
			name:   "block pastebin exfiltration",
			intent: "block exfiltration to pastebin",
			action: "deny",
			tools:  []string{"fetch"},
			assertWhen: func(t *testing.T, when engine.Condition) {
				containsValue(t, when.DomainMatches, "pastebin.com")
			},
		},
		{
			name:   "allow git commands",
			intent: "allow git commands",
			action: "allow",
			tools:  []string{"exec"},
			assertWhen: func(t *testing.T, when engine.Condition) {
				containsValue(t, when.CommandMatches, "git *")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildPolicyFromIntent(intentSpec{Intent: tt.intent, Strictness: "balanced"})
			if err != nil {
				t.Fatalf("buildPolicyFromIntent() error = %v", err)
			}
			if len(result.Policy.Rules) != 1 {
				t.Fatalf("expected 1 rule, got %d", len(result.Policy.Rules))
			}
			rule := result.Policy.Rules[0]
			if rule.Action != tt.action {
				t.Fatalf("action = %q, want %q", rule.Action, tt.action)
			}
			if !sameStringSet([]string(result.Policy.Match.Tool), tt.tools) {
				t.Fatalf("tools = %v, want %v", []string(result.Policy.Match.Tool), tt.tools)
			}
			tt.assertWhen(t, rule.When)
		})
	}
}

func TestPolicyGenerateCommand_OutputAndAppend(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "generated.yaml")

	_, _, err := runCLI(t, "policy", "generate", "block rm -rf", "--output", outFile)
	if err != nil {
		t.Fatalf("generate output error: %v", err)
	}

	first, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !strings.Contains(string(first), "generated-rm-rf") {
		t.Fatalf("missing generated policy in file: %s", string(first))
	}

	_, _, err = runCLI(t, "policy", "generate", "allow git commands", "--output", outFile, "--append")
	if err != nil {
		t.Fatalf("generate append error: %v", err)
	}

	second, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read output after append: %v", err)
	}

	var cfg engine.Config
	if err := yaml.Unmarshal(second, &cfg); err != nil {
		t.Fatalf("parse yaml: %v", err)
	}
	if len(cfg.Policies) != 2 {
		t.Fatalf("expected 2 policies after append, got %d", len(cfg.Policies))
	}
}

func TestBuildFallbackIntent_KeywordExtraction(t *testing.T) {
	tests := []struct {
		name      string
		intent    string
		want      []string
		wantErr   string
		wantName  string
		contains  []string
		maxTokens int
	}{
		{
			name:      "block all outbound curl requests",
			intent:    "block all outbound curl requests",
			contains:  []string{"curl", "outbound", "requests"},
			wantName:  "generated-curl",
			maxTokens: 3,
		},
		{
			name:     "deny wget downloads",
			intent:   "deny wget downloads",
			want:     []string{"wget", "downloads"},
			wantName: "generated-wget",
		},
		{
			name:    "only stop words",
			intent:  "the and for",
			wantErr: "no meaningful keywords",
		},
		{
			name:     "short meaningful single token",
			intent:   "rm",
			want:     []string{"rm"},
			wantName: "generated-rm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildFallbackIntent(intentSpec{Intent: tt.intent, Strictness: "balanced"}, "deny")
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("buildFallbackIntent() error = %v", err)
			}

			rule := got.Policy.Rules[0]
			if len(tt.want) > 0 && !sameStringSet(rule.When.CommandContains, tt.want) {
				t.Fatalf("command_contains = %v, want %v", rule.When.CommandContains, tt.want)
			}
			for _, kw := range tt.contains {
				containsValue(t, rule.When.CommandContains, kw)
			}
			if tt.maxTokens > 0 && len(rule.When.CommandContains) > tt.maxTokens {
				t.Fatalf("command_contains too long = %v", rule.When.CommandContains)
			}
			if tt.wantName != "" && got.Policy.Name != tt.wantName {
				t.Fatalf("policy name = %q, want %q", got.Policy.Name, tt.wantName)
			}
		})
	}
}

func containsValue(t *testing.T, items []string, want string) {
	t.Helper()
	for _, item := range items {
		if item == want {
			return
		}
	}
	t.Fatalf("%q not found in %v", want, items)
}
