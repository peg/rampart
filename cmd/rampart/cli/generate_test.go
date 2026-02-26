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

func TestBuildPolicyFromIntent_FallbackUsesKeywords(t *testing.T) {
	result, err := buildPolicyFromIntent(intentSpec{
		Intent:     "block kubernetes operations",
		Strictness: "balanced",
	})
	if err != nil {
		t.Fatalf("buildPolicyFromIntent() error = %v", err)
	}

	if len(result.Policy.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(result.Policy.Rules))
	}
	containsValue(t, result.Policy.Rules[0].When.CommandContains, "kubernetes")
	containsValue(t, result.Policy.Rules[0].When.CommandContains, "operations")
}

func TestBuildPolicyFromIntent_FallbackNoKeywordsReturnsError(t *testing.T) {
	_, err := buildPolicyFromIntent(intentSpec{
		Intent:     "block all and for from",
		Strictness: "balanced",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if got, want := err.Error(), "no matching templates or keywords found; try --interactive"; !strings.Contains(got, want) {
		t.Fatalf("error %q does not contain %q", got, want)
	}
}

func TestPolicyGenerateCommand_FallbackWarningOnStderr(t *testing.T) {
	stdout, stderr, err := runCLI(t, "policy", "generate", "block kubernetes operations")
	if err != nil {
		t.Fatalf("generate error: %v", err)
	}

	if got, want := stderr, "Warning: no matching template found for intent; using keyword-only policy — review before use"; !strings.Contains(got, want) {
		t.Fatalf("stderr %q does not contain %q", got, want)
	}
	if got, want := stdout, "command_contains"; !strings.Contains(got, want) {
		t.Fatalf("stdout missing command_contains: %s", got)
	}
	if got, want := stdout, "- kubernetes"; !strings.Contains(got, want) {
		t.Fatalf("stdout missing kubernetes keyword: %s", got)
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
