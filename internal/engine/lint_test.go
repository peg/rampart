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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempPolicy(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLint_ValidPolicy(t *testing.T) {
	path := writeTempPolicy(t, `
version: "1"
default_action: deny
policies:
  - name: safe-reads
    match:
      tool: read
    rules:
      - action: allow
        when:
          path_matches: ["/tmp/*"]
        message: allow tmp reads
`)
	result := LintPolicyFile(path)
	if result.HasErrors() {
		t.Errorf("expected no errors, got: %v", result.Findings)
	}
}

func TestLint_InvalidYAML(t *testing.T) {
	path := writeTempPolicy(t, `
version: "1"
policies:
  - name: broken
    rules:
      - action: deny
        when:
          [invalid yaml
`)
	result := LintPolicyFile(path)
	if !result.HasErrors() {
		t.Error("expected error for invalid YAML")
	}
	if !strings.Contains(result.Findings[0].Message, "invalid YAML") {
		t.Errorf("expected invalid YAML message, got: %s", result.Findings[0].Message)
	}
}

func TestLint_UnknownAction(t *testing.T) {
	path := writeTempPolicy(t, `
version: "1"
default_action: deny
policies:
  - name: test
    match:
      tool: exec
    rules:
      - action: blok
        when:
          command_matches: ["rm *"]
        message: blocked
`)
	result := LintPolicyFile(path)
	if result.Errors != 1 {
		t.Errorf("expected 1 error, got %d: %v", result.Errors, result.Findings)
	}
	found := false
	for _, f := range result.Findings {
		if f.Severity == LintError && strings.Contains(f.Message, `"blok"`) && strings.Contains(f.Message, `"deny"`) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected suggestion for blok->deny, findings: %v", result.Findings)
	}
}

func TestLint_UnknownConditionField(t *testing.T) {
	path := writeTempPolicy(t, `
version: "1"
default_action: deny
policies:
  - name: test
    match:
      tool: exec
    rules:
      - action: deny
        when:
          command_match: ["rm *"]
        message: blocked
`)
	result := LintPolicyFile(path)
	found := false
	for _, f := range result.Findings {
		if f.Severity == LintError && strings.Contains(f.Message, "command_match") && strings.Contains(f.Message, "command_matches") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected unknown condition field error, findings: %v", result.Findings)
	}
}

func TestLint_EmptyConditions(t *testing.T) {
	path := writeTempPolicy(t, `
version: "1"
default_action: deny
policies:
  - name: test
    match:
      tool: exec
    rules:
      - action: deny
        when: {}
        message: deny all
`)
	result := LintPolicyFile(path)
	found := false
	for _, f := range result.Findings {
		if f.Severity == LintInfo && strings.Contains(f.Message, "no conditions") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected empty conditions info finding, findings: %v", result.Findings)
	}
}

func TestLint_MatchInsteadOfWhen(t *testing.T) {
	path := writeTempPolicy(t, `
version: "1"
default_action: deny
policies:
  - name: test
    match:
      tool: exec
    rules:
      - action: deny
        match:
          command_matches: ["rm *"]
        message: blocked
`)
	result := LintPolicyFile(path)
	found := false
	for _, f := range result.Findings {
		if f.Severity == LintWarning && strings.Contains(f.Message, `"match"`) && strings.Contains(f.Message, `"when"`) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected match->when warning, findings: %v", result.Findings)
	}
}

func TestLint_ReasonInsteadOfMessage(t *testing.T) {
	path := writeTempPolicy(t, `
version: "1"
default_action: deny
policies:
  - name: test
    match:
      tool: exec
    rules:
      - action: deny
        when:
          command_matches: ["rm *"]
        reason: blocked
`)
	result := LintPolicyFile(path)
	found := false
	for _, f := range result.Findings {
		if f.Severity == LintWarning && strings.Contains(f.Message, `"reason"`) && strings.Contains(f.Message, `"message"`) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected reason->message warning, findings: %v", result.Findings)
	}
}

func TestLint_NoDefaultAction(t *testing.T) {
	path := writeTempPolicy(t, `
version: "1"
policies:
  - name: test
    match:
      tool: exec
    rules:
      - action: deny
        when:
          command_matches: ["rm *"]
        message: blocked
`)
	result := LintPolicyFile(path)
	found := false
	for _, f := range result.Findings {
		if f.Severity == LintInfo && strings.Contains(f.Message, "default_action") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected default_action info, findings: %v", result.Findings)
	}
}

func TestLint_DefaultActionAllowWarning(t *testing.T) {
	path := writeTempPolicy(t, `
version: "1"
default_action: allow
policies:
  - name: test
    match:
      tool: exec
    rules:
      - action: deny
        when:
          command_matches: ["rm *"]
        message: blocked
`)
	result := LintPolicyFile(path)
	found := false
	for _, f := range result.Findings {
		if f.Severity == LintWarning && strings.Contains(f.Message, `default_action is "allow"`) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected default_action allow warning, findings: %v", result.Findings)
	}
}

func TestLint_NoPolicies(t *testing.T) {
	path := writeTempPolicy(t, `
version: "1"
default_action: deny
policies: []
`)
	result := LintPolicyFile(path)
	found := false
	for _, f := range result.Findings {
		if f.Severity == LintWarning && strings.Contains(f.Message, "no rules") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected no rules warning, findings: %v", result.Findings)
	}
}

func TestLint_ShadowedRule(t *testing.T) {
	path := writeTempPolicy(t, `
version: "1"
default_action: allow
policies:
  - name: test
    match:
      tool: exec
    rules:
      - action: deny
        when:
          default: true
        message: deny all
      - action: allow
        when:
          command_matches: ["ls"]
        message: allow ls
`)
	result := LintPolicyFile(path)
	found := false
	for _, f := range result.Findings {
		if f.Severity == LintInfo && strings.Contains(f.Message, "shadowed") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected shadowed rule info, findings: %v", result.Findings)
	}
}

func TestLint_GlobDepth(t *testing.T) {
	path := writeTempPolicy(t, `
version: "1"
default_action: deny
policies:
  - name: test
    match:
      tool: exec
    rules:
      - action: deny
        when:
          command_matches: ["**/**/**/**/deep"]
        message: too deep
`)
	result := LintPolicyFile(path)
	found := false
	for _, f := range result.Findings {
		if f.Severity == LintWarning && strings.Contains(f.Message, "**") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected glob depth warning, findings: %v", result.Findings)
	}
}

func TestLint_NoRulesInPolicy(t *testing.T) {
	path := writeTempPolicy(t, `
version: "1"
default_action: deny
policies:
  - name: empty-policy
    match:
      tool: exec
    rules: []
`)
	result := LintPolicyFile(path)
	found := false
	for _, f := range result.Findings {
		if f.Severity == LintWarning && strings.Contains(f.Message, "no rules") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected no rules warning, findings: %v", result.Findings)
	}
}

func TestLint_FileNotFound(t *testing.T) {
	result := LintPolicyFile("/nonexistent/policy.yaml")
	if !result.HasErrors() {
		t.Error("expected error for missing file")
	}
}

func TestLint_Summary(t *testing.T) {
	r := LintResult{Errors: 2, Warnings: 1}
	s := r.Summary("test.yaml")
	if !strings.Contains(s, "2 error(s)") || !strings.Contains(s, "1 warning(s)") {
		t.Errorf("unexpected summary: %s", s)
	}
}

func TestLint_SummaryClean(t *testing.T) {
	r := LintResult{}
	s := r.Summary("test.yaml")
	if !strings.Contains(s, "no issues") {
		t.Errorf("unexpected summary: %s", s)
	}
}

func TestLint_CrossPolicyShadow(t *testing.T) {
	path := writeTempPolicy(t, `
version: "1"
default_action: allow
policies:
  - name: blocker
    priority: 1
    match:
      tool: exec
    rules:
      - action: deny
        when:
          default: true
        message: deny everything
  - name: permitter
    priority: 50
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["ls"]
        message: allow ls
`)
	result := LintPolicyFile(path)
	found := false
	for _, f := range result.Findings {
		if f.Severity == LintInfo && strings.Contains(f.Message, "permitter") && strings.Contains(f.Message, "blocker") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected cross-policy shadow info, findings: %v", result.Findings)
	}
}
