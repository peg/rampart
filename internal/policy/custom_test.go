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

package policy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peg/rampart/internal/policy"
	"gopkg.in/yaml.v3"
)

func TestLoadCustomPolicy_Missing(t *testing.T) {
	p, err := policy.LoadCustomPolicy("/does/not/exist.yaml")
	if err != nil {
		t.Fatalf("expected nil error for missing file, got %v", err)
	}
	if p.Version != "1" {
		t.Errorf("expected version=1, got %q", p.Version)
	}
}

func TestLoadCustomPolicy_Existing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.yaml")
	_ = os.WriteFile(path, []byte(`version: "1"
policies: []
`), 0o644)

	p, err := policy.LoadCustomPolicy(path)
	if err != nil {
		t.Fatalf("LoadCustomPolicy: %v", err)
	}
	if p.Version != "1" {
		t.Errorf("expected version=1, got %q", p.Version)
	}
}

func TestSaveCustomPolicy_ValidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.yaml")

	p := &policy.CustomPolicy{Version: "1"}
	_ = p.AddRule("allow", "npm install *", "msg", "")

	if err := policy.SaveCustomPolicy(path, p); err != nil {
		t.Fatalf("SaveCustomPolicy: %v", err)
	}

	data, _ := os.ReadFile(path)
	var out map[string]interface{}
	if err := yaml.Unmarshal(data, &out); err != nil {
		t.Fatalf("saved file is not valid YAML: %v\n%s", err, data)
	}
}

func TestAddRule_Allow_Command(t *testing.T) {
	p := &policy.CustomPolicy{Version: "1"}
	if err := p.AddRule("allow", "npm install *", "allow npm", ""); err != nil {
		t.Fatal(err)
	}

	if len(p.Policies) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(p.Policies))
	}
	e := p.Policies[0]
	if e.Name != "custom-allow-commands" {
		t.Errorf("entry name = %q, want custom-allow-commands", e.Name)
	}
	if len(e.Rules) != 1 || e.Rules[0].Action != "allow" {
		t.Errorf("unexpected rules: %+v", e.Rules)
	}
}

func TestAddRule_Deny_Path(t *testing.T) {
	p := &policy.CustomPolicy{Version: "1"}
	if err := p.AddRule("deny", "/etc/**", "block etc", ""); err != nil {
		t.Fatal(err)
	}

	e := p.Policies[0]
	if e.Name != "custom-deny-paths" {
		t.Errorf("entry name = %q, want custom-deny-paths", e.Name)
	}
	if len(e.Rules[0].When.PathMatches) != 1 {
		t.Errorf("expected path_matches, got %+v", e.Rules[0].When)
	}
}

func TestAddRule_AccumulatesInSameEntry(t *testing.T) {
	p := &policy.CustomPolicy{Version: "1"}
	_ = p.AddRule("allow", "npm install *", "", "")
	_ = p.AddRule("allow", "yarn install", "", "")

	if len(p.Policies) != 1 {
		t.Errorf("expected 1 entry, got %d (rules should be grouped)", len(p.Policies))
	}
	if p.TotalRules() != 2 {
		t.Errorf("expected 2 rules, got %d", p.TotalRules())
	}
}

func TestAddRule_EmptyPatternError(t *testing.T) {
	p := &policy.CustomPolicy{Version: "1"}
	err := p.AddRule("allow", "", "", "")
	if err == nil {
		t.Fatal("expected error for empty pattern")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected 'empty' in error, got %v", err)
	}
}

func TestTotalRules(t *testing.T) {
	p := &policy.CustomPolicy{Version: "1"}
	if p.TotalRules() != 0 {
		t.Errorf("empty policy should have 0 rules")
	}
	_ = p.AddRule("allow", "a *", "", "")
	_ = p.AddRule("deny", "b *", "", "")
	_ = p.AddRule("allow", "/tmp/**", "", "")
	if p.TotalRules() != 3 {
		t.Errorf("expected 3 rules, got %d", p.TotalRules())
	}
}

func TestIsPathPattern(t *testing.T) {
	cases := []struct {
		pattern string
		want    bool
	}{
		{"/etc/passwd", true},
		{"~/Documents/**", true},
		{"**/node_modules/**", true},
		{"relative/path", true},
		{"npm install", false},
		{"rm -rf *", false},
	}
	for _, c := range cases {
		got := policy.IsPathPattern(c.pattern)
		if got != c.want {
			t.Errorf("IsPathPattern(%q) = %v, want %v", c.pattern, got, c.want)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.yaml")

	orig := &policy.CustomPolicy{Version: "1"}
	_ = orig.AddRule("allow", "npm install *", "allow npm", "")
	_ = orig.AddRule("deny", "rm -rf /", "block rm", "")

	if err := policy.SaveCustomPolicy(path, orig); err != nil {
		t.Fatal(err)
	}

	loaded, err := policy.LoadCustomPolicy(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}

	if loaded.TotalRules() != orig.TotalRules() {
		t.Errorf("rule count mismatch: got %d, want %d", loaded.TotalRules(), orig.TotalRules())
	}
}

func TestIsPathPatternCommands(t *testing.T) {
	// These should be detected as commands (exec), not paths
	commands := []string{
		"go build ./...",
		"npm install lodash",
		"git commit -m 'test'",
		"docker run -v /tmp:/data alpine",
		"kubectl get pods -n default",
		"curl https://example.com",
		"make all",
	}
	for _, cmd := range commands {
		if policy.IsPathPattern(cmd) {
			t.Errorf("IsPathPattern(%q) = true, want false (should be exec)", cmd)
		}
	}

	// These should be detected as paths
	paths := []string{
		"/etc/passwd",
		"~/Documents/file.txt",
		"**/node_modules/**",
		"./config.yaml",
		"src/main.go",
	}
	for _, p := range paths {
		if !policy.IsPathPattern(p) {
			t.Errorf("IsPathPattern(%q) = false, want true (should be path)", p)
		}
	}
}
