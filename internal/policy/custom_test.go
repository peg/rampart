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
	"time"

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

func TestDetectTool(t *testing.T) {
	tests := []struct {
		pattern string
		want    string
	}{
		{"npm install *", "exec"},
		{"git commit -m *", "exec"},
		{"/etc/**", "path"},
		{"~/Documents/**", "path"},
		{"**/node_modules/**", "path"},
		{"./config.yaml", "path"},
		{"rm -rf /", "exec"},
		{"curl https://example.com", "exec"},
	}
	for _, tt := range tests {
		got := policy.DetectTool(tt.pattern)
		if got != tt.want {
			t.Errorf("DetectTool(%q) = %q, want %q", tt.pattern, got, tt.want)
		}
	}
}

func TestFlattenRules(t *testing.T) {
	p := &policy.CustomPolicy{Version: "1"}
	_ = p.AddRule("allow", "npm install *", "allow npm", "")
	_ = p.AddRule("deny", "rm -rf /", "block rm", "exec")
	_ = p.AddRule("allow", "/etc/passwd", "allow etc", "")

	flat := p.FlattenRules()
	if len(flat) != 3 {
		t.Fatalf("expected 3 flat rules, got %d", len(flat))
	}

	// Check first rule (npm install)
	if flat[0].Action != "allow" || flat[0].Pattern != "npm install *" {
		t.Errorf("rule 0: got %+v", flat[0])
	}

	// Check second rule (rm -rf)
	if flat[1].Action != "deny" || flat[1].Pattern != "rm -rf /" || flat[1].Tool != "exec" {
		t.Errorf("rule 1: got %+v", flat[1])
	}

	// Check third rule (etc)
	if flat[2].Action != "allow" || flat[2].Pattern != "/etc/passwd" {
		t.Errorf("rule 2: got %+v", flat[2])
	}

	// All should have entry/rule indices
	for i, rule := range flat {
		if rule.EntryIdx < 0 || rule.RuleIdx < 0 {
			t.Errorf("rule %d missing indices: %+v", i, rule)
		}
	}
}

func TestHasPattern(t *testing.T) {
	p := &policy.CustomPolicy{Version: "1"}
	_ = p.AddRule("allow", "npm install *", "", "")
	_ = p.AddRule("deny", "rm -rf /", "", "")

	// Test existing pattern
	exists, action, tool := p.HasPattern("npm install *")
	if !exists {
		t.Error("HasPattern should find npm install *")
	}
	if action != "allow" {
		t.Errorf("action = %q, want allow", action)
	}

	// Test another existing pattern
	exists, action, tool = p.HasPattern("rm -rf /")
	if !exists {
		t.Error("HasPattern should find rm -rf /")
	}
	if action != "deny" {
		t.Errorf("action = %q, want deny", action)
	}

	// Test non-existent pattern
	exists, action, tool = p.HasPattern("nonexistent pattern")
	if exists {
		t.Error("HasPattern should not find nonexistent pattern")
	}
	if action != "" || tool != "" {
		t.Errorf("empty result should have empty action and tool, got %q, %q", action, tool)
	}
}

func TestRemoveRuleAt(t *testing.T) {
	p := &policy.CustomPolicy{Version: "1"}
	_ = p.AddRule("allow", "npm install *", "", "")
	_ = p.AddRule("allow", "yarn install", "", "")
	_ = p.AddRule("deny", "rm -rf /", "", "")

	if p.TotalRules() != 3 {
		t.Fatalf("expected 3 rules initially, got %d", p.TotalRules())
	}

	// Remove middle rule (flat index 1)
	if err := policy.RemoveRuleAt(p, 1); err != nil {
		t.Fatalf("RemoveRuleAt(1): %v", err)
	}

	if p.TotalRules() != 2 {
		t.Errorf("after removal, expected 2 rules, got %d", p.TotalRules())
	}

	flat := p.FlattenRules()
	if len(flat) != 2 {
		t.Errorf("after removal, expected 2 flat rules, got %d", len(flat))
	}

	// Verify the right rules remain
	patterns := []string{}
	for _, r := range flat {
		patterns = append(patterns, r.Pattern)
	}
	if patterns[0] != "npm install *" || patterns[1] != "rm -rf /" {
		t.Errorf("wrong rules after removal: %v", patterns)
	}
}

func TestRemoveRuleAt_Last(t *testing.T) {
	p := &policy.CustomPolicy{Version: "1"}
	_ = p.AddRule("allow", "npm install *", "", "")

	if err := policy.RemoveRuleAt(p, 0); err != nil {
		t.Fatalf("RemoveRuleAt(0): %v", err)
	}

	if p.TotalRules() != 0 {
		t.Errorf("after removing last rule, expected 0 rules, got %d", p.TotalRules())
	}
	if len(p.Policies) != 0 {
		t.Errorf("entry should be removed when empty, got %d entries", len(p.Policies))
	}
}

func TestRemoveRuleAt_InvalidIndex(t *testing.T) {
	p := &policy.CustomPolicy{Version: "1"}
	_ = p.AddRule("allow", "npm install *", "", "")

	// Test negative index
	err := policy.RemoveRuleAt(p, -1)
	if err == nil {
		t.Error("expected error for negative index")
	}

	// Test out of range
	err = policy.RemoveRuleAt(p, 10)
	if err == nil {
		t.Error("expected error for out of range index")
	}
	if !strings.Contains(err.Error(), "out of range") {
		t.Errorf("error should mention 'out of range', got: %v", err)
	}
}

func TestAddRuleTemporal_Expiration(t *testing.T) {
	p := &policy.CustomPolicy{Version: "1"}

	// Create an expiration time 1 hour from now
	expTime := time.Now().Add(1 * time.Hour)
	opts := policy.TemporalOpts{
		ExpiresAt: &expTime,
		Once:      false,
	}
	if err := p.AddRuleTemporal("allow", "npm install *", "temp npm", "", opts); err != nil {
		t.Fatalf("AddRuleTemporal: %v", err)
	}

	if p.TotalRules() != 1 {
		t.Fatalf("expected 1 rule, got %d", p.TotalRules())
	}

	flat := p.FlattenRules()
	if flat[0].Pattern != "npm install *" {
		t.Errorf("pattern mismatch: got %q", flat[0].Pattern)
	}

	// Check the raw rule for temporal fields
	rule := p.Policies[0].Rules[0]
	if rule.ExpiresAt == nil {
		t.Error("ExpiresAt should be set")
	}
	if rule.Once {
		t.Error("Once should be false")
	}
}

func TestAddRuleTemporal_Once(t *testing.T) {
	p := &policy.CustomPolicy{Version: "1"}

	opts := policy.TemporalOpts{
		ExpiresAt: nil,
		Once:      true,
	}
	if err := p.AddRuleTemporal("deny", "curl *", "one-time block", "", opts); err != nil {
		t.Fatalf("AddRuleTemporal: %v", err)
	}

	rule := p.Policies[0].Rules[0]
	if !rule.Once {
		t.Error("Once should be true")
	}
	if rule.ExpiresAt != nil {
		t.Error("ExpiresAt should be nil")
	}
}
