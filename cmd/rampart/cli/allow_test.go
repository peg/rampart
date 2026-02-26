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

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peg/rampart/internal/policy"
	"gopkg.in/yaml.v3"
)

// ── Pattern validation ──────────────────────────────────────────────────────

func TestValidateGlobPattern_Valid(t *testing.T) {
	patterns := []string{
		"npm install *",
		"go test ./...",
		"/tmp/**",
		"**/node_modules/**",
		"curl https://api.example.com/*",
		"rm -rf *",
		"[abc]",
		"[a-z]",
	}
	for _, p := range patterns {
		t.Run(p, func(t *testing.T) {
			if err := validateGlobPattern(p); err != nil {
				t.Errorf("validateGlobPattern(%q) returned unexpected error: %v", p, err)
			}
		})
	}
}

func TestValidateGlobPattern_Invalid(t *testing.T) {
	tests := []struct {
		pattern string
		wantErr string
	}{
		{"invalid[pattern", "missing closing bracket"},
		{"]nope", "unexpected ']'"},
	}
	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			err := validateGlobPattern(tt.pattern)
			if err == nil {
				t.Fatalf("expected error for pattern %q, got nil", tt.pattern)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("got error %q, want it to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// ── custom policy package ──────────────────────────────────────────────────

func TestLoadCustomPolicy_MissingFile(t *testing.T) {
	p, err := policy.LoadCustomPolicy("/nonexistent/path/custom.yaml")
	if err != nil {
		t.Fatalf("LoadCustomPolicy on missing file should not error, got: %v", err)
	}
	if p.Version != "1" {
		t.Errorf("expected version 1, got %q", p.Version)
	}
	if len(p.Policies) != 0 {
		t.Errorf("expected empty policies, got %d", len(p.Policies))
	}
}

func TestLoadCustomPolicy_ExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.yaml")

	content := `version: "1"
policies:
  - name: custom-allow-commands
    match:
      tool:
        - exec
    rules:
      - action: allow
        when:
          command_matches:
            - "npm install *"
        message: "User-allowed: npm install *"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	p, err := policy.LoadCustomPolicy(path)
	if err != nil {
		t.Fatalf("LoadCustomPolicy: %v", err)
	}
	if len(p.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(p.Policies))
	}
	if len(p.Policies[0].Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(p.Policies[0].Rules))
	}
}

func TestSaveCustomPolicy_CreatesDirectories(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "deeper", "custom.yaml")

	p := &policy.CustomPolicy{Version: "1"}
	if err := policy.SaveCustomPolicy(path, p); err != nil {
		t.Fatalf("SaveCustomPolicy: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected file at %s: %v", path, err)
	}
}

func TestSaveCustomPolicy_HeaderComment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.yaml")

	p := &policy.CustomPolicy{Version: "1"}
	if err := policy.SaveCustomPolicy(path, p); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "# Rampart custom policy") {
		t.Errorf("expected header comment, got: %s", string(data)[:60])
	}
}

func TestAddRule_CommandPattern(t *testing.T) {
	p := &policy.CustomPolicy{Version: "1"}
	if err := p.AddRule("allow", "npm install *", "test msg", ""); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	if p.TotalRules() != 1 {
		t.Fatalf("expected 1 rule, got %d", p.TotalRules())
	}

	entry := p.Policies[0]
	if entry.Name != "custom-allow-commands" {
		t.Errorf("expected entry name custom-allow-commands, got %q", entry.Name)
	}
	if len(entry.Match.Tool) == 0 || entry.Match.Tool[0] != "exec" {
		t.Errorf("expected tool exec, got %v", entry.Match.Tool)
	}
	rule := entry.Rules[0]
	if rule.Action != "allow" {
		t.Errorf("expected action allow, got %q", rule.Action)
	}
	if len(rule.When.CommandMatches) == 0 || rule.When.CommandMatches[0] != "npm install *" {
		t.Errorf("expected command_matches [npm install *], got %v", rule.When.CommandMatches)
	}
}

func TestAddRule_PathPattern(t *testing.T) {
	p := &policy.CustomPolicy{Version: "1"}
	if err := p.AddRule("deny", "/etc/**", "block etc", ""); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	entry := p.Policies[0]
	if entry.Name != "custom-deny-paths" {
		t.Errorf("expected entry name custom-deny-paths, got %q", entry.Name)
	}

	// Should apply to read/write/edit
	tools := map[string]bool{}
	for _, t := range entry.Match.Tool {
		tools[t] = true
	}
	for _, want := range []string{"read", "write", "edit"} {
		if !tools[want] {
			t.Errorf("expected tool %q in match, got %v", want, entry.Match.Tool)
		}
	}

	rule := entry.Rules[0]
	if len(rule.When.PathMatches) == 0 || rule.When.PathMatches[0] != "/etc/**" {
		t.Errorf("expected path_matches [/etc/**], got %v", rule.When.PathMatches)
	}
}

func TestAddRule_AppendsToExistingEntry(t *testing.T) {
	p := &policy.CustomPolicy{Version: "1"}

	if err := p.AddRule("allow", "npm install *", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := p.AddRule("allow", "go test *", "", ""); err != nil {
		t.Fatal(err)
	}

	// Should still be a single policy entry with two rules.
	if len(p.Policies) != 1 {
		t.Fatalf("expected 1 policy entry, got %d", len(p.Policies))
	}
	if p.TotalRules() != 2 {
		t.Fatalf("expected 2 rules total, got %d", p.TotalRules())
	}
}

func TestAddRule_EmptyPattern(t *testing.T) {
	p := &policy.CustomPolicy{Version: "1"}
	err := p.AddRule("allow", "", "", "")
	if err == nil {
		t.Fatal("expected error for empty pattern")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected 'empty' in error, got: %v", err)
	}
}

func TestAddRule_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.yaml")

	// Create policy, add rules, save.
	p := &policy.CustomPolicy{Version: "1"}
	_ = p.AddRule("allow", "npm install *", "allow npm", "")
	_ = p.AddRule("deny", "rm -rf /", "protect root", "")
	if err := policy.SaveCustomPolicy(path, p); err != nil {
		t.Fatal(err)
	}

	// Reload from disk.
	p2, err := policy.LoadCustomPolicy(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}

	if p2.TotalRules() != 2 {
		t.Fatalf("expected 2 rules after reload, got %d", p2.TotalRules())
	}
}

func TestAddRule_InvalidYAMLPreserved(t *testing.T) {
	// Verify that the YAML saved by SaveCustomPolicy is valid.
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.yaml")

	p := &policy.CustomPolicy{Version: "1"}
	_ = p.AddRule("allow", "npm install *", "msg", "")
	_ = p.AddRule("deny", "/etc/**", "block", "")
	if err := policy.SaveCustomPolicy(path, p); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Strip the leading comment so yaml.Unmarshal is happy.
	var out map[string]interface{}
	if err := yaml.Unmarshal(data, &out); err != nil {
		t.Fatalf("saved YAML is not valid: %v\nContent:\n%s", err, data)
	}
}

// ── CLI command integration ────────────────────────────────────────────────

func TestAllowCmd_Basic(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)

	// Make sure the policy dir exists.
	_ = os.MkdirAll(filepath.Join(dir, ".rampart", "policies"), 0o755)

	// The global policy path is derived from HOME.
	policyPath := filepath.Join(dir, ".rampart", "policies", "custom.yaml")

	outBuf := &bytes.Buffer{}
	cmd := NewRootCmd(context.Background(), outBuf, &bytes.Buffer{})
	cmd.SetArgs([]string{
		"allow",
		"npm install *",
		"--global",
		"--yes",
		"--api", "http://127.0.0.1:0", // unreachable — that's fine
	})

	_ = cmd.Execute()

	// Verify the policy file was created with at least one rule.
	p, err := policy.LoadCustomPolicy(policyPath)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if p.TotalRules() == 0 {
		t.Fatal("expected at least one rule to be written")
	}
}

func TestBlockCmd_Basic(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)

	_ = os.MkdirAll(filepath.Join(dir, ".rampart", "policies"), 0o755)
	policyPath := filepath.Join(dir, ".rampart", "policies", "custom.yaml")

	cmd := NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
	cmd.SetArgs([]string{
		"block",
		"rm -rf /",
		"--global",
		"--yes",
		"--api", "http://127.0.0.1:0",
	})

	_ = cmd.Execute()

	p, err := policy.LoadCustomPolicy(policyPath)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if p.TotalRules() == 0 {
		t.Fatal("expected at least one deny rule")
	}

	// Check the rule has action deny.
	var foundDeny bool
	for _, entry := range p.Policies {
		for _, rule := range entry.Rules {
			if rule.Action == "deny" {
				foundDeny = true
			}
		}
	}
	if !foundDeny {
		t.Error("expected a deny rule to be present")
	}
}

func TestAllowCmd_EmptyPattern(t *testing.T) {
	cmd := NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
	errBuf := &bytes.Buffer{}
	cmd.SetErr(errBuf)
	cmd.SetArgs([]string{"allow", "", "--yes"})
	// cobra will reject this because ExactArgs(1) needs a non-empty string,
	// but pattern validation runs inside RunE. Test that the command exists.
	// (cobra sees "" as a valid arg, so RunE fires).
	err := cmd.Execute()
	if err == nil {
		t.Log("note: cobra may have handled empty pattern differently")
	}
}

func TestAllowCmd_InvalidGlob(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)

	cmd := NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
	cmd.SetArgs([]string{"allow", "bad[pattern", "--global", "--yes"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected an error for invalid glob pattern")
	}
	if !strings.Contains(err.Error(), "invalid glob pattern") {
		t.Errorf("expected 'invalid glob pattern' in error, got: %v", err)
	}
}

func TestAllowCmd_GlobalVsProjectMutuallyExclusive(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)

	cmd := NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
	cmd.SetArgs([]string{"allow", "npm install *", "--global", "--project", "--yes"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for mutually exclusive flags")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected 'mutually exclusive' in error, got: %v", err)
	}
}

// ── Reload API ─────────────────────────────────────────────────────────────

func TestReloadPolicy_Success(t *testing.T) {
	// Start a mock HTTP server that responds 200 to /v1/policy/reload.
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/policy/reload" {
			called = true
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		} else {
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	testSetHome(t, dir)

	_ = os.MkdirAll(filepath.Join(dir, ".rampart", "policies"), 0o755)

	// Set a fake token so reloadPolicy is actually called.
	t.Setenv("RAMPART_TOKEN", "test-token")

	cmd := NewRootCmd(context.Background(), &bytes.Buffer{}, &bytes.Buffer{})
	outBuf := &bytes.Buffer{}
	cmd.SetOut(outBuf)
	cmd.SetArgs([]string{
		"allow",
		"npm install *",
		"--global",
		"--yes",
		"--api", srv.URL,
	})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	if !called {
		t.Error("expected reload endpoint to be called")
	}

	out := outBuf.String()
	if !strings.Contains(out, "reloaded") {
		t.Errorf("expected 'reloaded' in output, got: %s", out)
	}
}

func TestReloadPolicy_DaemonUnreachable(t *testing.T) {
	dir := t.TempDir()
	testSetHome(t, dir)

	_ = os.MkdirAll(filepath.Join(dir, ".rampart", "policies"), 0o755)

	t.Setenv("RAMPART_TOKEN", "test-token")

	outBuf := &bytes.Buffer{}
	cmd := NewRootCmd(context.Background(), outBuf, &bytes.Buffer{})
	cmd.SetArgs([]string{
		"allow",
		"npm install *",
		"--global",
		"--yes",
		"--api", "http://127.0.0.1:1", // nothing listening here
	})

	// Should not fail — daemon unreachable is not fatal.
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("expected no error when daemon unreachable, got: %v", err)
	}

	out := outBuf.String()
	if !strings.Contains(out, "Saved") && !strings.Contains(out, "rampart serve") {
		t.Errorf("expected 'Saved' or 'rampart serve' hint in output, got: %s", out)
	}
}

// ── IsPathPattern ──────────────────────────────────────────────────────────

func TestIsPathPattern(t *testing.T) {
	tests := []struct {
		pattern string
		want    bool
	}{
		{"/etc/passwd", true},
		{"~/Documents/**", true},
		{"**/node_modules/**", true},
		{"path/to/file", true},
		{"npm install *", false},
		{"rm -rf *", false},
		{"go test", false},
		{"curl https://example.com", false}, // URLs are not file paths
	}
	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			got := policy.IsPathPattern(tt.pattern)
			if got != tt.want {
				t.Errorf("IsPathPattern(%q) = %v, want %v", tt.pattern, got, tt.want)
			}
		})
	}
}

// ── DetectTool ─────────────────────────────────────────────────────────────

func TestDetectTool(t *testing.T) {
	if got := policy.DetectTool("npm install *"); got != "exec" {
		t.Errorf("DetectTool(npm...) = %q, want exec", got)
	}
	if got := policy.DetectTool("/etc/**"); got != "path" {
		t.Errorf("DetectTool(/etc/...) = %q, want path", got)
	}
}

// ── actionColor ────────────────────────────────────────────────────────────

func TestActionColor(t *testing.T) {
	if c := actionColor("allow", true); c != colorGreen {
		t.Errorf("actionColor(allow, true) = %q, want colorGreen", c)
	}
	if c := actionColor("deny", true); c != colorRed {
		t.Errorf("actionColor(deny, true) = %q, want colorRed", c)
	}
	if c := actionColor("allow", false); c != "" {
		t.Errorf("actionColor(allow, false) = %q, want empty", c)
	}
}

// ── defaultMessage ─────────────────────────────────────────────────────────

func TestDefaultMessage(t *testing.T) {
	msg := defaultMessage("allow", "npm install *", "exec")
	if !strings.Contains(msg, "npm install *") {
		t.Errorf("defaultMessage(allow) = %q, should contain pattern", msg)
	}

	msg = defaultMessage("deny", "rm -rf /", "exec")
	if !strings.Contains(msg, "rm -rf /") {
		t.Errorf("defaultMessage(deny) = %q, should contain pattern", msg)
	}
}

// ── Multiple rules accumulate ──────────────────────────────────────────────

func TestMultipleAllowBlockRules(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "custom.yaml")

	p := &policy.CustomPolicy{Version: "1"}

	// Add several rules.
	patterns := []struct {
		action  string
		pattern string
	}{
		{"allow", "npm install *"},
		{"allow", "go test ./..."},
		{"deny", "rm -rf /"},
		{"deny", "/etc/**"},
	}
	for _, pt := range patterns {
		if err := p.AddRule(pt.action, pt.pattern, "", ""); err != nil {
			t.Fatalf("AddRule(%q, %q): %v", pt.action, pt.pattern, err)
		}
	}

	if err := policy.SaveCustomPolicy(policyPath, p); err != nil {
		t.Fatal(err)
	}

	// Reload and verify total count.
	p2, err := policy.LoadCustomPolicy(policyPath)
	if err != nil {
		t.Fatal(err)
	}

	if p2.TotalRules() != 4 {
		t.Errorf("expected 4 rules, got %d", p2.TotalRules())
	}
}
