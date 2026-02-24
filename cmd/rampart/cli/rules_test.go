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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	custompolicy "github.com/peg/rampart/internal/policy"
)

// ─── rulesRelTime ────────────────────────────────────────────────────────────

func TestRulesRelTime_JustNow(t *testing.T) {
	got := rulesRelTime(time.Now().Add(-10 * time.Second))
	if got != "just now" {
		t.Errorf("want %q, got %q", "just now", got)
	}
}

func TestRulesRelTime_Minutes(t *testing.T) {
	got := rulesRelTime(time.Now().Add(-90 * time.Second))
	if got != "1 minute ago" {
		t.Errorf("want %q, got %q", "1 minute ago", got)
	}
	got2 := rulesRelTime(time.Now().Add(-45 * time.Minute))
	if !strings.Contains(got2, "minutes ago") {
		t.Errorf("expected 'minutes ago', got %q", got2)
	}
}

func TestRulesRelTime_Hours(t *testing.T) {
	got := rulesRelTime(time.Now().Add(-2 * time.Hour))
	if got != "2 hours ago" {
		t.Errorf("want %q, got %q", "2 hours ago", got)
	}
}

func TestRulesRelTime_Days(t *testing.T) {
	got := rulesRelTime(time.Now().Add(-48 * time.Hour))
	if got != "2 days ago" {
		t.Errorf("want %q, got %q", "2 days ago", got)
	}
}

func TestRulesRelTime_Weeks(t *testing.T) {
	got := rulesRelTime(time.Now().Add(-14 * 24 * time.Hour))
	if got != "2 weeks ago" {
		t.Errorf("want %q, got %q", "2 weeks ago", got)
	}
}

func TestRulesRelTime_Zero(t *testing.T) {
	got := rulesRelTime(time.Time{})
	if got != "unknown" {
		t.Errorf("want %q, got %q", "unknown", got)
	}
}

func TestRulesRelTime_Old(t *testing.T) {
	// Dates older than 30 days should show a formatted date.
	old := time.Now().Add(-90 * 24 * time.Hour)
	got := rulesRelTime(old)
	if len(got) != 10 || !strings.Contains(got, "-") {
		t.Errorf("expected YYYY-MM-DD format for old date, got %q", got)
	}
}

// ─── padRight / padLeft / truncateStr ────────────────────────────────────────

func TestPadRight(t *testing.T) {
	if got := padRight("abc", 6); got != "abc   " {
		t.Errorf("want %q, got %q", "abc   ", got)
	}
	if got := padRight("toolong", 3); got != "toolong" {
		t.Errorf("want %q, got %q", "toolong", got)
	}
}

func TestPadLeft(t *testing.T) {
	if got := padLeft("1", 4); got != "   1" {
		t.Errorf("want %q, got %q", "   1", got)
	}
}

func TestTruncateStr(t *testing.T) {
	if got := truncateStr("hello world", 8); got != "hello..." {
		t.Errorf("want %q, got %q", "hello...", got)
	}
	if got := truncateStr("short", 10); got != "short" {
		t.Errorf("want %q, got %q", "short", got)
	}
}

// ─── List: empty state ───────────────────────────────────────────────────────

func TestRulesList_Empty(t *testing.T) {
	// Override HOME so no global custom.yaml exists.
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Change to a temp dir so project custom.yaml doesn't exist either.
	origDir, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	_ = os.Chdir(t.TempDir())

	var buf bytes.Buffer
	err := runRulesList(&buf, &rootOptions{}, false, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "No custom rules found") {
		t.Errorf("expected empty state message, got:\n%s", out)
	}
	if !strings.Contains(out, "rampart allow") {
		t.Errorf("expected hint for rampart allow, got:\n%s", out)
	}
}

// ─── List: with global rules ─────────────────────────────────────────────────

func TestRulesList_GlobalRules(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Write global custom.yaml.
	gDir := filepath.Join(tmpHome, ".rampart", "policies")
	if err := os.MkdirAll(gDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cp := &custompolicy.CustomPolicy{
		Version: "1",
		Rules: []custompolicy.CustomRule{
			{Action: "allow", Tool: "exec", Pattern: "npm install *", AddedAt: time.Now().Add(-2 * time.Hour)},
			{Action: "deny", Tool: "exec", Pattern: "curl * | bash", AddedAt: time.Now().Add(-72 * time.Hour)},
		},
	}
	gPath := filepath.Join(gDir, "custom.yaml")
	if err := custompolicy.SaveCustomPolicy(gPath, cp); err != nil {
		t.Fatal(err)
	}

	// Use a temp dir as cwd so there's no project policy.
	origDir, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	_ = os.Chdir(t.TempDir())

	var buf bytes.Buffer
	err := runRulesList(&buf, &rootOptions{}, false, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "allow") {
		t.Errorf("expected 'allow' in output, got:\n%s", out)
	}
	if !strings.Contains(out, "npm install") {
		t.Errorf("expected pattern in output, got:\n%s", out)
	}
	if !strings.Contains(out, "deny") {
		t.Errorf("expected 'deny' in output, got:\n%s", out)
	}
	if !strings.Contains(out, "Global") {
		t.Errorf("expected 'Global' section header, got:\n%s", out)
	}
}

// ─── List: with project rules ────────────────────────────────────────────────

func TestRulesList_ProjectRules(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	origDir, _ := os.Getwd()
	tmpCwd := t.TempDir()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	_ = os.Chdir(tmpCwd)

	// Write project custom.yaml.
	pDir := filepath.Join(tmpCwd, ".rampart")
	if err := os.MkdirAll(pDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cp := &custompolicy.CustomPolicy{
		Version: "1",
		Rules: []custompolicy.CustomRule{
			{Action: "deny", Tool: "write", Pattern: "*.prod.*", AddedAt: time.Now().Add(-24 * time.Hour)},
		},
	}
	pPath := filepath.Join(pDir, "custom.yaml")
	if err := custompolicy.SaveCustomPolicy(pPath, cp); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	err := runRulesList(&buf, &rootOptions{}, false, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Project") {
		t.Errorf("expected 'Project' section header, got:\n%s", out)
	}
	if !strings.Contains(out, "*.prod.*") {
		t.Errorf("expected pattern in output, got:\n%s", out)
	}
}

// ─── List: both sources ──────────────────────────────────────────────────────

func TestRulesList_Both(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	origDir, _ := os.Getwd()
	tmpCwd := t.TempDir()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	_ = os.Chdir(tmpCwd)

	// Global rule.
	gDir := filepath.Join(tmpHome, ".rampart", "policies")
	_ = os.MkdirAll(gDir, 0o755)
	gp := &custompolicy.CustomPolicy{
		Version: "1",
		Rules:   []custompolicy.CustomRule{{Action: "allow", Tool: "exec", Pattern: "docker build *", AddedAt: time.Now().Add(-1 * time.Hour)}},
	}
	_ = custompolicy.SaveCustomPolicy(filepath.Join(gDir, "custom.yaml"), gp)

	// Project rule.
	pDir := filepath.Join(tmpCwd, ".rampart")
	_ = os.MkdirAll(pDir, 0o755)
	pp := &custompolicy.CustomPolicy{
		Version: "1",
		Rules:   []custompolicy.CustomRule{{Action: "deny", Tool: "write", Pattern: "secrets/**", AddedAt: time.Now().Add(-5 * 24 * time.Hour)}},
	}
	_ = custompolicy.SaveCustomPolicy(filepath.Join(pDir, "custom.yaml"), pp)

	var buf bytes.Buffer
	err := runRulesList(&buf, &rootOptions{}, false, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Global") {
		t.Errorf("expected Global section, got:\n%s", out)
	}
	if !strings.Contains(out, "Project") {
		t.Errorf("expected Project section, got:\n%s", out)
	}
	if !strings.Contains(out, "docker build") {
		t.Errorf("expected docker build pattern, got:\n%s", out)
	}
	if !strings.Contains(out, "secrets/") {
		t.Errorf("expected secrets pattern, got:\n%s", out)
	}
}

// ─── List: --global flag ─────────────────────────────────────────────────────

func TestRulesList_GlobalOnly(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	origDir, _ := os.Getwd()
	tmpCwd := t.TempDir()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	_ = os.Chdir(tmpCwd)

	// Global rule only.
	gDir := filepath.Join(tmpHome, ".rampart", "policies")
	_ = os.MkdirAll(gDir, 0o755)
	gp := &custompolicy.CustomPolicy{
		Version: "1",
		Rules:   []custompolicy.CustomRule{{Action: "allow", Tool: "exec", Pattern: "global-only-pattern", AddedAt: time.Now()}},
	}
	_ = custompolicy.SaveCustomPolicy(filepath.Join(gDir, "custom.yaml"), gp)

	// Project rule should NOT appear.
	pDir := filepath.Join(tmpCwd, ".rampart")
	_ = os.MkdirAll(pDir, 0o755)
	pp := &custompolicy.CustomPolicy{
		Version: "1",
		Rules:   []custompolicy.CustomRule{{Action: "deny", Tool: "write", Pattern: "project-pattern", AddedAt: time.Now()}},
	}
	_ = custompolicy.SaveCustomPolicy(filepath.Join(pDir, "custom.yaml"), pp)

	var buf bytes.Buffer
	err := runRulesList(&buf, &rootOptions{}, true, false, false) // globalOnly=true
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "global-only-pattern") {
		t.Errorf("expected global pattern, got:\n%s", out)
	}
	if strings.Contains(out, "project-pattern") {
		t.Errorf("should not show project rules when --global set, got:\n%s", out)
	}
}

// ─── List: --json output ─────────────────────────────────────────────────────

func TestRulesList_JSON(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	origDir, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	_ = os.Chdir(t.TempDir())

	gDir := filepath.Join(tmpHome, ".rampart", "policies")
	_ = os.MkdirAll(gDir, 0o755)
	gp := &custompolicy.CustomPolicy{
		Version: "1",
		Rules:   []custompolicy.CustomRule{{Action: "allow", Tool: "exec", Pattern: "npm *", AddedAt: time.Now().Add(-time.Hour)}},
	}
	_ = custompolicy.SaveCustomPolicy(filepath.Join(gDir, "custom.yaml"), gp)

	var buf bytes.Buffer
	err := runRulesList(&buf, &rootOptions{}, false, false, true) // jsonOut=true
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, buf.String())
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result))
	}
	if result[0]["action"] != "allow" {
		t.Errorf("expected action=allow, got %v", result[0]["action"])
	}
	if result[0]["pattern"] != "npm *" {
		t.Errorf("expected pattern=npm *, got %v", result[0]["pattern"])
	}
	if result[0]["source"] != "global" {
		t.Errorf("expected source=global, got %v", result[0]["source"])
	}
}

// ─── Remove ──────────────────────────────────────────────────────────────────

func TestRulesRemove_ValidIndex(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	origDir, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	_ = os.Chdir(t.TempDir())

	gDir := filepath.Join(tmpHome, ".rampart", "policies")
	_ = os.MkdirAll(gDir, 0o755)
	gp := &custompolicy.CustomPolicy{
		Version: "1",
		Rules: []custompolicy.CustomRule{
			{Action: "allow", Tool: "exec", Pattern: "npm install *", AddedAt: time.Now().Add(-time.Hour)},
			{Action: "deny", Tool: "exec", Pattern: "curl * | bash", AddedAt: time.Now().Add(-2 * time.Hour)},
		},
	}
	gPath := filepath.Join(gDir, "custom.yaml")
	_ = custompolicy.SaveCustomPolicy(gPath, gp)

	// Simulate "y" confirmation.
	cmd := newRulesCmd(&rootOptions{})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetIn(strings.NewReader("y\n"))
	cmd.SetArgs([]string{"remove", "1"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the first rule was removed.
	loaded, err := custompolicy.LoadCustomPolicy(gPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Rules) != 1 {
		t.Fatalf("expected 1 rule remaining, got %d", len(loaded.Rules))
	}
	if loaded.Rules[0].Pattern != "curl * | bash" {
		t.Errorf("wrong rule remaining: %q", loaded.Rules[0].Pattern)
	}
}

func TestRulesRemove_InvalidIndex(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	origDir, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	_ = os.Chdir(t.TempDir())

	cmd := newRulesCmd(&rootOptions{})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetIn(strings.NewReader("y\n"))
	cmd.SetArgs([]string{"remove", "99"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for out-of-range index")
	}
}

func TestRulesRemove_NonNumericIndex(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	origDir, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	_ = os.Chdir(t.TempDir())

	cmd := newRulesCmd(&rootOptions{})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"remove", "abc"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for non-numeric index")
	}
}

func TestRulesRemove_Cancelled(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	origDir, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	_ = os.Chdir(t.TempDir())

	gDir := filepath.Join(tmpHome, ".rampart", "policies")
	_ = os.MkdirAll(gDir, 0o755)
	gp := &custompolicy.CustomPolicy{
		Version: "1",
		Rules:   []custompolicy.CustomRule{{Action: "allow", Tool: "exec", Pattern: "npm *", AddedAt: time.Now()}},
	}
	gPath := filepath.Join(gDir, "custom.yaml")
	_ = custompolicy.SaveCustomPolicy(gPath, gp)

	// Simulate "n" (cancel).
	cmd := newRulesCmd(&rootOptions{})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetIn(strings.NewReader("n\n"))
	cmd.SetArgs([]string{"remove", "1"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cancel should not return error: %v", err)
	}

	// Rule should still be there.
	loaded, err := custompolicy.LoadCustomPolicy(gPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Rules) != 1 {
		t.Errorf("expected rule to still exist after cancel, got %d rules", len(loaded.Rules))
	}
}

func TestRulesRemove_Force(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	origDir, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	_ = os.Chdir(t.TempDir())

	gDir := filepath.Join(tmpHome, ".rampart", "policies")
	_ = os.MkdirAll(gDir, 0o755)
	gp := &custompolicy.CustomPolicy{
		Version: "1",
		Rules:   []custompolicy.CustomRule{{Action: "allow", Tool: "exec", Pattern: "npm *", AddedAt: time.Now()}},
	}
	gPath := filepath.Join(gDir, "custom.yaml")
	_ = custompolicy.SaveCustomPolicy(gPath, gp)

	cmd := newRulesCmd(&rootOptions{})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	// No input needed when --force is set.
	cmd.SetArgs([]string{"remove", "1", "--force"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	loaded, err := custompolicy.LoadCustomPolicy(gPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Rules) != 0 {
		t.Errorf("expected 0 rules after forced remove, got %d", len(loaded.Rules))
	}
}

// ─── Reset ───────────────────────────────────────────────────────────────────

func TestRulesReset_Empty(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	origDir, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	_ = os.Chdir(t.TempDir())

	cmd := newRulesCmd(&rootOptions{})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"reset"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "No custom rules") {
		t.Errorf("expected empty message, got:\n%s", out)
	}
}

func TestRulesReset_WithRules(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	origDir, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	_ = os.Chdir(t.TempDir())

	gDir := filepath.Join(tmpHome, ".rampart", "policies")
	_ = os.MkdirAll(gDir, 0o755)
	gp := &custompolicy.CustomPolicy{
		Version: "1",
		Rules: []custompolicy.CustomRule{
			{Action: "allow", Tool: "exec", Pattern: "a", AddedAt: time.Now()},
			{Action: "deny", Tool: "exec", Pattern: "b", AddedAt: time.Now()},
		},
	}
	gPath := filepath.Join(gDir, "custom.yaml")
	_ = custompolicy.SaveCustomPolicy(gPath, gp)

	cmd := newRulesCmd(&rootOptions{})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetIn(strings.NewReader("y\n"))
	cmd.SetArgs([]string{"reset"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	loaded, err := custompolicy.LoadCustomPolicy(gPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Rules) != 0 {
		t.Errorf("expected 0 rules after reset, got %d", len(loaded.Rules))
	}
}

func TestRulesReset_Cancelled(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	origDir, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	_ = os.Chdir(t.TempDir())

	gDir := filepath.Join(tmpHome, ".rampart", "policies")
	_ = os.MkdirAll(gDir, 0o755)
	gp := &custompolicy.CustomPolicy{
		Version: "1",
		Rules:   []custompolicy.CustomRule{{Action: "allow", Tool: "exec", Pattern: "keep-me", AddedAt: time.Now()}},
	}
	gPath := filepath.Join(gDir, "custom.yaml")
	_ = custompolicy.SaveCustomPolicy(gPath, gp)

	cmd := newRulesCmd(&rootOptions{})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetIn(strings.NewReader("n\n"))
	cmd.SetArgs([]string{"reset"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cancel should not return error: %v", err)
	}

	loaded, err := custompolicy.LoadCustomPolicy(gPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Rules) != 1 {
		t.Errorf("expected rules preserved after cancel, got %d rules", len(loaded.Rules))
	}
}

func TestRulesReset_Force(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	origDir, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	_ = os.Chdir(t.TempDir())

	gDir := filepath.Join(tmpHome, ".rampart", "policies")
	_ = os.MkdirAll(gDir, 0o755)
	gp := &custompolicy.CustomPolicy{
		Version: "1",
		Rules:   []custompolicy.CustomRule{{Action: "allow", Tool: "exec", Pattern: "x", AddedAt: time.Now()}},
	}
	gPath := filepath.Join(gDir, "custom.yaml")
	_ = custompolicy.SaveCustomPolicy(gPath, gp)

	cmd := newRulesCmd(&rootOptions{})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"reset", "--force"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	loaded, err := custompolicy.LoadCustomPolicy(gPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Rules) != 0 {
		t.Errorf("expected 0 rules after forced reset, got %d", len(loaded.Rules))
	}
}
