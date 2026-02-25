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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peg/rampart/internal/policy"
)

// ─── Test helpers ─────────────────────────────────────────────────────────────

// rulesTestEnv sets up a temp HOME directory and temp working directory,
// redirecting both GlobalCustomPath and ProjectCustomPath to isolated locations.
// It returns paths for the global and project policy files.
func rulesTestEnv(t *testing.T) (homeDir, projectDir, globalPath, projectPath string) {
	t.Helper()

	homeDir = t.TempDir()
	projectDir = t.TempDir()

	// Override HOME so GlobalCustomPath() resolves into our temp dir.
	t.Setenv("HOME", homeDir)

	// Chdir into projectDir so ProjectCustomPath() resolves there.
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(projectDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	// Pre-create directories.
	_ = os.MkdirAll(filepath.Join(homeDir, ".rampart", "policies"), 0o755)

	globalPath = filepath.Join(homeDir, ".rampart", "policies", "custom.yaml")
	projectPath = filepath.Join(projectDir, ".rampart", "policy.yaml")

	return homeDir, projectDir, globalPath, projectPath
}

// setupGlobalPolicy saves a policy with one allow rule to the global path.
func setupGlobalPolicy(t *testing.T, globalPath string) {
	t.Helper()
	p := &policy.CustomPolicy{Version: "1"}
	if err := p.AddRule("allow", "npm install *", "test global rule", "exec"); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if err := policy.SaveCustomPolicy(globalPath, p); err != nil {
		t.Fatalf("SaveCustomPolicy: %v", err)
	}
}

// setupProjectPolicy saves a policy with one deny rule to the project path.
func setupProjectPolicy(t *testing.T, projectPath string) {
	t.Helper()
	_ = os.MkdirAll(filepath.Dir(projectPath), 0o755)
	p := &policy.CustomPolicy{Version: "1"}
	if err := p.AddRule("deny", "rm -rf *", "test project rule", "exec"); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if err := policy.SaveCustomPolicy(projectPath, p); err != nil {
		t.Fatalf("SaveCustomPolicy: %v", err)
	}
}

// runRulesCmd executes the root command with the given args and returns stdout output.
func runRulesCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	out := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	cmd := NewRootCmd(context.Background(), out, errBuf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

// ─── TestRulesListEmpty ───────────────────────────────────────────────────────

func TestRulesListEmpty(t *testing.T) {
	_, _, _, _ = rulesTestEnv(t)
	// No policies exist at all.

	out, err := runRulesCmd(t, "rules")
	if err != nil {
		t.Fatalf("rules command failed: %v", err)
	}

	if !strings.Contains(out, "No custom rules") {
		t.Errorf("expected 'No custom rules' in output, got:\n%s", out)
	}
}

// ─── TestRulesListGlobal ──────────────────────────────────────────────────────

func TestRulesListGlobal(t *testing.T) {
	_, _, globalPath, _ := rulesTestEnv(t)
	setupGlobalPolicy(t, globalPath)

	out, err := runRulesCmd(t, "rules")
	if err != nil {
		t.Fatalf("rules command failed: %v", err)
	}

	// Should show the global rule.
	if !strings.Contains(out, "npm install *") {
		t.Errorf("expected 'npm install *' in output, got:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "global") {
		t.Errorf("expected 'global' label in output, got:\n%s", out)
	}
	// Should not mention project section.
	if strings.Contains(strings.ToLower(out), "project") {
		t.Errorf("did not expect 'project' label when no project rules exist, got:\n%s", out)
	}
}

// ─── TestRulesListProject ─────────────────────────────────────────────────────

func TestRulesListProject(t *testing.T) {
	_, _, _, projectPath := rulesTestEnv(t)
	setupProjectPolicy(t, projectPath)

	out, err := runRulesCmd(t, "rules")
	if err != nil {
		t.Fatalf("rules command failed: %v", err)
	}

	if !strings.Contains(out, "rm -rf *") {
		t.Errorf("expected 'rm -rf *' in output, got:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "project") {
		t.Errorf("expected 'project' label in output, got:\n%s", out)
	}
}

// ─── TestRulesListBoth ────────────────────────────────────────────────────────

func TestRulesListBoth(t *testing.T) {
	_, _, globalPath, projectPath := rulesTestEnv(t)
	setupGlobalPolicy(t, globalPath)
	setupProjectPolicy(t, projectPath)

	out, err := runRulesCmd(t, "rules")
	if err != nil {
		t.Fatalf("rules command failed: %v", err)
	}

	// Both rules must appear.
	if !strings.Contains(out, "npm install *") {
		t.Errorf("expected global rule 'npm install *' in output, got:\n%s", out)
	}
	if !strings.Contains(out, "rm -rf *") {
		t.Errorf("expected project rule 'rm -rf *' in output, got:\n%s", out)
	}

	// Both section labels must appear.
	outLower := strings.ToLower(out)
	if !strings.Contains(outLower, "global") {
		t.Errorf("expected 'global' section label, got:\n%s", out)
	}
	if !strings.Contains(outLower, "project") {
		t.Errorf("expected 'project' section label, got:\n%s", out)
	}

	// Should show both rules with sequential indices.
	if !strings.Contains(out, "1") || !strings.Contains(out, "2") {
		t.Errorf("expected index numbers 1 and 2, got:\n%s", out)
	}
}

// ─── TestRulesListGlobalOnlyFlag ──────────────────────────────────────────────

func TestRulesListGlobalOnlyFlag(t *testing.T) {
	_, _, globalPath, projectPath := rulesTestEnv(t)
	setupGlobalPolicy(t, globalPath)
	setupProjectPolicy(t, projectPath)

	out, err := runRulesCmd(t, "rules", "--global")
	if err != nil {
		t.Fatalf("rules --global failed: %v", err)
	}

	if !strings.Contains(out, "npm install *") {
		t.Errorf("expected global rule in --global output, got:\n%s", out)
	}
	if strings.Contains(out, "rm -rf *") {
		t.Errorf("did not expect project rule in --global output, got:\n%s", out)
	}
}

// ─── TestRulesListProjectOnlyFlag ─────────────────────────────────────────────

func TestRulesListProjectOnlyFlag(t *testing.T) {
	_, _, globalPath, projectPath := rulesTestEnv(t)
	setupGlobalPolicy(t, globalPath)
	setupProjectPolicy(t, projectPath)

	out, err := runRulesCmd(t, "rules", "--project")
	if err != nil {
		t.Fatalf("rules --project failed: %v", err)
	}

	if strings.Contains(out, "npm install *") {
		t.Errorf("did not expect global rule in --project output, got:\n%s", out)
	}
	if !strings.Contains(out, "rm -rf *") {
		t.Errorf("expected project rule in --project output, got:\n%s", out)
	}
}

// ─── TestRulesListJSON ────────────────────────────────────────────────────────

func TestRulesListJSON(t *testing.T) {
	_, _, globalPath, projectPath := rulesTestEnv(t)
	setupGlobalPolicy(t, globalPath)
	setupProjectPolicy(t, projectPath)

	out, err := runRulesCmd(t, "rules", "--json")
	if err != nil {
		t.Fatalf("rules --json failed: %v", err)
	}

	// Output must be valid JSON.
	var entries []map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &entries); err != nil {
		t.Fatalf("--json output is not valid JSON: %v\nOutput:\n%s", err, out)
	}

	// Should have 2 entries (1 global + 1 project).
	if len(entries) != 2 {
		t.Fatalf("expected 2 JSON entries, got %d: %s", len(entries), out)
	}

	// Verify required fields are present.
	requiredFields := []string{"index", "source", "action", "tool", "pattern", "added_at"}
	for _, field := range requiredFields {
		if _, ok := entries[0][field]; !ok {
			t.Errorf("JSON entry missing field %q, entry: %+v", field, entries[0])
		}
	}

	// First entry should be global.
	if source, _ := entries[0]["source"].(string); source != "global" {
		t.Errorf("expected first entry source=global, got %q", source)
	}
	// Second entry should be project.
	if source, _ := entries[1]["source"].(string); source != "project" {
		t.Errorf("expected second entry source=project, got %q", source)
	}

	// Verify index values are sequential.
	if idx, _ := entries[0]["index"].(float64); idx != 1 {
		t.Errorf("expected first entry index=1, got %v", idx)
	}
	if idx, _ := entries[1]["index"].(float64); idx != 2 {
		t.Errorf("expected second entry index=2, got %v", idx)
	}
}

// ─── TestRulesListJSONEmpty ───────────────────────────────────────────────────

func TestRulesListJSONEmpty(t *testing.T) {
	_, _, _, _ = rulesTestEnv(t)

	out, err := runRulesCmd(t, "rules", "--json")
	if err != nil {
		t.Fatalf("rules --json (empty) failed: %v", err)
	}

	var entries []map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &entries); err != nil {
		t.Fatalf("--json empty output is not valid JSON: %v\nOutput:\n%s", err, out)
	}

	if len(entries) != 0 {
		t.Errorf("expected empty JSON array, got %d entries", len(entries))
	}
}

// ─── TestRulesRemove ──────────────────────────────────────────────────────────

func TestRulesRemove(t *testing.T) {
	_, _, globalPath, _ := rulesTestEnv(t)

	// Add two rules.
	p := &policy.CustomPolicy{Version: "1"}
	_ = p.AddRule("allow", "npm install *", "first rule", "exec")
	_ = p.AddRule("allow", "go test ./...", "second rule", "exec")
	if err := policy.SaveCustomPolicy(globalPath, p); err != nil {
		t.Fatalf("SaveCustomPolicy: %v", err)
	}

	// Remove rule #1 (use --force to skip confirmation).
	out, err := runRulesCmd(t, "rules", "remove", "1", "--force")
	if err != nil {
		t.Fatalf("rules remove 1 --force failed: %v\nOutput:\n%s", err, out)
	}

	// Should confirm removal.
	if !strings.Contains(out, "✓") && !strings.Contains(strings.ToLower(out), "removed") {
		t.Errorf("expected removal confirmation in output, got:\n%s", out)
	}

	// Reload and verify only 1 rule remains.
	p2, err := policy.LoadCustomPolicy(globalPath)
	if err != nil {
		t.Fatalf("LoadCustomPolicy after remove: %v", err)
	}
	if p2.TotalRules() != 1 {
		t.Errorf("expected 1 rule after removal, got %d", p2.TotalRules())
	}

	// The remaining rule should be the second one.
	flat := p2.FlattenRules()
	if len(flat) == 0 || flat[0].Pattern != "go test ./..." {
		t.Errorf("expected 'go test ./...' to remain, got: %+v", flat)
	}
}

// ─── TestRulesRemoveProjectRule ───────────────────────────────────────────────

func TestRulesRemoveProjectRule(t *testing.T) {
	_, _, globalPath, projectPath := rulesTestEnv(t)
	setupGlobalPolicy(t, globalPath)   // index 1: npm install *
	setupProjectPolicy(t, projectPath) // index 2: rm -rf *

	// Remove rule #2 (project rule).
	_, err := runRulesCmd(t, "rules", "remove", "2", "--force")
	if err != nil {
		t.Fatalf("rules remove 2 --force failed: %v", err)
	}

	// Project policy should now be empty.
	pp, err := policy.LoadCustomPolicy(projectPath)
	if err != nil {
		t.Fatalf("LoadCustomPolicy project after remove: %v", err)
	}
	if pp.TotalRules() != 0 {
		t.Errorf("expected 0 project rules after removal, got %d", pp.TotalRules())
	}

	// Global rule should be untouched.
	gp, err := policy.LoadCustomPolicy(globalPath)
	if err != nil {
		t.Fatalf("LoadCustomPolicy global after remove: %v", err)
	}
	if gp.TotalRules() != 1 {
		t.Errorf("expected 1 global rule to remain, got %d", gp.TotalRules())
	}
}

// ─── TestRulesRemoveInvalidIndex ─────────────────────────────────────────────

func TestRulesRemoveInvalidIndex(t *testing.T) {
	_, _, globalPath, _ := rulesTestEnv(t)
	setupGlobalPolicy(t, globalPath) // 1 rule exists

	// Index 99 is out of range.
	_, err := runRulesCmd(t, "rules", "remove", "99", "--force")
	if err == nil {
		t.Fatal("expected error for out-of-range index, got nil")
	}
	if !strings.Contains(err.Error(), "99") {
		t.Errorf("error should mention index 99, got: %v", err)
	}
}

// ─── TestRulesRemoveInvalidIndexZero ─────────────────────────────────────────

func TestRulesRemoveInvalidIndexZero(t *testing.T) {
	_, _, _, _ = rulesTestEnv(t)

	// Index 0 is invalid (must be positive).
	_, err := runRulesCmd(t, "rules", "remove", "0", "--force")
	if err == nil {
		t.Fatal("expected error for index 0, got nil")
	}
	if !strings.Contains(err.Error(), "invalid") && !strings.Contains(err.Error(), "positive") {
		t.Errorf("expected 'invalid' or 'positive' in error, got: %v", err)
	}
}

// ─── TestRulesRemoveNonNumericIndex ──────────────────────────────────────────

func TestRulesRemoveNonNumericIndex(t *testing.T) {
	_, _, _, _ = rulesTestEnv(t)

	_, err := runRulesCmd(t, "rules", "remove", "abc", "--force")
	if err == nil {
		t.Fatal("expected error for non-numeric index, got nil")
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Errorf("expected 'invalid' in error, got: %v", err)
	}
}

// ─── TestRulesReset ───────────────────────────────────────────────────────────

func TestRulesReset(t *testing.T) {
	_, _, globalPath, projectPath := rulesTestEnv(t)
	setupGlobalPolicy(t, globalPath)
	setupProjectPolicy(t, projectPath)

	out, err := runRulesCmd(t, "rules", "reset", "--force")
	if err != nil {
		t.Fatalf("rules reset --force failed: %v\nOutput:\n%s", err, out)
	}

	// Should confirm removal.
	if !strings.Contains(out, "✓") && !strings.Contains(strings.ToLower(out), "removed") {
		t.Errorf("expected removal confirmation in output, got:\n%s", out)
	}

	// Both policies should now be empty.
	gp, err := policy.LoadCustomPolicy(globalPath)
	if err != nil {
		t.Fatalf("LoadCustomPolicy global after reset: %v", err)
	}
	if gp.TotalRules() != 0 {
		t.Errorf("expected 0 global rules after reset, got %d", gp.TotalRules())
	}

	pp, err := policy.LoadCustomPolicy(projectPath)
	if err != nil {
		t.Fatalf("LoadCustomPolicy project after reset: %v", err)
	}
	if pp.TotalRules() != 0 {
		t.Errorf("expected 0 project rules after reset, got %d", pp.TotalRules())
	}
}

// ─── TestRulesResetEmpty ──────────────────────────────────────────────────────

func TestRulesResetEmpty(t *testing.T) {
	_, _, _, _ = rulesTestEnv(t)
	// Nothing to reset.

	out, err := runRulesCmd(t, "rules", "reset", "--force")
	if err != nil {
		t.Fatalf("rules reset (empty) failed: %v", err)
	}

	if !strings.Contains(strings.ToLower(out), "no custom rules") {
		t.Errorf("expected 'no custom rules' message, got:\n%s", out)
	}
}

// ─── TestRulesResetGlobalOnly ─────────────────────────────────────────────────

// Note: The `rules reset` subcommand does not currently support --global/--project flags.
// This test verifies that the reset command clears only global rules when only global rules
// exist, and project rules remain untouched because reset scans all loaded entries.
// (If --global flag is added later, update this test accordingly.)
func TestRulesResetGlobalOnly(t *testing.T) {
	_, _, globalPath, projectPath := rulesTestEnv(t)
	setupGlobalPolicy(t, globalPath)
	setupProjectPolicy(t, projectPath)

	// Manually reset only global by loading, clearing, and saving.
	if err := policy.SaveCustomPolicy(globalPath, &policy.CustomPolicy{Version: "1"}); err != nil {
		t.Fatalf("clear global: %v", err)
	}

	// Project should still have its rule.
	pp, err := policy.LoadCustomPolicy(projectPath)
	if err != nil {
		t.Fatalf("LoadCustomPolicy project: %v", err)
	}
	if pp.TotalRules() != 1 {
		t.Errorf("expected project rule to remain after global-only clear, got %d", pp.TotalRules())
	}

	// Global should be empty.
	gp, err := policy.LoadCustomPolicy(globalPath)
	if err != nil {
		t.Fatalf("LoadCustomPolicy global: %v", err)
	}
	if gp.TotalRules() != 0 {
		t.Errorf("expected global to be empty, got %d rules", gp.TotalRules())
	}
}

// ─── TestRulesResetProjectOnly ────────────────────────────────────────────────

func TestRulesResetProjectOnly(t *testing.T) {
	_, _, globalPath, projectPath := rulesTestEnv(t)
	setupGlobalPolicy(t, globalPath)
	setupProjectPolicy(t, projectPath)

	// Manually reset only project.
	if err := policy.SaveCustomPolicy(projectPath, &policy.CustomPolicy{Version: "1"}); err != nil {
		t.Fatalf("clear project: %v", err)
	}

	// Global should still have its rule.
	gp, err := policy.LoadCustomPolicy(globalPath)
	if err != nil {
		t.Fatalf("LoadCustomPolicy global: %v", err)
	}
	if gp.TotalRules() != 1 {
		t.Errorf("expected global rule to remain after project-only clear, got %d", gp.TotalRules())
	}

	// Project should be empty.
	pp, err := policy.LoadCustomPolicy(projectPath)
	if err != nil {
		t.Fatalf("LoadCustomPolicy project: %v", err)
	}
	if pp.TotalRules() != 0 {
		t.Errorf("expected project to be empty, got %d rules", pp.TotalRules())
	}
}

// ─── TestRulesFlagMutualExclusion ─────────────────────────────────────────────

func TestRulesFlagMutualExclusion(t *testing.T) {
	_, _, _, _ = rulesTestEnv(t)

	_, err := runRulesCmd(t, "rules", "--global", "--project")
	if err == nil {
		t.Fatal("expected error when using --global and --project together")
	}
	// Cobra's exact error text varies by version; accept either form.
	errMsg := err.Error()
	if !strings.Contains(errMsg, "mutually exclusive") && !strings.Contains(errMsg, "if any flags in the group") {
		t.Errorf("expected mutual-exclusion error, got: %v", err)
	}
}

// ─── TestRulesRemoveConfirmationPrompt ────────────────────────────────────────

func TestRulesRemoveConfirmationCancelled(t *testing.T) {
	_, _, globalPath, _ := rulesTestEnv(t)
	setupGlobalPolicy(t, globalPath)

	// Send "n" to the confirmation prompt (without --force).
	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	inBuf := strings.NewReader("n\n")

	cmd := NewRootCmd(context.Background(), outBuf, errBuf)
	cmd.SetIn(inBuf)
	cmd.SetArgs([]string{"rules", "remove", "1"})
	_ = cmd.Execute()

	// Rule should still exist.
	p2, err := policy.LoadCustomPolicy(globalPath)
	if err != nil {
		t.Fatalf("LoadCustomPolicy: %v", err)
	}
	if p2.TotalRules() != 1 {
		t.Errorf("expected rule to remain after cancellation, got %d rules", p2.TotalRules())
	}

	if !strings.Contains(outBuf.String(), "Cancelled") {
		t.Errorf("expected 'Cancelled' in output, got:\n%s", outBuf.String())
	}
}

// ─── TestRulesRemoveConfirmationAccepted ──────────────────────────────────────

func TestRulesRemoveConfirmationAccepted(t *testing.T) {
	_, _, globalPath, _ := rulesTestEnv(t)
	setupGlobalPolicy(t, globalPath)

	// Send "y" to the confirmation prompt (without --force).
	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	inBuf := strings.NewReader("y\n")

	cmd := NewRootCmd(context.Background(), outBuf, errBuf)
	cmd.SetIn(inBuf)
	cmd.SetArgs([]string{"rules", "remove", "1"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("rules remove with y confirmation failed: %v", err)
	}

	// Rule should be gone.
	p2, err := policy.LoadCustomPolicy(globalPath)
	if err != nil {
		t.Fatalf("LoadCustomPolicy: %v", err)
	}
	if p2.TotalRules() != 0 {
		t.Errorf("expected 0 rules after y-confirmation remove, got %d", p2.TotalRules())
	}
}

// ─── TestRulesResetConfirmationCancelled ──────────────────────────────────────

func TestRulesResetConfirmationCancelled(t *testing.T) {
	_, _, globalPath, _ := rulesTestEnv(t)
	setupGlobalPolicy(t, globalPath)

	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	inBuf := strings.NewReader("n\n")

	cmd := NewRootCmd(context.Background(), outBuf, errBuf)
	cmd.SetIn(inBuf)
	cmd.SetArgs([]string{"rules", "reset"})
	_ = cmd.Execute()

	// Rule should still exist.
	p2, err := policy.LoadCustomPolicy(globalPath)
	if err != nil {
		t.Fatalf("LoadCustomPolicy: %v", err)
	}
	if p2.TotalRules() != 1 {
		t.Errorf("expected rule to remain after reset cancellation, got %d rules", p2.TotalRules())
	}

	if !strings.Contains(outBuf.String(), "Cancelled") {
		t.Errorf("expected 'Cancelled' in output, got:\n%s", outBuf.String())
	}
}

// ─── TestRulesMultipleRulesOrdering ──────────────────────────────────────────

func TestRulesMultipleRulesOrdering(t *testing.T) {
	_, _, globalPath, projectPath := rulesTestEnv(t)

	// Add 2 global rules.
	gp := &policy.CustomPolicy{Version: "1"}
	_ = gp.AddRule("allow", "npm install *", "g1", "exec")
	_ = gp.AddRule("allow", "go test ./...", "g2", "exec")
	if err := policy.SaveCustomPolicy(globalPath, gp); err != nil {
		t.Fatalf("save global: %v", err)
	}

	// Add 1 project rule.
	_ = os.MkdirAll(filepath.Dir(projectPath), 0o755)
	pp := &policy.CustomPolicy{Version: "1"}
	_ = pp.AddRule("deny", "rm -rf *", "p1", "exec")
	if err := policy.SaveCustomPolicy(projectPath, pp); err != nil {
		t.Fatalf("save project: %v", err)
	}

	out, err := runRulesCmd(t, "rules", "--json")
	if err != nil {
		t.Fatalf("rules --json failed: %v", err)
	}

	var entries []map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &entries); err != nil {
		t.Fatalf("JSON parse: %v\nOutput:\n%s", err, out)
	}

	if len(entries) != 3 {
		t.Fatalf("expected 3 entries (2 global + 1 project), got %d", len(entries))
	}

	// Indices should be 1, 2, 3.
	for i, e := range entries {
		want := float64(i + 1)
		if got, _ := e["index"].(float64); got != want {
			t.Errorf("entry %d: index=%v, want %v", i, got, want)
		}
	}

	// First two should be global, last project.
	for i := 0; i < 2; i++ {
		if src, _ := entries[i]["source"].(string); src != "global" {
			t.Errorf("entry %d: expected source=global, got %q", i, src)
		}
	}
	if src, _ := entries[2]["source"].(string); src != "project" {
		t.Errorf("entry 2: expected source=project, got %q", src)
	}
}

// ─── TestRulesRemoveLastRuleInEntry ──────────────────────────────────────────

// Removing the last rule in an entry should also remove the empty entry.
func TestRulesRemoveLastRuleInEntry(t *testing.T) {
	_, _, globalPath, _ := rulesTestEnv(t)
	setupGlobalPolicy(t, globalPath) // 1 rule → 1 entry

	_, err := runRulesCmd(t, "rules", "remove", "1", "--force")
	if err != nil {
		t.Fatalf("rules remove 1 --force failed: %v", err)
	}

	gp, err := policy.LoadCustomPolicy(globalPath)
	if err != nil {
		t.Fatalf("LoadCustomPolicy: %v", err)
	}
	if len(gp.Policies) != 0 {
		t.Errorf("expected empty Policies slice after removing last rule, got %d entries", len(gp.Policies))
	}
}

// ─── TestRulesListSummaryCount ────────────────────────────────────────────────

func TestRulesListSummaryCount(t *testing.T) {
	_, _, globalPath, projectPath := rulesTestEnv(t)
	setupGlobalPolicy(t, globalPath)
	setupProjectPolicy(t, projectPath)

	out, err := runRulesCmd(t, "rules")
	if err != nil {
		t.Fatalf("rules failed: %v", err)
	}

	// The output should mention "2" (total custom rule count).
	if !strings.Contains(out, "2") {
		t.Errorf("expected total count '2' in summary, got:\n%s", out)
	}
}

// ─── TestRulesJSONActionField ─────────────────────────────────────────────────

func TestRulesJSONActionField(t *testing.T) {
	_, _, globalPath, projectPath := rulesTestEnv(t)
	setupGlobalPolicy(t, globalPath)   // action: allow
	setupProjectPolicy(t, projectPath) // action: deny

	out, err := runRulesCmd(t, "rules", "--json")
	if err != nil {
		t.Fatalf("rules --json failed: %v", err)
	}

	var entries []map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &entries); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}

	action0, _ := entries[0]["action"].(string)
	action1, _ := entries[1]["action"].(string)

	if action0 != "allow" {
		t.Errorf("entry[0].action = %q, want allow", action0)
	}
	if action1 != "deny" {
		t.Errorf("entry[1].action = %q, want deny", action1)
	}
}

// ─── TestRulesRemoveOutOfRangeEmpty ──────────────────────────────────────────

func TestRulesRemoveOutOfRangeEmpty(t *testing.T) {
	_, _, _, _ = rulesTestEnv(t)
	// No rules exist.

	_, err := runRulesCmd(t, "rules", "remove", "1", "--force")
	if err == nil {
		t.Fatal("expected error when removing from empty policy")
	}
}
