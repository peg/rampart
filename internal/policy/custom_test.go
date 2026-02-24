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
	"testing"
	"time"

	custompolicy "github.com/peg/rampart/internal/policy"
)

func TestLoadCustomPolicy_NotExist(t *testing.T) {
	cp, err := custompolicy.LoadCustomPolicy(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	if err != nil {
		t.Fatalf("expected no error for missing file, got: %v", err)
	}
	if cp.Version != "1" {
		t.Errorf("expected version 1, got %q", cp.Version)
	}
	if len(cp.Rules) != 0 {
		t.Errorf("expected empty rules, got %d", len(cp.Rules))
	}
}

func TestLoadCustomPolicy_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.yaml")

	now := time.Now().UTC().Truncate(time.Second)
	original := &custompolicy.CustomPolicy{
		Version: "1",
		Rules: []custompolicy.CustomRule{
			{Action: "allow", Tool: "exec", Pattern: "npm install *", AddedAt: now},
			{Action: "deny", Tool: "write", Pattern: "*.secret", AddedAt: now.Add(-time.Hour)},
		},
	}

	if err := custompolicy.SaveCustomPolicy(path, original); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	loaded, err := custompolicy.LoadCustomPolicy(path)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	if loaded.Version != original.Version {
		t.Errorf("version mismatch: want %q, got %q", original.Version, loaded.Version)
	}
	if len(loaded.Rules) != len(original.Rules) {
		t.Fatalf("rule count mismatch: want %d, got %d", len(original.Rules), len(loaded.Rules))
	}
	for i, r := range loaded.Rules {
		orig := original.Rules[i]
		if r.Action != orig.Action {
			t.Errorf("rule[%d].Action: want %q, got %q", i, orig.Action, r.Action)
		}
		if r.Tool != orig.Tool {
			t.Errorf("rule[%d].Tool: want %q, got %q", i, orig.Tool, r.Tool)
		}
		if r.Pattern != orig.Pattern {
			t.Errorf("rule[%d].Pattern: want %q, got %q", i, orig.Pattern, r.Pattern)
		}
	}
}

func TestSaveCustomPolicy_CreatesParentDirs(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b", "c", "custom.yaml")

	cp := &custompolicy.CustomPolicy{Version: "1"}
	if err := custompolicy.SaveCustomPolicy(nested, cp); err != nil {
		t.Fatalf("expected parent dirs to be created, got error: %v", err)
	}

	if _, err := os.Stat(nested); err != nil {
		t.Errorf("file not created: %v", err)
	}
}

func TestAppendRule(t *testing.T) {
	cp := &custompolicy.CustomPolicy{Version: "1"}
	rule := custompolicy.CustomRule{Action: "allow", Tool: "exec", Pattern: "ls *"}

	result := custompolicy.AppendRule(cp, rule)
	if len(result.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(result.Rules))
	}
	if result.Rules[0].Pattern != "ls *" {
		t.Errorf("unexpected pattern: %q", result.Rules[0].Pattern)
	}
	// AddedAt should have been set automatically.
	if result.Rules[0].AddedAt.IsZero() {
		t.Error("expected AddedAt to be set automatically")
	}
}

func TestAppendRule_PreservesExistingAddedAt(t *testing.T) {
	cp := &custompolicy.CustomPolicy{Version: "1"}
	fixed := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	rule := custompolicy.CustomRule{Action: "deny", Tool: "write", Pattern: "*.env", AddedAt: fixed}

	custompolicy.AppendRule(cp, rule)
	if !cp.Rules[0].AddedAt.Equal(fixed) {
		t.Errorf("expected AddedAt to be preserved, got %v", cp.Rules[0].AddedAt)
	}
}

func TestRemoveRuleAt_Valid(t *testing.T) {
	cp := &custompolicy.CustomPolicy{
		Version: "1",
		Rules: []custompolicy.CustomRule{
			{Action: "allow", Tool: "exec", Pattern: "a"},
			{Action: "deny", Tool: "exec", Pattern: "b"},
			{Action: "allow", Tool: "exec", Pattern: "c"},
		},
	}

	if err := custompolicy.RemoveRuleAt(cp, 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cp.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(cp.Rules))
	}
	if cp.Rules[0].Pattern != "a" || cp.Rules[1].Pattern != "c" {
		t.Errorf("unexpected rules after removal: %+v", cp.Rules)
	}
}

func TestRemoveRuleAt_OutOfRange(t *testing.T) {
	cp := &custompolicy.CustomPolicy{
		Version: "1",
		Rules:   []custompolicy.CustomRule{{Action: "allow", Tool: "exec", Pattern: "x"}},
	}
	if err := custompolicy.RemoveRuleAt(cp, 5); err == nil {
		t.Error("expected error for out-of-range index")
	}
}

func TestRemoveRuleAt_NegativeIndex(t *testing.T) {
	cp := &custompolicy.CustomPolicy{
		Version: "1",
		Rules:   []custompolicy.CustomRule{{Action: "allow", Tool: "exec", Pattern: "x"}},
	}
	if err := custompolicy.RemoveRuleAt(cp, -1); err == nil {
		t.Error("expected error for negative index")
	}
}

func TestGlobalCustomPath(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	path, err := custompolicy.GlobalCustomPath()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !filepath.IsAbs(path) {
		t.Errorf("expected absolute path, got %q", path)
	}
	if filepath.Base(path) != "custom.yaml" {
		t.Errorf("expected filename custom.yaml, got %q", filepath.Base(path))
	}
}

func TestProjectCustomPath(t *testing.T) {
	path := custompolicy.ProjectCustomPath()
	if path == "" {
		t.Error("expected non-empty project path")
	}
	if filepath.Base(path) != "custom.yaml" {
		t.Errorf("expected filename custom.yaml, got %q", filepath.Base(path))
	}
}
