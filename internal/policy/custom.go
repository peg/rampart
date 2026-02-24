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

// Package policy provides utilities for managing user-editable policy files
// (custom.yaml) on behalf of CLI commands like `rampart allow` and `rampart block`.
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// CustomPolicy is the top-level structure of a user-managed custom.yaml file.
// It is a valid Rampart policy document that can be loaded by the engine.
type CustomPolicy struct {
	Version  string        `yaml:"version"`
	Policies []CustomEntry `yaml:"policies,omitempty"`
}

// CustomEntry is a named policy block within custom.yaml.
type CustomEntry struct {
	Name     string       `yaml:"name"`
	Priority int          `yaml:"priority,omitempty"`
	Match    CustomMatch  `yaml:"match,omitempty"`
	Rules    []CustomRule `yaml:"rules"`
}

// CustomMatch defines which tools this entry applies to.
type CustomMatch struct {
	Tool []string `yaml:"tool,omitempty"`
}

// CustomRule is a single allow/deny rule.
type CustomRule struct {
	Action  string          `yaml:"action"`
	When    CustomCondition `yaml:"when,omitempty"`
	Message string          `yaml:"message,omitempty"`
	// Added records when the rule was created; not used by the policy engine.
	Added time.Time `yaml:"added,omitempty"`
}

// CustomCondition holds the match conditions for a rule.
type CustomCondition struct {
	CommandMatches []string `yaml:"command_matches,omitempty"`
	PathMatches    []string `yaml:"path_matches,omitempty"`
}

// LoadCustomPolicy reads custom.yaml from path. If the file does not exist,
// it returns an empty (but valid) CustomPolicy ready to be populated.
func LoadCustomPolicy(path string) (*CustomPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &CustomPolicy{Version: "1"}, nil
		}
		return nil, fmt.Errorf("policy: read %s: %w", path, err)
	}

	var p CustomPolicy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("policy: parse %s: %w", path, err)
	}
	if p.Version == "" {
		p.Version = "1"
	}
	return &p, nil
}

// SaveCustomPolicy writes p to path, creating parent directories as needed.
// The file is written atomically (temp file + rename) to prevent corruption.
func SaveCustomPolicy(path string, p *CustomPolicy) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("policy: create dir %s: %w", dir, err)
	}

	data, err := yaml.Marshal(p)
	if err != nil {
		return fmt.Errorf("policy: marshal: %w", err)
	}

	header := "# Rampart custom policy — managed by `rampart allow` / `rampart block`.\n" +
		"# You can edit this file manually. Changes take effect on reload.\n\n"
	out := append([]byte(header), data...)

	// Write to temp file first, then rename for atomicity
	tmp, err := os.CreateTemp(dir, ".custom-*.yaml")
	if err != nil {
		return fmt.Errorf("policy: create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("policy: write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("policy: close temp file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("policy: rename %s -> %s: %w", tmpPath, path, err)
	}
	return nil
}

// AddRule adds a new rule to the policy, appending it to the appropriate
// named entry (creating that entry if it does not yet exist).
//
//   - action:  "allow" or "deny"
//   - pattern: a glob pattern for the command or file path
//   - message: a human-readable description (may be empty)
//   - tool:    "exec", "read", "write", "edit", or "" for auto-detection
func (p *CustomPolicy) AddRule(action, pattern, message, tool string) error {
	if strings.TrimSpace(pattern) == "" {
		return fmt.Errorf("pattern cannot be empty")
	}

	// Determine if this is a path-based or command-based rule.
	// Explicit tool flag overrides auto-detection.
	var usePathCondition bool
	var matchTools []string

	if tool != "" {
		// Explicit tool specified — use it
		switch tool {
		case "exec":
			usePathCondition = false
			matchTools = []string{"exec"}
		case "read", "write", "edit":
			usePathCondition = true
			matchTools = []string{tool}
		default:
			// "path" or unknown — default to read/write/edit
			usePathCondition = true
			matchTools = []string{"read", "write", "edit"}
		}
	} else {
		// Auto-detect from pattern
		if IsPathPattern(pattern) {
			usePathCondition = true
			matchTools = []string{"read", "write", "edit"}
		} else {
			usePathCondition = false
			matchTools = []string{"exec"}
		}
	}

	// Build the condition based on determined type.
	var cond CustomCondition
	if usePathCondition {
		cond = CustomCondition{PathMatches: []string{pattern}}
	} else {
		cond = CustomCondition{CommandMatches: []string{pattern}}
	}

	// Pick a stable entry name so rules of the same type are grouped.
	entryName := entryName(action, usePathCondition)

	for i := range p.Policies {
		if p.Policies[i].Name == entryName {
			p.Policies[i].Rules = append(p.Policies[i].Rules, CustomRule{
				Action:  action,
				When:    cond,
				Message: message,
				Added:   time.Now().UTC(),
			})
			return nil
		}
	}

	// Entry not found — create a new one.
	p.Policies = append(p.Policies, CustomEntry{
		Name:  entryName,
		Match: CustomMatch{Tool: matchTools},
		Rules: []CustomRule{
			{
				Action:  action,
				When:    cond,
				Message: message,
				Added:   time.Now().UTC(),
			},
		},
	})
	return nil
}

// TotalRules returns the total number of rules across all entries.
func (p *CustomPolicy) TotalRules() int {
	n := 0
	for _, e := range p.Policies {
		n += len(e.Rules)
	}
	return n
}

// IsPathPattern returns true when the pattern looks like a file/directory path
// rather than a shell command. URLs are NOT considered paths.
func IsPathPattern(pattern string) bool {
	// URLs contain slashes but are not file paths
	if strings.HasPrefix(pattern, "http://") || strings.HasPrefix(pattern, "https://") {
		return false
	}
	// Commands that start with common tools followed by URLs are not paths
	// e.g., "curl https://example.com" should be exec, not path
	for _, prefix := range []string{"curl ", "wget ", "fetch "} {
		if strings.HasPrefix(pattern, prefix) {
			return false
		}
	}
	return strings.HasPrefix(pattern, "/") ||
		strings.HasPrefix(pattern, "~/") ||
		strings.HasPrefix(pattern, "**/") ||
		strings.Contains(pattern, "/")
}

// DetectTool returns the likely tool type for a pattern ("exec" or "path").
func DetectTool(pattern string) string {
	if IsPathPattern(pattern) {
		return "path"
	}
	return "exec"
}

// entryName returns a stable, human-readable name for an entry bucket.
func entryName(action string, isPath bool) string {
	kind := "commands"
	if isPath {
		kind = "paths"
	}
	return fmt.Sprintf("custom-%s-%s", action, kind)
}

// GlobalCustomPath returns the path to the global custom policy file.
// This is ~/.rampart/policies/custom.yaml.
func GlobalCustomPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("policy: cannot determine home dir: %w", err)
	}
	return filepath.Join(home, ".rampart", "policies", "custom.yaml"), nil
}

// ProjectCustomPath returns the path to project-local custom policy.
// This is .rampart/policy.yaml in the current directory.
func ProjectCustomPath() string {
	return filepath.Join(".rampart", "policy.yaml")
}

// FlatRule is a simplified view of a rule for display purposes.
// It flattens the nested structure into a single row.
type FlatRule struct {
	Action   string
	Tool     string
	Pattern  string
	Message  string
	AddedAt  time.Time
	EntryIdx int // Index in Policies array
	RuleIdx  int // Index in Rules array within entry
}

// FlattenRules returns all rules as a flat list for display.
func (p *CustomPolicy) FlattenRules() []FlatRule {
	var result []FlatRule
	for ei, entry := range p.Policies {
		// Determine tool from match
		tool := "exec"
		if len(entry.Match.Tool) > 0 {
			tool = entry.Match.Tool[0]
		}

		for ri, rule := range entry.Rules {
			// Extract pattern from condition
			pattern := ""
			if len(rule.When.CommandMatches) > 0 {
				pattern = rule.When.CommandMatches[0]
			} else if len(rule.When.PathMatches) > 0 {
				pattern = rule.When.PathMatches[0]
				if tool == "exec" {
					tool = "read" // Path-based rules are typically read/write
				}
			}

			result = append(result, FlatRule{
				Action:   rule.Action,
				Tool:     tool,
				Pattern:  pattern,
				Message:  rule.Message,
				AddedAt:  rule.Added,
				EntryIdx: ei,
				RuleIdx:  ri,
			})
		}
	}
	return result
}

// RemoveRuleAt removes the rule at the given flat index.
// Returns an error if the index is out of range.
func RemoveRuleAt(p *CustomPolicy, flatIdx int) error {
	if flatIdx < 0 {
		return fmt.Errorf("policy: invalid index %d", flatIdx)
	}

	// Walk through to find the rule at flatIdx
	idx := 0
	for ei := range p.Policies {
		for ri := range p.Policies[ei].Rules {
			if idx == flatIdx {
				// Found it - remove this rule
				rules := p.Policies[ei].Rules
				p.Policies[ei].Rules = append(rules[:ri], rules[ri+1:]...)

				// If entry is now empty, remove the entry
				if len(p.Policies[ei].Rules) == 0 {
					p.Policies = append(p.Policies[:ei], p.Policies[ei+1:]...)
				}
				return nil
			}
			idx++
		}
	}

	return fmt.Errorf("policy: index %d out of range (have %d rules)", flatIdx, idx)
}
