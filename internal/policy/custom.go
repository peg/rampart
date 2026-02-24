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

// Package policy provides types and helpers for managing user-defined custom
// policy rules created via `rampart allow` / `rampart block`.
package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// CustomRule represents a single user-added allow or deny rule.
type CustomRule struct {
	// Action is "allow" or "deny".
	Action string `yaml:"action"`

	// Tool is the tool category this rule applies to (e.g. "exec", "write", "*").
	Tool string `yaml:"tool"`

	// Pattern is a glob pattern matched against the tool's primary argument
	// (command, path, URL, etc.).
	Pattern string `yaml:"pattern"`

	// AddedAt records when the rule was created.
	AddedAt time.Time `yaml:"added_at"`
}

// CustomPolicy is the serialised form of a custom rules file.
type CustomPolicy struct {
	// Version is the file format version. Currently "1".
	Version string `yaml:"version"`

	// Rules is the ordered list of custom rules.
	Rules []CustomRule `yaml:"rules,omitempty"`
}

// GlobalCustomPath returns the filesystem path to the global custom-rules file
// (~/.rampart/policies/custom.yaml). It returns an error when the user home
// directory cannot be determined.
func GlobalCustomPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("custom policy: resolve home dir: %w", err)
	}
	return filepath.Join(home, ".rampart", "policies", "custom.yaml"), nil
}

// ProjectCustomPath returns the path to the project-level custom-rules file
// (.rampart/custom.yaml) relative to the current working directory.
func ProjectCustomPath() string {
	return filepath.Join(".rampart", "custom.yaml")
}

// LoadCustomPolicy reads a CustomPolicy from path. If the file does not exist
// the function returns an empty policy (no rules) without an error.
func LoadCustomPolicy(path string) (*CustomPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &CustomPolicy{Version: "1"}, nil
		}
		return nil, fmt.Errorf("custom policy: read %s: %w", path, err)
	}

	var cp CustomPolicy
	if err := yaml.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("custom policy: parse %s: %w", path, err)
	}
	if cp.Version == "" {
		cp.Version = "1"
	}
	return &cp, nil
}

// SaveCustomPolicy writes cp to path, creating any missing parent directories.
func SaveCustomPolicy(path string, cp *CustomPolicy) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("custom policy: create dirs for %s: %w", path, err)
	}
	data, err := yaml.Marshal(cp)
	if err != nil {
		return fmt.Errorf("custom policy: marshal: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("custom policy: write %s: %w", path, err)
	}
	return nil
}

// AppendRule adds rule to cp and returns the updated policy.
func AppendRule(cp *CustomPolicy, rule CustomRule) *CustomPolicy {
	if rule.AddedAt.IsZero() {
		rule.AddedAt = time.Now().UTC()
	}
	cp.Rules = append(cp.Rules, rule)
	return cp
}

// RemoveRuleAt removes the rule at zero-based index idx from cp.
// It returns an error when idx is out of range.
func RemoveRuleAt(cp *CustomPolicy, idx int) error {
	if idx < 0 || idx >= len(cp.Rules) {
		return fmt.Errorf("custom policy: index %d out of range (have %d rules)", idx, len(cp.Rules))
	}
	cp.Rules = append(cp.Rules[:idx], cp.Rules[idx+1:]...)
	return nil
}
