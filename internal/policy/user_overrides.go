package policy

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/peg/rampart/internal/filetxn"
	"gopkg.in/yaml.v3"
)

type UserOverridesPolicy struct {
	Policies []UserOverrideEntry `yaml:"policies"`
}

type UserOverrideEntry struct {
	Name  string             `yaml:"name"`
	Match UserOverrideMatch  `yaml:"match"`
	Rules []UserOverrideRule `yaml:"rules"`
}

type UserOverrideMatch struct {
	Tool []string `yaml:"tool"`
}

type UserOverrideRule struct {
	When    UserOverrideWhen `yaml:"when"`
	Action  string           `yaml:"action"`
	Message string           `yaml:"message"`
}

type UserOverrideWhen struct {
	CommandMatches []string `yaml:"command_matches,omitempty,flow"`
}

func LoadUserOverridesPolicy(path string) (*UserOverridesPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &UserOverridesPolicy{}, nil
		}
		return nil, fmt.Errorf("policy: read %s: %w", path, err)
	}

	var p UserOverridesPolicy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("policy: parse %s: %w", path, err)
	}
	return &p, nil
}

func SaveUserOverridesPolicy(path string, p *UserOverridesPolicy) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("policy: create dir %s: %w", dir, err)
	}
	return filetxn.WithLock(path, func() error {
		return saveUserOverridesPolicyLocked(path, p)
	})
}

func saveUserOverridesPolicyLocked(path string, p *UserOverridesPolicy) error {
	dir := filepath.Dir(path)
	data, err := yaml.Marshal(p)
	if err != nil {
		return fmt.Errorf("policy: marshal: %w", err)
	}

	header := "# Rampart user override policies\n# Auto-generated entries are added here when you create durable allow carve-outs\n# This file is never overwritten by upgrades or rampart setup\n"
	out := append([]byte(header), data...)

	tmp, err := os.CreateTemp(dir, ".user-overrides-*.yaml")
	if err != nil {
		return fmt.Errorf("policy: create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("policy: write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("policy: sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("policy: close temp file: %w", err)
	}
	if err := filetxn.Replace(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("policy: rename %s -> %s: %w", tmpPath, path, err)
	}
	return nil
}

func AddUserOverrideAllow(path, tool, rawCommand, message string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("policy: create dir: %w", err)
	}
	pattern := BuildAllowPattern(rawCommand)
	err := filetxn.WithLock(path, func() error {
		p, err := LoadUserOverridesPolicy(path)
		if err != nil {
			return err
		}
		ruleName := fmt.Sprintf("user-allow-%s", HashPattern(pattern))
		for _, entry := range p.Policies {
			if entry.Name == ruleName {
				return nil
			}
		}
		if message == "" {
			message = "User allowed (always)"
		}
		p.Policies = append(p.Policies, UserOverrideEntry{
			Name:  ruleName,
			Match: UserOverrideMatch{Tool: []string{tool}},
			Rules: []UserOverrideRule{{
				When:    UserOverrideWhen{CommandMatches: []string{pattern}},
				Action:  "allow",
				Message: message,
			}},
		})
		return saveUserOverridesPolicyLocked(path, p)
	})
	if err != nil {
		return "", err
	}
	return pattern, nil
}
