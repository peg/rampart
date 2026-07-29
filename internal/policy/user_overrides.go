package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/peg/rampart/internal/filetxn"
	"github.com/peg/rampart/internal/securefile"
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

// stringOrSlice keeps user-overrides.yaml compatible with older Rampart
// releases that emitted a scalar tool while current releases emit a list.
type stringOrSlice []string

func (s *stringOrSlice) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		*s = []string{value.Value}
		return nil
	case yaml.SequenceNode:
		return value.Decode((*[]string)(s))
	default:
		return fmt.Errorf("policy: tool must be a string or list of strings")
	}
}

type UserOverrideMatch struct {
	Tool stringOrSlice `yaml:"tool"`
}

type UserOverrideRule struct {
	When    UserOverrideWhen `yaml:"when"`
	Action  string           `yaml:"action"`
	Message string           `yaml:"message"`
}

type UserOverrideWhen struct {
	CommandMatches []string `yaml:"command_matches,omitempty,flow"`
	PathMatches    []string `yaml:"path_matches,omitempty,flow"`
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

func saveUserOverridesPolicyLocked(path string, p *UserOverridesPolicy) error {
	if err := validateUserOverridesPolicy(p); err != nil {
		return err
	}
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
	if err := securefile.OwnerOnly(tmpPath); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("policy: secure temp file: %w", err)
	}
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

// UserOverrideResult describes the durable rule selected by
// EnsureUserOverrideAllow.
type UserOverrideResult struct {
	Name    string
	Pattern string
	Created bool
}

// UserOverrideRuleName returns the stable identity used for an allow carve-out.
func UserOverrideRuleName(tool, pattern string) string {
	hashInput := pattern
	if tool != "exec" {
		hashInput = tool + "\x00" + pattern
	}
	return fmt.Sprintf("user-allow-%s", HashPattern(hashInput))
}

// EnsureUserOverrideAllow stores an explicit glob pattern supplied by a policy
// author. Automatic approval flows must call BuildExactAllowPattern first.
// Concurrent callers coordinate through the policy file's cross-process lock.
func EnsureUserOverrideAllow(path, tool, pattern, message string) (UserOverrideResult, error) {
	var result UserOverrideResult
	tool = strings.TrimSpace(tool)
	pattern = strings.TrimSpace(pattern)
	if tool == "" {
		return result, fmt.Errorf("policy: allow rule requires a tool")
	}
	if pattern == "" {
		return result, fmt.Errorf("policy: allow rule requires a non-empty pattern")
	}
	if err := ValidateGlobPatterns("allow", []string{pattern}); err != nil {
		return result, fmt.Errorf("policy: invalid allow pattern: %w", err)
	}
	switch tool {
	case "exec", "read", "write", "edit":
		// Supported by exact command/path conditions below.
	default:
		return result, fmt.Errorf("policy: automatic allow is unsupported for tool %q; author an explicit policy instead", tool)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return result, fmt.Errorf("policy: create dir: %w", err)
	}
	result = UserOverrideResult{
		Name:    UserOverrideRuleName(tool, pattern),
		Pattern: pattern,
	}
	err := filetxn.WithLock(path, func() error {
		p, err := LoadUserOverridesPolicy(path)
		if err != nil {
			return err
		}
		if err := validateUserOverridesPolicy(p); err != nil {
			return err
		}
		for _, entry := range p.Policies {
			if entry.Name == result.Name {
				return nil
			}
		}
		if message == "" {
			message = "User allowed (always)"
		}
		when := UserOverrideWhen{}
		if tool == "exec" {
			when.CommandMatches = []string{pattern}
		} else {
			when.PathMatches = []string{pattern}
		}
		p.Policies = append(p.Policies, UserOverrideEntry{
			Name:  result.Name,
			Match: UserOverrideMatch{Tool: []string{BuildExactAllowPattern(tool)}},
			Rules: []UserOverrideRule{{
				When:    when,
				Action:  "allow",
				Message: message,
			}},
		})
		if err := validateUserOverridesPolicy(p); err != nil {
			return err
		}
		if err := saveUserOverridesPolicyLocked(path, p); err != nil {
			return err
		}
		result.Created = true
		return nil
	})
	if err != nil {
		return result, err
	}
	return result, nil
}

func validateUserOverridesPolicy(p *UserOverridesPolicy) error {
	if p == nil {
		return fmt.Errorf("policy: user overrides config is nil")
	}
	seen := make(map[string]struct{}, len(p.Policies))
	for index, entry := range p.Policies {
		name := strings.TrimSpace(entry.Name)
		if name == "" {
			return fmt.Errorf("policy: user override at index %d has no name", index)
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("policy: duplicate user override name %q", name)
		}
		seen[name] = struct{}{}
		if err := ValidateGlobPatterns(fmt.Sprintf("policy %d match.tool", index), []string(entry.Match.Tool)); err != nil {
			return fmt.Errorf("policy: invalid user override: %w", err)
		}
		for ruleIndex, rule := range entry.Rules {
			if err := ValidateGlobPatterns(fmt.Sprintf("policy %d rule %d command_matches", index, ruleIndex), rule.When.CommandMatches); err != nil {
				return fmt.Errorf("policy: invalid user override: %w", err)
			}
			if err := ValidateGlobPatterns(fmt.Sprintf("policy %d rule %d path_matches", index, ruleIndex), rule.When.PathMatches); err != nil {
				return fmt.Errorf("policy: invalid user override: %w", err)
			}
		}
	}
	return nil
}

// AddUserOverrideAllow preserves the original convenience API for CLI callers
// that only need the normalized pattern.
func AddUserOverrideAllow(path, tool, pattern, message string) (string, error) {
	result, err := EnsureUserOverrideAllow(path, tool, pattern, message)
	return result.Pattern, err
}
