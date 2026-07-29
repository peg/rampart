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

package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	policyutil "github.com/peg/rampart/internal/policy"
	"github.com/peg/rampart/internal/securefile"
	"gopkg.in/yaml.v3"
)

// DefaultAutoAllowedPath returns the default path for auto-generated allow rules.
func DefaultAutoAllowedPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".rampart", "policies", "auto-allowed.yaml")
}

// dangerousCommandPrefixes lists command prefixes that should NEVER be
// generalized. These commands are kept exact to prevent accidental
// auto-allow of destructive operations.
var dangerousCommandPrefixes = []string{
	"systemctl stop", "systemctl disable",
	"rm -rf", "rm -f", "rm",
	"chmod", "chown",
	"kill", "killall", "pkill",
	"dd",
	"mkfs", "fdisk",
	"reboot", "shutdown", "halt",
}

// isDangerousCommand returns true if the command starts with a dangerous prefix.
func isDangerousCommand(tokens []string) bool {
	joined := strings.Join(tokens, " ")
	for _, prefix := range dangerousCommandPrefixes {
		if joined == prefix || strings.HasPrefix(joined, prefix+" ") {
			return true
		}
	}
	return false
}

// GeneralizeCommand takes a full command string and generalizes it for
// policy use. It keeps the first 1-2 meaningful tokens and wildcards the rest.
// Dangerous commands (rm, chmod, kill, etc.) are never generalized.
// Single-token commands are kept exact.
//
// Examples:
//
//	"kubectl apply -f deployment.yaml" → "kubectl apply *"
//	"npm install express" → "npm install *"
//	"git push origin main" → "git push *"
//	"ls" → "ls"
//	"rm -rf /tmp/build" → "rm -rf /tmp/build"
func GeneralizeCommand(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return "*"
	}

	// Split on whitespace.
	tokens := strings.Fields(cmd)

	// Single-token commands: keep exact.
	if len(tokens) == 1 {
		return tokens[0]
	}

	// Dangerous commands: keep exact, never generalize.
	if isDangerousCommand(tokens) {
		return strings.Join(tokens, " ")
	}

	if len(tokens) <= 2 {
		// Short commands: keep as-is plus wildcard (no space before glob so
		// the exact command without extra args also matches).
		return strings.Join(tokens, " ") + "*"
	}

	// Keep first two tokens, wildcard the rest.
	return tokens[0] + " " + tokens[1] + "*"
}

// GenerateAllowRule creates a narrowly scoped Policy from a ToolCall. Automatic
// approval persistence is exact by default: it never inserts wildcards, and
// literal glob metacharacters in commands and paths are escaped.
func GenerateAllowRule(call ToolCall) (Policy, error) {
	return generateAllowRuleAt(call, time.Now().UTC())
}

func generateAllowRuleAt(call ToolCall, now time.Time) (Policy, error) {
	tool := strings.TrimSpace(call.Tool)
	if tool == "" {
		return Policy{}, fmt.Errorf("persist: allow rule requires a tool")
	}

	now = now.UTC()
	var ruleName string
	var exactPattern string
	var rule Rule

	switch tool {
	case "exec":
		cmd := strings.TrimSpace(call.Command())
		if cmd == "" {
			return Policy{}, fmt.Errorf("persist: exec allow rule requires a command")
		}
		exactPattern = policyutil.BuildExactAllowPattern(cmd)
		if err := policyutil.ValidateGlobPatterns("command_matches", []string{exactPattern}); err != nil {
			return Policy{}, fmt.Errorf("persist: exact command cannot be represented safely: %w", err)
		}
		tokens := strings.Fields(cmd)
		nameParts := tokens
		if len(nameParts) > 2 {
			nameParts = nameParts[:2]
		}
		ruleName = fmt.Sprintf("auto-allow-%s", sanitizeName(strings.Join(nameParts, "-")))
		rule = Rule{
			Action: "allow",
			When: Condition{
				CommandMatches: []string{exactPattern},
			},
		}

	case "read", "write", "edit":
		path := call.Path()
		if strings.TrimSpace(path) == "" {
			return Policy{}, fmt.Errorf("persist: %s allow rule requires a path", tool)
		}
		action := tool
		exactPattern = policyutil.BuildExactAllowPattern(path)
		if err := policyutil.ValidateGlobPatterns("path_matches", []string{exactPattern}); err != nil {
			return Policy{}, fmt.Errorf("persist: exact path cannot be represented safely: %w", err)
		}
		ruleName = fmt.Sprintf("auto-allow-%s-%s", action, sanitizeName(path))
		rule = Rule{
			Action: "allow",
			When: Condition{
				PathMatches: []string{exactPattern},
			},
		}

	default:
		return Policy{}, fmt.Errorf("persist: automatic allow is unsupported for tool %q; author an explicit policy instead", tool)
	}

	generated := Policy{
		Name: fmt.Sprintf("%s-%s-%s", ruleName, now.Format("20060102T150405Z"), policyutil.ExactPatternHash(tool, exactPattern)),
		Match: Match{
			Tool: StringOrSlice{policyutil.BuildExactAllowPattern(tool)},
		},
		Rules: []Rule{rule},
	}
	if err := validatePolicy(generated, make(map[string]*regexp.Regexp)); err != nil {
		return Policy{}, fmt.Errorf("persist: generated policy is invalid: %w", err)
	}
	return generated, nil
}

// MigrateAllowRuleGlobs rewrites old-format command_matches patterns that
// have a space before the trailing glob ("cmd arg *" → "cmd arg*").
// This migration is needed after the v0.9.7 GeneralizeCommand fix.
// Safe to call multiple times — only rewrites if patterns are found.
func MigrateAllowRuleGlobs(policyPath string) (int, error) {
	if _, err := os.Stat(policyPath); os.IsNotExist(err) {
		return 0, nil
	}
	var migrated int
	err := withPolicyFileLock(policyPath, func() error {
		var err error
		migrated, err = migrateAllowRuleGlobsLocked(policyPath)
		return err
	})
	return migrated, err
}

func migrateAllowRuleGlobsLocked(policyPath string) (int, error) {
	data, err := os.ReadFile(policyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("persist: read %s: %w", policyPath, err)
	}

	var cfg Config
	if err := safeUnmarshal(data, &cfg); err != nil {
		return 0, fmt.Errorf("persist: parse %s: %w", policyPath, err)
	}

	migrated := 0
	for pi := range cfg.Policies {
		for ri := range cfg.Policies[pi].Rules {
			for ci, pat := range cfg.Policies[pi].Rules[ri].When.CommandMatches {
				// Rewrite "cmd arg *" → "cmd arg*" (space before trailing glob only)
				if strings.HasSuffix(pat, " *") {
					cfg.Policies[pi].Rules[ri].When.CommandMatches[ci] = pat[:len(pat)-2] + "*"
					migrated++
				}
			}
		}
	}

	if migrated == 0 {
		return 0, nil
	}

	if err := writeConfigAtomic(policyPath, &cfg); err != nil {
		return 0, fmt.Errorf("persist: write migrated %s: %w", policyPath, err)
	}
	return migrated, nil
}

// AppendAllowRule generates an allow rule from a ToolCall and appends it
// to the auto-allowed policy file. Creates the file and directories if needed.
func AppendAllowRule(policyPath string, call ToolCall) error {
	policy, err := GenerateAllowRule(call)
	if err != nil {
		return err
	}
	// Ensure directory exists.
	dir := filepath.Dir(policyPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("persist: create policy dir: %w", err)
	}
	return withPolicyFileLock(policyPath, func() error {
		return appendAllowRuleLocked(policyPath, policy)
	})
}

// RemoveAllowRule removes a named rule from an auto-generated policy using the
// same cross-process transaction as AppendAllowRule. It returns whether a rule
// was removed and the number of rules left in the file.
func RemoveAllowRule(policyPath, name string) (bool, int, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return false, 0, fmt.Errorf("persist: rule name is required")
	}

	removed := false
	remaining := 0
	err := withPolicyFileLock(policyPath, func() error {
		data, err := os.ReadFile(policyPath)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return fmt.Errorf("persist: read policy file: %w", err)
		}
		var cfg Config
		if err := safeUnmarshal(data, &cfg); err != nil {
			return fmt.Errorf("persist: parse existing policy: %w", err)
		}

		for index := range cfg.Policies {
			if cfg.Policies[index].Name != name {
				continue
			}
			cfg.Policies = append(cfg.Policies[:index], cfg.Policies[index+1:]...)
			removed = true
			break
		}
		remaining = len(cfg.Policies)
		if !removed {
			return nil
		}
		if remaining > 0 {
			return writeConfigAtomic(policyPath, &cfg)
		}
		if err := os.Remove(policyPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("persist: remove empty policy file: %w", err)
		}
		if err := syncPolicyDir(filepath.Dir(policyPath)); err != nil {
			return fmt.Errorf("persist: sync policy directory: %w", err)
		}
		return nil
	})
	return removed, remaining, err
}

func appendAllowRuleLocked(policyPath string, policy Policy) error {
	// Load existing config or create new one.
	var cfg Config
	data, err := os.ReadFile(policyPath)
	if err == nil {
		if err := safeUnmarshal(data, &cfg); err != nil {
			return fmt.Errorf("persist: parse existing policy: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("persist: read policy file: %w", err)
	}

	if cfg.Version == "" {
		cfg.Version = "1"
		cfg.DefaultAction = "deny"
	}
	if err := cfg.validate(); err != nil {
		return fmt.Errorf("persist: validate existing policy: %w", err)
	}

	// Dedup: skip if an identical rule already exists (same tool + command/path pattern).
	for _, existing := range cfg.Policies {
		if len(existing.Match.Tool) > 0 && len(policy.Match.Tool) > 0 &&
			existing.Match.Tool[0] == policy.Match.Tool[0] &&
			len(existing.Rules) > 0 && len(policy.Rules) > 0 &&
			conditionsEqual(existing.Rules[0].When, policy.Rules[0].When) {
			return nil // already exists
		}
	}

	cfg.Policies = append(cfg.Policies, policy)

	return writeConfigAtomic(policyPath, &cfg)
}

// sanitizeName converts a string to a safe policy name component.
func sanitizeName(s string) string {
	s = strings.TrimSpace(s)
	replacer := strings.NewReplacer(
		"/", "-",
		"\\", "-",
		" ", "-",
		".", "-",
		":", "-",
		"*", "star",
	)
	name := replacer.Replace(s)
	// Remove leading/trailing dashes.
	name = strings.Trim(name, "-")
	if name == "" {
		return "unknown"
	}
	if len(name) > 50 {
		name = name[:50]
	}
	return name
}

// conditionsEqual checks if two Conditions match the same patterns.
func conditionsEqual(a, b Condition) bool {
	return slicesEqual(a.CommandMatches, b.CommandMatches) &&
		slicesEqual(a.CommandNotMatches, b.CommandNotMatches) &&
		slicesEqual(a.CommandContains, b.CommandContains) &&
		slicesEqual(a.CommandEnvAssignments, b.CommandEnvAssignments) &&
		slicesEqual(a.PathMatches, b.PathMatches) &&
		a.Default == b.Default &&
		callCountEqual(a.CallCount, b.CallCount)
}

func callCountEqual(a, b *CallCountCondition) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Tool == b.Tool &&
		a.Gte == b.Gte &&
		a.Window == b.Window
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// CleanExpiredRules removes expired temporal rules from a policy file.
// Returns the number of rules removed and any error.
func CleanExpiredRules(policyPath string) (int, error) {
	if _, err := os.Stat(policyPath); os.IsNotExist(err) {
		return 0, nil
	}
	var removed int
	err := withPolicyFileLock(policyPath, func() error {
		var err error
		removed, err = cleanExpiredRulesLocked(policyPath)
		return err
	})
	return removed, err
}

func cleanExpiredRulesLocked(policyPath string) (int, error) {
	data, err := os.ReadFile(policyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("persist: read policy for cleanup: %w", err)
	}

	var cfg Config
	if err := safeUnmarshal(data, &cfg); err != nil {
		return 0, fmt.Errorf("persist: parse policy for cleanup: %w", err)
	}

	now := time.Now().UTC()
	removed := 0
	cleaned := make([]Policy, 0, len(cfg.Policies))

	for _, p := range cfg.Policies {
		var activeRules []Rule
		for _, r := range p.Rules {
			if r.ExpiresAt != nil && now.After(*r.ExpiresAt) {
				removed++
				continue
			}
			activeRules = append(activeRules, r)
		}
		if len(activeRules) > 0 {
			p.Rules = activeRules
			cleaned = append(cleaned, p)
		}
	}

	if removed == 0 {
		return 0, nil
	}

	cfg.Policies = cleaned
	return removed, writeConfigAtomic(policyPath, &cfg)
}

// RemoveRule removes a specific rule by policy name and rule index from
// a policy file. Used to consume once:true rules after they fire.
func RemoveRule(policyPath, policyName string, ruleIndex int) error {
	return withPolicyFileLock(policyPath, func() error {
		return removeRule(policyPath, policyName, ruleIndex, nil)
	})
}

func removeRule(policyPath, policyName string, ruleIndex int, expected *Rule) error {
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return fmt.Errorf("persist: read policy for rule removal: %w", err)
	}

	var cfg Config
	if err := safeUnmarshal(data, &cfg); err != nil {
		return fmt.Errorf("persist: parse policy for rule removal: %w", err)
	}

	for i, p := range cfg.Policies {
		if p.Name != policyName {
			continue
		}
		removeIndex := ruleIndex
		if expected != nil {
			if removeIndex < 0 || removeIndex >= len(p.Rules) || !reflect.DeepEqual(p.Rules[removeIndex], *expected) {
				removeIndex = -1
				for candidate := range p.Rules {
					if reflect.DeepEqual(p.Rules[candidate], *expected) {
						removeIndex = candidate
						break
					}
				}
			}
			if removeIndex < 0 {
				return fmt.Errorf("persist: one-time rule no longer present in policy %q", policyName)
			}
		} else if removeIndex < 0 || removeIndex >= len(p.Rules) {
			return fmt.Errorf("persist: rule index %d out of range for policy %q", removeIndex, policyName)
		}
		cfg.Policies[i].Rules = append(p.Rules[:removeIndex], p.Rules[removeIndex+1:]...)
		if len(cfg.Policies[i].Rules) == 0 {
			cfg.Policies = append(cfg.Policies[:i], cfg.Policies[i+1:]...)
		}
		return writeConfigAtomic(policyPath, &cfg)
	}

	return fmt.Errorf("persist: policy %q not found", policyName)
}

// writeConfigAtomic writes a Config to a YAML file atomically.
func writeConfigAtomic(policyPath string, cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("persist: policy config is nil")
	}
	if err := cfg.validate(); err != nil {
		return fmt.Errorf("persist: validate policy before write: %w", err)
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("persist: marshal policy: %w", err)
	}

	header := fmt.Sprintf("# Auto-generated by Rampart — do not edit manually.\n# Last updated: %s\n",
		time.Now().UTC().Format(time.RFC3339))

	dir := filepath.Dir(policyPath)
	tmpFile, err := os.CreateTemp(dir, ".rampart-policy-*.yaml.tmp")
	if err != nil {
		return fmt.Errorf("persist: create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	if err := securefile.OwnerOnly(tmpPath); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("persist: secure temp file: %w", err)
	}

	if _, err := tmpFile.WriteString(header + string(out)); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("persist: write temp file: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("persist: sync temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("persist: close temp file: %w", err)
	}
	if err := replaceFileAtomic(tmpPath, policyPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("persist: rename temp file: %w", err)
	}
	return nil
}
