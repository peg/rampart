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
	"strings"
	"time"

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
		// Short commands: keep as-is plus wildcard.
		return strings.Join(tokens, " ") + " *"
	}

	// Keep first two tokens, wildcard the rest.
	return tokens[0] + " " + tokens[1] + " *"
}

// GenerateAllowRule creates a Policy from a ToolCall that would allow
// similar future calls.
func GenerateAllowRule(call ToolCall) Policy {
	tool := call.Tool
	if tool == "" {
		tool = "*"
	}

	now := time.Now().UTC()
	var ruleName string
	var rule Rule

	switch tool {
	case "exec":
		cmd := call.Command()
		generalized := GeneralizeCommand(cmd)
		tokens := strings.Fields(cmd)
		nameParts := tokens
		if len(nameParts) > 2 {
			nameParts = nameParts[:2]
		}
		ruleName = fmt.Sprintf("auto-allow-%s", strings.Join(nameParts, "-"))
		rule = Rule{
			Action: "allow",
			When: Condition{
				CommandMatches: []string{generalized},
			},
		}

	case "read", "write":
		path := call.Path()
		if path == "" {
			path = "*"
		}
		action := tool
		ruleName = fmt.Sprintf("auto-allow-%s-%s", action, sanitizeName(path))
		rule = Rule{
			Action: "allow",
			When: Condition{
				PathMatches: []string{path},
			},
		}

	default:
		// MCP or other tools: match on tool name.
		ruleName = fmt.Sprintf("auto-allow-%s", sanitizeName(tool))
		rule = Rule{
			Action: "allow",
			When: Condition{
				Default: true,
			},
		}
	}

	return Policy{
		Name: fmt.Sprintf("%s-%s", ruleName, now.Format("20060102T150405Z")),
		Match: Match{
			Tool: StringOrSlice{tool},
		},
		Rules: []Rule{rule},
	}
}

// AppendAllowRule generates an allow rule from a ToolCall and appends it
// to the auto-allowed policy file. Creates the file and directories if needed.
func AppendAllowRule(policyPath string, call ToolCall) error {
	policy := GenerateAllowRule(call)

	// Ensure directory exists.
	dir := filepath.Dir(policyPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("persist: create policy dir: %w", err)
	}

	// Load existing config or create new one.
	var cfg Config
	data, err := os.ReadFile(policyPath)
	if err == nil {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("persist: parse existing policy: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("persist: read policy file: %w", err)
	}

	if cfg.Version == "" {
		cfg.Version = "1"
		cfg.DefaultAction = "deny"
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

	out, err := marshalCleanYAML(&cfg)
	if err != nil {
		return fmt.Errorf("persist: marshal policy: %w", err)
	}

	// Add comment header.
	header := fmt.Sprintf("# Auto-generated by Rampart — do not edit manually.\n# Last updated: %s\n",
		time.Now().UTC().Format(time.RFC3339))

	// Atomic write: write to temp file then rename to prevent corruption.
	tmpFile, err := os.CreateTemp(dir, ".rampart-policy-*.yaml.tmp")
	if err != nil {
		return fmt.Errorf("persist: create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	if _, err := tmpFile.WriteString(header + string(out)); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("persist: write temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("persist: close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, policyPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("persist: rename temp file: %w", err)
	}

	return nil
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
		slicesEqual(a.PathMatches, b.PathMatches) &&
		a.Default == b.Default
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

// cleanRule is a minimal YAML representation that omits empty fields.
type cleanRule struct {
	Action string     `yaml:"action"`
	When   cleanWhen  `yaml:"when"`
}

type cleanWhen struct {
	CommandMatches []string `yaml:"command_matches,omitempty"`
	PathMatches    []string `yaml:"path_matches,omitempty"`
	Default        bool     `yaml:"default,omitempty"`
}

type cleanPolicy struct {
	Name  string        `yaml:"name"`
	Match cleanMatch    `yaml:"match"`
	Rules []cleanRule   `yaml:"rules"`
}

type cleanMatch struct {
	Tool []string `yaml:"tool"`
}

type cleanConfig struct {
	Version       string        `yaml:"version"`
	DefaultAction string        `yaml:"default_action"`
	Policies      []cleanPolicy `yaml:"policies"`
}

// marshalCleanYAML converts a Config to clean YAML without empty fields.
func marshalCleanYAML(cfg *Config) ([]byte, error) {
	clean := cleanConfig{
		Version:       cfg.Version,
		DefaultAction: cfg.DefaultAction,
	}
	for _, p := range cfg.Policies {
		cp := cleanPolicy{
			Name:  p.Name,
			Match: cleanMatch{Tool: []string(p.Match.Tool)},
		}
		for _, r := range p.Rules {
			cp.Rules = append(cp.Rules, cleanRule{
				Action: r.Action,
				When: cleanWhen{
					CommandMatches: r.When.CommandMatches,
					PathMatches:    r.When.PathMatches,
					Default:        r.When.Default,
				},
			})
		}
		clean.Policies = append(clean.Policies, cp)
	}
	return yaml.Marshal(&clean)
}

// MatchesAutoAllowFile checks if a ToolCall matches any rule in the auto-allow
// policy file. Returns true if the call should be allowed immediately without
// going through the approval queue.
//
// This is checked at the serve level BEFORE creating a pending approval, so
// that user "Always Allow" decisions override require_approval policies.
func MatchesAutoAllowFile(policyPath string, call ToolCall) bool {
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return false // no file = no auto-allow rules
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return false
	}

	for _, p := range cfg.Policies {
		// Check tool match.
		if len(p.Match.Tool) > 0 {
			matched := false
			for _, t := range p.Match.Tool {
				if t == "*" || t == call.Tool {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		// Check rules.
		for _, r := range p.Rules {
			if r.Action != "allow" {
				continue
			}
			// Default: matches anything for this tool.
			if r.When.Default {
				return true
			}
			// Exec: command_matches.
			if len(r.When.CommandMatches) > 0 {
				cmd := call.Command()
				for _, pattern := range r.When.CommandMatches {
					if MatchGlob(pattern, cmd) {
						return true
					}
				}
			}
			// Write/read: path_matches.
			if len(r.When.PathMatches) > 0 {
				path := call.Path()
				for _, pattern := range r.When.PathMatches {
					if MatchGlob(pattern, path) {
						return true
					}
				}
			}
		}
	}

	return false
}
