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
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level policy configuration loaded from YAML.
type Config struct {
	// Version is the policy schema version. Currently "1".
	Version string `yaml:"version"`

	// DefaultAction determines what happens when no rule matches a tool call.
	// Valid values: "allow", "deny". Default: "deny".
	DefaultAction string `yaml:"default_action"`

	// Policies is the ordered list of policy rules.
	Policies []Policy `yaml:"policies"`

	// Notify configures webhook notifications for policy decisions.
	Notify *NotifyConfig `yaml:"notify,omitempty"`

	responseRegexCache map[string]*regexp.Regexp
}

const maxResponseRegexPatternLength = 500

var responseRegexBackreferencePattern = regexp.MustCompile(`\\[1-9][0-9]*`)

// Policy is a named set of rules scoped to specific agents and tools.
type Policy struct {
	// Name uniquely identifies this policy.
	Name string `yaml:"name"`

	// Priority controls evaluation order. Lower number = higher priority.
	// Default: 100. When multiple policies match, deny always wins
	// regardless of priority.
	Priority int `yaml:"priority"`

	// Enabled allows disabling a policy without removing it.
	// Default: true.
	Enabled *bool `yaml:"enabled"`

	// Match defines which tool calls this policy applies to.
	Match Match `yaml:"match"`

	// Rules are evaluated top-to-bottom. First matching rule wins
	// within this policy.
	Rules []Rule `yaml:"rules"`
}

// IsEnabled returns whether this policy is active.
// Defaults to true if not explicitly set.
func (p Policy) IsEnabled() bool {
	if p.Enabled == nil {
		return true
	}
	return *p.Enabled
}

// EffectivePriority returns the policy's priority, defaulting to 100.
func (p Policy) EffectivePriority() int {
	if p.Priority == 0 {
		return 100
	}
	return p.Priority
}

// Match defines the scope of a policy: which agents and tools it applies to.
type Match struct {
	// Agent is a glob pattern for agent identity.
	// "*" matches all agents. "ops-*" matches "ops-deploy", "ops-monitor".
	// Default: "*".
	Agent string `yaml:"agent"`

	// Tool is a glob pattern or list of tool names.
	// "exec" matches only exec. "fs.*" matches "fs.read", "fs.write".
	// Can be a string or list of strings in YAML.
	Tool StringOrSlice `yaml:"tool"`
}

// EffectiveAgent returns the agent pattern, defaulting to "*".
func (m Match) EffectiveAgent() string {
	if m.Agent == "" {
		return "*"
	}
	return m.Agent
}

// Rule is a single allow/deny/log rule within a policy.
type Rule struct {
	// Action is what to do when this rule matches: "allow", "deny", "log",
	// "require_approval", or "webhook".
	Action string `yaml:"action"`

	// When defines the conditions under which this rule matches.
	When Condition `yaml:"when"`

	// Message is a human-readable reason shown to the agent on denial
	// and recorded in the audit trail.
	Message string `yaml:"message"`

	// Webhook configures the external webhook for action: webhook rules.
	Webhook *WebhookActionConfig `yaml:"webhook,omitempty"`
}

// WebhookActionConfig defines the webhook endpoint and behavior for
// action: webhook rules.
type WebhookActionConfig struct {
	// URL is the webhook endpoint to POST to for allow/deny decisions.
	URL string `yaml:"url"`

	// Timeout is how long to wait for the webhook response.
	// Default: 5s.
	Timeout Duration `yaml:"timeout,omitempty"`

	// FailOpen determines behavior on webhook error or timeout.
	// true = allow on failure (default), false = deny on failure.
	FailOpen *bool `yaml:"fail_open,omitempty"`
}

// EffectiveTimeout returns the configured timeout or 5s default.
// Capped at 30s to prevent resource exhaustion.
func (c *WebhookActionConfig) EffectiveTimeout() time.Duration {
	const maxTimeout = 30 * time.Second
	if c.Timeout.Duration > 0 {
		if c.Timeout.Duration > maxTimeout {
			return maxTimeout
		}
		return c.Timeout.Duration
	}
	return 5 * time.Second
}

// EffectiveFailOpen returns whether to fail open on error/timeout.
// Default: true (fail open).
func (c *WebhookActionConfig) EffectiveFailOpen() bool {
	if c.FailOpen == nil {
		return true
	}
	return *c.FailOpen
}

// Duration is a time.Duration that unmarshals from YAML duration strings
// like "5s", "1m", "500ms".
type Duration struct {
	time.Duration
}

// UnmarshalYAML parses a duration string.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	dur, err := time.ParseDuration(value.Value)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", value.Value, err)
	}
	d.Duration = dur
	return nil
}

// ParseAction converts the rule's action string to an Action constant.
// Returns an error for unknown actions.
func (r Rule) ParseAction() (Action, error) {
	switch strings.ToLower(r.Action) {
	case "allow":
		return ActionAllow, nil
	case "deny":
		return ActionDeny, nil
	case "log":
		return ActionLog, nil
	case "require_approval":
		return ActionRequireApproval, nil
	case "webhook":
		return ActionWebhook, nil
	default:
		return ActionAllow, fmt.Errorf("engine: unknown action %q", r.Action)
	}
}

// Condition defines when a rule matches. All specified fields must match
// (AND logic). Within a field, any pattern matching is sufficient (OR logic).
type Condition struct {
	// CommandMatches is a list of glob patterns for exec commands.
	// Any matching pattern triggers the rule.
	CommandMatches []string `yaml:"command_matches"`

	// CommandNotMatches excludes commands from matching.
	// If a command matches any of these, the rule does not apply.
	CommandNotMatches []string `yaml:"command_not_matches"`

	// PathMatches is a list of glob patterns for file paths.
	PathMatches []string `yaml:"path_matches"`

	// PathNotMatches excludes file paths from matching.
	PathNotMatches []string `yaml:"path_not_matches"`

	// URLMatches is a list of glob patterns for URLs.
	URLMatches []string `yaml:"url_matches"`

	// DomainMatches is a list of glob patterns for domains.
	DomainMatches []string `yaml:"domain_matches"`

	// ResponseMatches is a list of regex patterns for tool response bodies.
	ResponseMatches []string `yaml:"response_matches"`

	// ResponseNotMatches excludes response bodies from matching.
	ResponseNotMatches []string `yaml:"response_not_matches"`

	// Default, when true, makes this rule match all tool calls.
	// Use as a catch-all at the end of a rules list.
	Default bool `yaml:"default"`
}

// IsEmpty returns true if no conditions are specified.
// An empty condition with Default=false matches nothing.
func (c Condition) IsEmpty() bool {
	return !c.Default &&
		len(c.CommandMatches) == 0 &&
		len(c.CommandNotMatches) == 0 &&
		len(c.PathMatches) == 0 &&
		len(c.PathNotMatches) == 0 &&
		len(c.URLMatches) == 0 &&
		len(c.DomainMatches) == 0 &&
		len(c.ResponseMatches) == 0 &&
		len(c.ResponseNotMatches) == 0
}

// StringOrSlice handles YAML fields that can be either a single string
// or a list of strings.
//
//	tool: "exec"           → ["exec"]
//	tool: ["exec", "read"] → ["exec", "read"]
type StringOrSlice []string

// NotifyConfig configures webhook notifications for policy decisions.
type NotifyConfig struct {
	// URL is the webhook endpoint to send notifications to.
	URL string `yaml:"url"`

	// Platform specifies the notification format.
	// Valid values: "auto", "slack", "discord", "teams", "webhook".
	// "auto" detects the platform based on the URL. Default: "auto".
	Platform string `yaml:"platform"`

	// On specifies which decision types trigger notifications.
	// Valid values: "deny", "log". Can be a string or list of strings.
	On []string `yaml:"on"`
}

// UnmarshalYAML implements custom YAML unmarshaling for string-or-slice fields.
func (s *StringOrSlice) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		*s = []string{value.Value}
		return nil
	case yaml.SequenceNode:
		var items []string
		if err := value.Decode(&items); err != nil {
			return fmt.Errorf("engine: invalid tool list: %w", err)
		}
		*s = items
		return nil
	default:
		return fmt.Errorf("engine: tool must be a string or list of strings")
	}
}

// FileStore loads policies from a YAML file on disk.
type FileStore struct {
	path string
}

// NewFileStore creates a policy store that reads from the given file path.
func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

// Load reads and parses the policy file. Returns an error if the file
// cannot be read or contains invalid YAML.
func (s *FileStore) Load() (*Config, error) {
	absPath, err := filepath.Abs(s.path)
	if err != nil {
		return nil, fmt.Errorf("engine: resolve path %q: %w", s.path, err)
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("engine: read policy file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("engine: parse policy file: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Path returns the file path this store reads from.
func (s *FileStore) Path() string {
	return s.path
}

// validate checks a policy config for structural errors.
func (cfg *Config) validate() error {
	seen := make(map[string]bool)
	cache := make(map[string]*regexp.Regexp)

	for i, p := range cfg.Policies {
		if p.Name == "" {
			return fmt.Errorf("engine: policy at index %d has no name", i)
		}
		if seen[p.Name] {
			return fmt.Errorf("engine: duplicate policy name %q", p.Name)
		}
		seen[p.Name] = true

		for j, r := range p.Rules {
			action, err := r.ParseAction()
			if err != nil {
				return fmt.Errorf("engine: policy %q rule %d: %w", p.Name, j, err)
			}
			if action == ActionWebhook {
				if r.Webhook == nil || r.Webhook.URL == "" {
					return fmt.Errorf("engine: policy %q rule %d: webhook action requires webhook.url", p.Name, j)
				}
			}
			if err := compileResponseRegexes(r.When, cache); err != nil {
				return fmt.Errorf("engine: policy %q rule %d: %w", p.Name, j, err)
			}
		}
	}

	cfg.responseRegexCache = cache
	return nil
}

func compileResponseRegexes(cond Condition, cache map[string]*regexp.Regexp) error {
	patterns := append([]string{}, cond.ResponseMatches...)
	patterns = append(patterns, cond.ResponseNotMatches...)

	for _, pattern := range patterns {
		if _, ok := cache[pattern]; ok {
			continue
		}

		if err := validateResponseRegexPattern(pattern); err != nil {
			return fmt.Errorf("invalid response regex %q: %w", pattern, err)
		}
		if responseRegexBackreferencePattern.MatchString(pattern) {
			slog.Warn("engine: response regex contains backreference; pattern may be unsupported", "pattern", pattern)
		}

		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid response regex %q: %w", pattern, err)
		}
		cache[pattern] = re
	}

	return nil
}

func validateResponseRegexPattern(pattern string) error {
	if len(pattern) > maxResponseRegexPatternLength {
		return fmt.Errorf("pattern too long (%d > %d characters)", len(pattern), maxResponseRegexPatternLength)
	}
	if hasNestedRegexQuantifiers(pattern) {
		return fmt.Errorf("nested quantifiers are not allowed")
	}
	return nil
}

func hasNestedRegexQuantifiers(pattern string) bool {
	type groupState struct {
		hasQuantifier bool
	}

	stack := make([]groupState, 0, 8)
	inClass := false
	escaped := false
	lastClosedGroupHadQuantifier := false

	for i := 0; i < len(pattern); {
		ch := pattern[i]

		if escaped {
			escaped = false
			lastClosedGroupHadQuantifier = false
			i++
			continue
		}
		if ch == '\\' {
			escaped = true
			lastClosedGroupHadQuantifier = false
			i++
			continue
		}

		if inClass {
			if ch == ']' {
				inClass = false
			}
			lastClosedGroupHadQuantifier = false
			i++
			continue
		}
		if ch == '[' {
			inClass = true
			lastClosedGroupHadQuantifier = false
			i++
			continue
		}

		if width, ok := regexQuantifierWidth(pattern, i); ok {
			if lastClosedGroupHadQuantifier {
				return true
			}
			if len(stack) > 0 {
				stack[len(stack)-1].hasQuantifier = true
			}
			lastClosedGroupHadQuantifier = false
			i += width
			continue
		}

		switch ch {
		case '(':
			stack = append(stack, groupState{})
			lastClosedGroupHadQuantifier = false
		case ')':
			if len(stack) == 0 {
				lastClosedGroupHadQuantifier = false
				i++
				continue
			}
			group := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if group.hasQuantifier && len(stack) > 0 {
				stack[len(stack)-1].hasQuantifier = true
			}
			lastClosedGroupHadQuantifier = group.hasQuantifier
		default:
			lastClosedGroupHadQuantifier = false
		}

		i++
	}

	return false
}

func regexQuantifierWidth(pattern string, i int) (int, bool) {
	if i >= len(pattern) {
		return 0, false
	}

	switch pattern[i] {
	case '*', '+', '?':
		return 1, true
	case '{':
		j := i + 1
		digits := 0
		for j < len(pattern) && pattern[j] >= '0' && pattern[j] <= '9' {
			j++
			digits++
		}
		if j < len(pattern) && pattern[j] == ',' {
			j++
			for j < len(pattern) && pattern[j] >= '0' && pattern[j] <= '9' {
				j++
				digits++
			}
		}
		if digits == 0 || j >= len(pattern) || pattern[j] != '}' {
			return 0, false
		}
		return j - i + 1, true
	default:
		return 0, false
	}
}
