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
	"strings"

	"gopkg.in/yaml.v3"
)

// LintSeverity represents the severity of a lint finding.
type LintSeverity int

const (
	LintInfo LintSeverity = iota
	LintWarning
	LintError
)

func (s LintSeverity) String() string {
	switch s {
	case LintInfo:
		return "info"
	case LintWarning:
		return "warning"
	case LintError:
		return "error"
	default:
		return "unknown"
	}
}

// LintFinding represents a single lint diagnostic.
type LintFinding struct {
	File     string
	Line     int
	Severity LintSeverity
	Message  string
}

func (f LintFinding) String() string {
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d: %s: %s", f.File, f.Line, f.Severity, f.Message)
	}
	return fmt.Sprintf("%s: %s: %s", f.File, f.Severity, f.Message)
}

// LintResult is the output of linting a policy file.
type LintResult struct {
	Findings []LintFinding
	Errors   int
	Warnings int
	Infos    int
}

// validActions are the known action values.
var validActions = map[string]bool{
	"allow":            true,
	"deny":             true,
	"watch":            true,
	"log":              true, // deprecated alias for watch
	"require_approval": true,
	"webhook":          true,
}

// validConditionFields are the known fields in a `when:` block.
var validConditionFields = map[string]bool{
	"command_matches":      true,
	"command_not_matches":  true,
	"command_contains":     true,
	"path_matches":         true,
	"path_not_matches":     true,
	"url_matches":          true,
	"domain_matches":       true,
	"response_matches":     true,
	"response_not_matches": true,
	"session_matches":      true,
	"session_not_matches":  true,
	"agent_depth":          true,
	"tool_param_matches":   true,
	"default":              true,
}

// commonFieldTypos maps common typos to their correct field names.
var commonFieldTypos = map[string]string{
	"command_match":    "command_matches",
	"commands_match":   "command_matches",
	"commands_matches": "command_matches",
	"path_match":       "path_matches",
	"paths_match":      "path_matches",
	"paths_matches":    "path_matches",
	"url_match":        "url_matches",
	"urls_match":       "url_matches",
	"urls_matches":     "url_matches",
	"domain_match":     "domain_matches",
	"domains_match":    "domain_matches",
	"domains_matches":  "domain_matches",
}

// commonActionTypos maps common action typos to suggestions.
var commonActionTypos = map[string]string{
	"block":    "deny",
	"blok":     "deny",
	"denyy":    "deny",
	"alow":     "allow",
	"allaw":    "allow",
	"permit":   "allow",
	"logging":  "log",
	"approve":  "require_approval",
	"approval": "require_approval",
}

// LintPolicyFile lints a policy YAML file and returns findings.
func LintPolicyFile(path string) LintResult {
	result := LintResult{}
	filename := path

	data, err := os.ReadFile(path)
	if err != nil {
		result.add(LintFinding{File: filename, Severity: LintError, Message: fmt.Sprintf("cannot read file: %v", err)})
		return result
	}

	// First pass: check raw YAML validity.
	var rawNode yaml.Node
	if err := yaml.Unmarshal(data, &rawNode); err != nil {
		result.add(LintFinding{File: filename, Severity: LintError, Message: fmt.Sprintf("invalid YAML: %v", err)})
		return result
	}

	// Second pass: unmarshal into raw map for field checking.
	var rawMap map[string]interface{}
	if err := yaml.Unmarshal(data, &rawMap); err != nil {
		result.add(LintFinding{File: filename, Severity: LintError, Message: fmt.Sprintf("invalid YAML structure: %v", err)})
		return result
	}

	// Third pass: unmarshal with line numbers for raw checks.
	lintRawYAML(&rawNode, filename, &result)

	// Fourth pass: parse into typed config.
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		result.add(LintFinding{File: filename, Severity: LintError, Message: fmt.Sprintf("invalid policy structure: %v", err)})
		return result
	}

	// Check default_action.
	if cfg.DefaultAction == "" {
		result.add(LintFinding{File: filename, Severity: LintInfo, Message: "default_action not explicitly set (implicit deny)"})
	}

	// Check policies array.
	if len(cfg.Policies) == 0 {
		result.add(LintFinding{File: filename, Severity: LintWarning, Message: "policy has no rules"})
		return result
	}

	// Lint each policy.
	for i, p := range cfg.Policies {
		lintPolicy(filename, i, p, cfg.Policies, &result)
	}

	return result
}

func lintPolicy(filename string, idx int, p Policy, allPolicies []Policy, result *LintResult) {
	if len(p.Rules) == 0 {
		result.add(LintFinding{File: filename, Severity: LintWarning, Message: fmt.Sprintf("policy %q has no rules", p.Name)})
	}

	for j, r := range p.Rules {
		lintRule(filename, p, j, r, result)
	}

	// Check for shadowed rules: if a deny rule with broad patterns precedes
	// a more specific rule, the specific rule may never fire.
	checkShadowedRules(filename, p, allPolicies, result)
}

func lintRule(filename string, p Policy, ruleIdx int, r Rule, result *LintResult) {
	// Check action validity.
	actionLower := strings.ToLower(r.Action)
	if !validActions[actionLower] {
		msg := fmt.Sprintf("unknown action %q", r.Action)
		if suggestion, ok := commonActionTypos[actionLower]; ok {
			msg += fmt.Sprintf(" (did you mean %q?)", suggestion)
		}
		result.add(LintFinding{File: filename, Severity: LintError, Message: msg})
	}
	// Deprecation warning for action: log
	if actionLower == "log" {
		result.add(LintFinding{
			File:     filename,
			Severity: LintWarning,
			Message:  fmt.Sprintf("policy %q rule %d: action \"log\" is deprecated — use \"watch\" instead (same behavior, clearer name)", p.Name, ruleIdx+1),
		})
	}

	// Check for empty when block (matches all tool calls in scope).
	if r.When.IsEmpty() {
		result.add(LintFinding{
			File:     filename,
			Severity: LintInfo,
			Message:  fmt.Sprintf("policy %q rule %d has no conditions — matches all tool calls in scope", p.Name, ruleIdx+1),
		})
	}

	// Check glob patterns for excessive depth.
	checkGlobDepth(filename, p.Name, ruleIdx, r.When.CommandMatches, "command_matches", result)
	checkGlobDepth(filename, p.Name, ruleIdx, r.When.PathMatches, "path_matches", result)
}

func checkGlobDepth(filename, policyName string, ruleIdx int, patterns []string, field string, result *LintResult) {
	for _, pat := range patterns {
		segments := strings.Split(pat, "/")
		globStarCount := 0
		for _, seg := range segments {
			if seg == "**" {
				globStarCount++
			}
		}
		if globStarCount > 3 {
			result.add(LintFinding{
				File:     filename,
				Severity: LintWarning,
				Message:  fmt.Sprintf("policy %q rule %d: %s pattern %q has %d ** segments (quadratic complexity risk)", policyName, ruleIdx+1, field, pat, globStarCount),
			})
		}
	}
}

func checkShadowedRules(filename string, p Policy, allPolicies []Policy, result *LintResult) {
	// Simple check: if a deny rule with `default: true` appears before another rule
	// in the same policy, subsequent rules are shadowed.
	for i, r := range p.Rules {
		if strings.ToLower(r.Action) == "deny" && r.When.Default {
			if i < len(p.Rules)-1 {
				for j := i + 1; j < len(p.Rules); j++ {
					result.add(LintFinding{
						File:     filename,
						Severity: LintInfo,
						Message:  fmt.Sprintf("policy %q rule %d will never match — shadowed by deny-all rule %d", p.Name, j+1, i+1),
					})
				}
			}
		}
	}

	// Cross-policy shadow check: if a higher-priority policy denies everything,
	// lower-priority policies with overlapping scope may never fire.
	for _, other := range allPolicies {
		if other.Name == p.Name {
			continue
		}
		if other.EffectivePriority() >= p.EffectivePriority() {
			continue
		}
		// Check if the other policy has a catch-all deny.
		hasCatchAllDeny := false
		for _, r := range other.Rules {
			if strings.ToLower(r.Action) == "deny" && r.When.Default {
				hasCatchAllDeny = true
				break
			}
		}
		if hasCatchAllDeny && scopeOverlaps(other.Match, p.Match) {
			result.add(LintFinding{
				File:     filename,
				Severity: LintInfo,
				Message:  fmt.Sprintf("policy %q may never match — higher-priority policy %q denies all matching tool calls", p.Name, other.Name),
			})
		}
	}
}

func scopeOverlaps(a, b Match) bool {
	// Conservative: if either matches all agents and all tools, they overlap.
	aAgent := a.EffectiveAgent()
	bAgent := b.EffectiveAgent()
	if aAgent != "*" && bAgent != "*" && aAgent != bAgent {
		return false
	}
	if len(a.Tool) == 0 || len(b.Tool) == 0 {
		return true // one matches all tools
	}
	for _, at := range a.Tool {
		for _, bt := range b.Tool {
			if at == bt || at == "*" || bt == "*" {
				return true
			}
		}
	}
	return false
}

// lintRawYAML walks the raw YAML AST to detect field-level issues
// like "match:" inside rules or "reason:" instead of "message:".
func lintRawYAML(root *yaml.Node, filename string, result *LintResult) {
	if root == nil || len(root.Content) == 0 {
		return
	}
	// root is a document node; its first child is the mapping.
	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		return
	}

	policiesNode := findMapValue(doc, "policies")
	if policiesNode == nil || policiesNode.Kind != yaml.SequenceNode {
		return
	}

	for _, policyNode := range policiesNode.Content {
		if policyNode.Kind != yaml.MappingNode {
			continue
		}
		rulesNode := findMapValue(policyNode, "rules")
		if rulesNode == nil || rulesNode.Kind != yaml.SequenceNode {
			continue
		}

		for _, ruleNode := range rulesNode.Content {
			if ruleNode.Kind != yaml.MappingNode {
				continue
			}
			checkRuleFields(ruleNode, filename, result)
		}
	}
}

func checkRuleFields(ruleNode *yaml.Node, filename string, result *LintResult) {
	for i := 0; i+1 < len(ruleNode.Content); i += 2 {
		key := ruleNode.Content[i]
		if key.Kind != yaml.ScalarNode {
			continue
		}

		switch key.Value {
		case "match":
			result.add(LintFinding{
				File:     filename,
				Line:     key.Line,
				Severity: LintWarning,
				Message:  `"match" is not valid in a rule — did you mean "when"?`,
			})
		case "reason":
			result.add(LintFinding{
				File:     filename,
				Line:     key.Line,
				Severity: LintWarning,
				Message:  `"reason" is not a valid field — did you mean "message"?`,
			})
		case "when":
			// Check condition fields inside when block.
			whenNode := ruleNode.Content[i+1]
			if whenNode.Kind == yaml.MappingNode {
				checkConditionFields(whenNode, filename, result)
			}
		}
	}
}

func checkConditionFields(whenNode *yaml.Node, filename string, result *LintResult) {
	for i := 0; i+1 < len(whenNode.Content); i += 2 {
		key := whenNode.Content[i]
		if key.Kind != yaml.ScalarNode {
			continue
		}
		field := key.Value
		if validConditionFields[field] {
			continue
		}
		msg := fmt.Sprintf("unknown condition field %q", field)
		if suggestion, ok := commonFieldTypos[field]; ok {
			msg += fmt.Sprintf(" (did you mean %q?)", suggestion)
		}
		result.add(LintFinding{
			File:     filename,
			Line:     key.Line,
			Severity: LintError,
			Message:  msg,
		})
	}
}

func findMapValue(node *yaml.Node, key string) *yaml.Node {
	if node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Kind == yaml.ScalarNode && node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func (r *LintResult) add(f LintFinding) {
	r.Findings = append(r.Findings, f)
	switch f.Severity {
	case LintError:
		r.Errors++
	case LintWarning:
		r.Warnings++
	case LintInfo:
		r.Infos++
	}
}

// Summary returns a human-readable summary line.
func (r LintResult) Summary(filename string) string {
	parts := []string{}
	if r.Errors > 0 {
		parts = append(parts, fmt.Sprintf("%d error(s)", r.Errors))
	}
	if r.Warnings > 0 {
		parts = append(parts, fmt.Sprintf("%d warning(s)", r.Warnings))
	}
	if r.Infos > 0 {
		parts = append(parts, fmt.Sprintf("%d info(s)", r.Infos))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%s: no issues found", filename)
	}
	return fmt.Sprintf("%s: %s", filename, strings.Join(parts, ", "))
}

// HasErrors returns true if any error-level findings exist.
func (r LintResult) HasErrors() bool {
	return r.Errors > 0
}
