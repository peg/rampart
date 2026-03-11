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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func newConvertCmd() *cobra.Command {
	var outputFile string

	cmd := &cobra.Command{
		Use:   "convert <settings.json>",
		Short: "Convert Claude Code settings to a Rampart policy",
		Long: `Import permission rules from a Claude Code settings.json file and generate
an equivalent Rampart policy YAML.

Supports rules from permissions.allow, permissions.deny, and permissions.ask.

Examples:
  rampart convert ~/.claude/settings.json
  rampart convert .claude/settings.json -o my-policy.yaml
  rampart convert ~/.claude/settings.json | rampart policy lint -`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConvert(cmd.OutOrStdout(), args[0], outputFile)
		},
	}

	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write policy to file instead of stdout")
	return cmd
}

// claudeSettings represents the relevant parts of a Claude Code settings.json.
type claudePermissions struct {
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
	Ask   []string `json:"ask"`
}

type claudeSettingsFile struct {
	Permissions claudePermissions `json:"permissions"`
}

// convertedRule holds a single converted policy rule.
type convertedRule struct {
	name    string
	action  string
	tool    string
	pattern string // command_matches or path_matches pattern
	comment string
}

func runConvert(w io.Writer, inputPath, outputFile string) error {
	// Expand ~ in path
	if strings.HasPrefix(inputPath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("resolve home: %w", err)
		}
		inputPath = filepath.Join(home, inputPath[2:])
	}

	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("read settings: %w", err)
	}

	var settings claudeSettingsFile
	if err := json.Unmarshal(data, &settings); err != nil {
		return fmt.Errorf("parse settings: %w", err)
	}

	perms := settings.Permissions
	totalRules := len(perms.Allow) + len(perms.Deny) + len(perms.Ask)
	if totalRules == 0 {
		return fmt.Errorf("no permission rules found in %s", inputPath)
	}

	var rules []convertedRule

	// Deny rules first (highest priority in Rampart too)
	for _, rule := range perms.Deny {
		r := convertClaudeRule(rule, "deny")
		if r != nil {
			rules = append(rules, *r)
		}
	}

	// Ask rules → require_approval
	for _, rule := range perms.Ask {
		r := convertClaudeRule(rule, "require_approval")
		if r != nil {
			rules = append(rules, *r)
		}
	}

	// Allow rules
	for _, rule := range perms.Allow {
		r := convertClaudeRule(rule, "allow")
		if r != nil {
			rules = append(rules, *r)
		}
	}

	// Deduplicate rule names by appending a counter
	nameCounts := make(map[string]int)
	for i := range rules {
		nameCounts[rules[i].name]++
	}
	nameIdx := make(map[string]int)
	for i := range rules {
		n := rules[i].name
		if nameCounts[n] > 1 {
			nameIdx[n]++
			rules[i].name = fmt.Sprintf("%s-%d", n, nameIdx[n])
		}
	}

	yaml := renderPolicy(rules, inputPath)

	if outputFile != "" {
		if err := os.WriteFile(outputFile, []byte(yaml), 0o644); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		fmt.Fprintf(w, "Wrote %d rules to %s\n", len(rules), outputFile)
		return nil
	}

	fmt.Fprint(w, yaml)
	return nil
}

// convertClaudeRule converts a single Claude Code permission rule to a Rampart rule.
// Returns nil if the rule can't be converted.
func convertClaudeRule(rule, action string) *convertedRule {
	// Parse "Tool" or "Tool(specifier)"
	tool, specifier := parseClaudeRule(rule)

	switch strings.ToLower(tool) {
	case "bash":
		return convertBashRule(specifier, action, rule)
	case "read":
		return convertReadRule(specifier, action, rule)
	case "write", "edit":
		return convertWriteRule(tool, specifier, action, rule)
	case "webfetch":
		return convertWebFetchRule(specifier, action, rule)
	case "mcp":
		return &convertedRule{
			name:    convertSlugify("mcp-" + action + "-" + specifier),
			action:  action,
			tool:    "mcp",
			comment: fmt.Sprintf("# Converted from: %s %s", action, rule),
		}
	default:
		return &convertedRule{
			name:    convertSlugify(tool + "-" + action),
			action:  action,
			tool:    strings.ToLower(tool),
			comment: fmt.Sprintf("# Converted from: %s %s (unsupported tool — review manually)", action, rule),
		}
	}
}

func convertBashRule(specifier, action, original string) *convertedRule {
	name := convertSlugify("bash-" + action)
	if specifier != "" && specifier != "*" {
		name = convertSlugify("bash-" + action + "-" + specifier)
	}

	r := &convertedRule{
		name:    name,
		action:  action,
		tool:    "exec",
		comment: fmt.Sprintf("# Converted from: %s %s", action, original),
	}

	if specifier == "" || specifier == "*" {
		r.pattern = "*"
	} else {
		r.pattern = specifier
	}

	return r
}

func convertReadRule(specifier, action, original string) *convertedRule {
	r := &convertedRule{
		name:    convertSlugify("read-" + action),
		action:  action,
		tool:    "read",
		comment: fmt.Sprintf("# Converted from: %s %s", action, original),
	}

	if specifier != "" && specifier != "*" {
		r.pattern = specifier
		r.name = convertSlugify("read-" + action + "-" + specifier)
	}

	return r
}

func convertWriteRule(tool, specifier, action, original string) *convertedRule {
	rampartTool := "write"
	if strings.ToLower(tool) == "edit" {
		rampartTool = "edit"
	}

	r := &convertedRule{
		name:    convertSlugify(rampartTool + "-" + action),
		action:  action,
		tool:    rampartTool,
		comment: fmt.Sprintf("# Converted from: %s %s", action, original),
	}

	if specifier != "" && specifier != "*" {
		r.pattern = specifier
		r.name = convertSlugify(rampartTool + "-" + action + "-" + specifier)
	}

	return r
}

func convertWebFetchRule(specifier, action, original string) *convertedRule {
	r := &convertedRule{
		name:    convertSlugify("fetch-" + action),
		action:  action,
		tool:    "fetch",
		comment: fmt.Sprintf("# Converted from: %s %s", action, original),
	}

	// Handle domain: prefix
	if strings.HasPrefix(specifier, "domain:") {
		domain := strings.TrimPrefix(specifier, "domain:")
		r.pattern = "*" + domain + "*"
		r.name = convertSlugify("fetch-" + action + "-" + domain)
	} else if specifier != "" {
		r.pattern = specifier
	}

	return r
}

// parseClaudeRule splits "Tool(specifier)" into tool and specifier.
func parseClaudeRule(rule string) (string, string) {
	rule = strings.TrimSpace(rule)
	paren := strings.IndexByte(rule, '(')
	if paren < 0 {
		return rule, ""
	}
	tool := rule[:paren]
	spec := rule[paren+1:]
	// Strip trailing )
	if strings.HasSuffix(spec, ")") {
		spec = spec[:len(spec)-1]
	}
	return tool, spec
}

// convertSlugify creates a policy rule name from a description.
func convertSlugify(s string) string {
	s = strings.ToLower(s)
	// Replace common patterns with readable names before slugifying
	s = strings.ReplaceAll(s, "/*", "-all")
	s = strings.ReplaceAll(s, "~/", "home-")
	s = strings.ReplaceAll(s, "**", "any")
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		case r == ' ' || r == '/' || r == '.':
			b.WriteRune('-')
		case r == '*':
			b.WriteRune('-')
		}
	}
	result := b.String()
	// Collapse multiple dashes
	for strings.Contains(result, "--") {
		result = strings.ReplaceAll(result, "--", "-")
	}
	return strings.Trim(result, "-")
}

// toolDisplayName maps internal tool names to human-friendly policy names.
var toolDisplayName = map[string]string{
	"exec":  "exec",
	"read":  "read",
	"write": "write",
	"edit":  "edit",
	"fetch": "fetch",
	"mcp":   "mcp",
}

// renderPolicy generates YAML output from converted rules, grouped by tool.
func renderPolicy(rules []convertedRule, source string) string {
	var b strings.Builder

	b.WriteString("# Rampart policy — converted from Claude Code settings\n")
	b.WriteString(fmt.Sprintf("# Source: %s\n", source))
	b.WriteString("#\n")
	b.WriteString("# Review these rules before using in production.\n")
	b.WriteString("# Claude Code and Rampart have different matching semantics —\n")
	b.WriteString("# test with: rampart policy test <this-file>\n")
	b.WriteString("\n")
	b.WriteString("version: \"1\"\n")
	b.WriteString("default_action: allow\n")
	b.WriteString("\n")
	b.WriteString("policies:\n")

	// Group rules by tool
	toolOrder := []string{"exec", "read", "write", "edit", "fetch", "mcp"}
	grouped := make(map[string][]convertedRule)
	for _, r := range rules {
		grouped[r.tool] = append(grouped[r.tool], r)
	}

	for _, tool := range toolOrder {
		toolRules, ok := grouped[tool]
		if !ok {
			continue
		}

		b.WriteString(fmt.Sprintf("\n  - name: claude-code-%s\n", tool))
		b.WriteString(fmt.Sprintf("    description: \"%s rules imported from Claude Code\"\n", tool))
		b.WriteString("    match:\n")
		b.WriteString(fmt.Sprintf("      tool: [\"%s\"]\n", tool))
		b.WriteString("    rules:\n")

		for _, r := range toolRules {
			b.WriteString("\n")
			b.WriteString("      " + r.comment + "\n")
			b.WriteString(fmt.Sprintf("      - action: %s\n", r.action))

			if r.pattern != "" {
				b.WriteString("        when:\n")

				switch r.tool {
				case "exec":
					b.WriteString(fmt.Sprintf("          command_matches:\n            - \"%s\"\n", r.pattern))
				case "read", "write", "edit":
					b.WriteString(fmt.Sprintf("          path_matches:\n            - \"%s\"\n", r.pattern))
				case "fetch":
					b.WriteString(fmt.Sprintf("          url_matches:\n            - \"%s\"\n", r.pattern))
				}
			}

			b.WriteString(fmt.Sprintf("        message: \"%s\"\n", r.comment[2:])) // strip "# "
		}
	}

	// Catch any tools we didn't anticipate
	for tool, toolRules := range grouped {
		found := false
		for _, t := range toolOrder {
			if t == tool {
				found = true
				break
			}
		}
		if found {
			continue
		}

		b.WriteString(fmt.Sprintf("\n  - name: claude-code-%s\n", tool))
		b.WriteString(fmt.Sprintf("    description: \"%s rules imported from Claude Code (review manually)\"\n", tool))
		b.WriteString("    rules:\n")

		for _, r := range toolRules {
			b.WriteString(fmt.Sprintf("\n      # %s\n", r.comment[2:]))
			b.WriteString(fmt.Sprintf("      - action: %s\n", r.action))
			b.WriteString(fmt.Sprintf("        message: \"%s\"\n", r.comment[2:]))
		}
	}

	return b.String()
}
