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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/peg/rampart/internal/engine"
	"github.com/spf13/cobra"
)

type policyTestCall struct {
	Agent  string         `json:"agent"`
	Tool   string         `json:"tool"`
	Params map[string]any `json:"params"`
}

type explanation struct {
	PolicyName  string
	Priority    int
	RuleIndex   int
	Action      engine.Action
	Message     string
	MatchDetail string
	RuleMatched bool
}

func newPolicyCmd(opts *rootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Policy utilities",
	}

	cmd.AddCommand(newPolicyCheckCmd(opts))
	cmd.AddCommand(newPolicyTestCmd(opts))
	cmd.AddCommand(newPolicyExplainCmd(opts))
	cmd.AddCommand(newPolicyLintCmd())

	// `rampart policy test` is an alias for `rampart test` — same command,
	// discoverable under the policy subcommand for users who expect it there.
	cmd.AddCommand(newTestCmd(opts))

	return cmd
}

func newPolicyCheckCmd(opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Validate policy configuration",
		RunE: func(cmd *cobra.Command, _ []string) error {
			store := engine.NewFileStore(opts.configPath)
			cfg, err := store.Load()
			if err != nil {
				return fmt.Errorf("policy: check failed: %w", err)
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "\u2713 Policy valid: %d policies loaded\n", len(cfg.Policies)); err != nil {
				return fmt.Errorf("policy: write check output: %w", err)
			}
			return nil
		},
	}
}

func newPolicyTestCmd(opts *rootOptions) *cobra.Command {
	var input string

	cmd := &cobra.Command{
		Use:   "test --input <file>",
		Short: "Evaluate a set of tool calls against policy",
		RunE: func(cmd *cobra.Command, _ []string) error {
			store := engine.NewFileStore(opts.configPath)
			eng, err := engine.New(store, nil)
			if err != nil {
				return fmt.Errorf("policy: create engine: %w", err)
			}

			if strings.TrimSpace(input) == "" {
				return fmt.Errorf("policy: --input is required")
			}

			var calls []policyTestCall
			if err := readJSONFile(input, &calls); err != nil {
				return fmt.Errorf("policy: read input file: %w", err)
			}

			_, err = fmt.Fprintln(cmd.OutOrStdout(), "TOOL     COMMAND              ACTION  POLICY        MESSAGE")
			if err != nil {
				return fmt.Errorf("policy: write test header: %w", err)
			}

			allowCount := 0
			denyCount := 0
			logCount := 0
			for _, testCall := range calls {
				decision := eng.Evaluate(engine.ToolCall{
					Agent:     normalizeAgent(testCall.Agent),
					Tool:      testCall.Tool,
					Params:    defaultParams(testCall.Params),
					Timestamp: time.Now().UTC(),
				})

				policyName := ""
				if len(decision.MatchedPolicies) > 0 {
					policyName = decision.MatchedPolicies[0]
				}

				command := renderCommand(testCall.Params)
				actionText := decision.Action.String()
				if decision.Action == engine.ActionDeny {
					actionText = strings.ToUpper(actionText)
				}
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%-8s %-20s %-7s %-12s %s\n", testCall.Tool, command, actionText, policyName, decision.Message); err != nil {
					return fmt.Errorf("policy: write test row: %w", err)
				}

				switch decision.Action {
				case engine.ActionAllow:
					allowCount++
				case engine.ActionDeny:
					denyCount++
				case engine.ActionWatch:
					logCount++
				}
			}

			total := allowCount + denyCount + logCount
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "\nResults: %d allow, %d deny, %d log (%d total)\n", allowCount, denyCount, logCount, total); err != nil {
				return fmt.Errorf("policy: write test summary: %w", err)
			}

			if denyCount > 0 {
				return fmt.Errorf("policy: test found %d unexpected denials", denyCount)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&input, "input", "", "Path to JSON test input file")
	_ = cmd.MarkFlagRequired("input")

	return cmd
}

func newPolicyExplainCmd(opts *rootOptions) *cobra.Command {
	var tool string
	var agent string

	cmd := &cobra.Command{
		Use:   "explain <command>",
		Short: "Explain how policy evaluates a command",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			command := args[0]

			policyPath, err := resolveExplainPolicyPath(cmd, opts.configPath)
			if err != nil {
				return err
			}
			store := engine.NewFileStore(policyPath)
			cfg, err := store.Load()
			if err != nil {
				return fmt.Errorf("policy: load config: %w", err)
			}
			eng, err := engine.New(store, nil)
			if err != nil {
				return fmt.Errorf("policy: create engine: %w", err)
			}

			call := engine.ToolCall{
				Agent:     normalizeAgent(agent),
				Tool:      tool,
				Params:    map[string]any{"command": command},
				Timestamp: time.Now().UTC(),
			}
			decision := eng.Evaluate(call)
			explanations := collectExplanations(cfg, call)

			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Evaluating: %s %q\n", tool, command); err != nil {
				return fmt.Errorf("policy: write explain output: %w", err)
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "  Agent: %s | Tool: %s\n\n", normalizeAgent(agent), tool); err != nil {
				return fmt.Errorf("policy: write explain output: %w", err)
			}

			if _, err := fmt.Fprintln(cmd.OutOrStdout(), "Matching policies:"); err != nil {
				return fmt.Errorf("policy: write explain output: %w", err)
			}
			if len(explanations) == 0 {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), "  (none)"); err != nil {
					return fmt.Errorf("policy: write explain output: %w", err)
				}
			}

			for i, item := range explanations {
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "  %d. %s (priority %d)\n", i+1, item.PolicyName, item.Priority); err != nil {
					return fmt.Errorf("policy: write explain output: %w", err)
				}
				if !item.RuleMatched {
					if _, err := fmt.Fprintln(cmd.OutOrStdout(), "     -> No rule matched"); err != nil {
						return fmt.Errorf("policy: write explain output: %w", err)
					}
					continue
				}
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "     -> Rule %d: %s %q\n", item.RuleIndex+1, strings.ToUpper(item.Action.String()), item.Message); err != nil {
					return fmt.Errorf("policy: write explain output: %w", err)
				}
				if item.MatchDetail != "" {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "        Matched: %s\n", item.MatchDetail); err != nil {
						return fmt.Errorf("policy: write explain output: %w", err)
					}
				}
			}

			policyName := ""
			if len(decision.MatchedPolicies) > 0 {
				policyName = decision.MatchedPolicies[0]
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "\nFinal decision: %s\n", strings.ToUpper(decision.Action.String())); err != nil {
				return fmt.Errorf("policy: write explain output: %w", err)
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "  Policy: %s\n", policyName); err != nil {
				return fmt.Errorf("policy: write explain output: %w", err)
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "  Message: %s\n", decision.Message); err != nil {
				return fmt.Errorf("policy: write explain output: %w", err)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&tool, "tool", "exec", "Tool type to evaluate")
	cmd.Flags().StringVar(&agent, "agent", "*", "Agent identity to evaluate")

	return cmd
}

func resolveExplainPolicyPath(cmd *cobra.Command, configPath string) (string, error) {
	candidate := strings.TrimSpace(configPath)

	// Explicit --config flag always wins.
	if cmd.Flags().Changed("config") {
		if candidate == "" {
			return "", fmt.Errorf("policy: --config cannot be empty")
		}
		if _, err := os.Stat(candidate); err != nil {
			if os.IsNotExist(err) {
				return "", fmt.Errorf("policy: config file not found at %s", candidate)
			}
			return "", fmt.Errorf("policy: check config %s: %w", candidate, err)
		}
		return candidate, nil
	}

	// If configPath was set programmatically to a non-default path (e.g. in
	// tests or via opts struct), use it directly. If the file doesn't exist,
	// return an error — don't silently fall through to auto-discovery, which
	// would produce a confusing mismatch between the configured path and what
	// actually gets explained.
	if candidate != "" && candidate != "rampart.yaml" {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		} else if os.IsNotExist(err) {
			return "", fmt.Errorf("policy: config file not found at %s", candidate)
		} else {
			return "", fmt.Errorf("policy: check config %s: %w", candidate, err)
		}
	}

	// Auto-discover: prefer ~/.rampart/policies/standard.yaml, then cwd rampart.yaml.
	home, err := os.UserHomeDir()
	if err == nil {
		standardPath := filepath.Join(home, ".rampart", "policies", "standard.yaml")
		if _, statErr := os.Stat(standardPath); statErr == nil {
			return standardPath, nil
		}
	}

	cwdPath := "rampart.yaml"
	if _, err := os.Stat(cwdPath); err == nil {
		return cwdPath, nil
	}

	return "", fmt.Errorf("policy: no config found. Tried ~/.rampart/policies/standard.yaml and %s; pass --config <path> or run 'rampart init'", cwdPath)
}

func collectExplanations(cfg *engine.Config, call engine.ToolCall) []explanation {
	items := make([]explanation, 0, len(cfg.Policies))
	for _, policy := range cfg.Policies {
		if !policy.IsEnabled() {
			continue
		}
		if !matchPolicyScope(policy.Match, call) {
			continue
		}

		item := explanation{
			PolicyName: policy.Name,
			Priority:   policy.EffectivePriority(),
		}
		for i, rule := range policy.Rules {
			matched, detail := engine.ExplainCondition(rule.When, call)
			if !matched {
				continue
			}
			action, err := rule.ParseAction()
			if err != nil {
				action = engine.ActionDeny
			}
			item.RuleMatched = true
			item.RuleIndex = i
			item.Action = action
			item.Message = rule.Message
			item.MatchDetail = detail
			break
		}
		items = append(items, item)
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].Priority < items[j].Priority
	})

	return items
}

func matchPolicyScope(match engine.Match, call engine.ToolCall) bool {
	if !engine.MatchGlob(match.EffectiveAgent(), call.Agent) {
		return false
	}
	if len(match.Tool) == 0 {
		return true
	}
	for _, tool := range match.Tool {
		if engine.MatchGlob(tool, call.Tool) {
			return true
		}
	}
	return false
}

func readJSONFile(path string, out any) error {
	data, err := osReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("parse JSON: %w", err)
	}
	return nil
}

var osReadFile = func(name string) ([]byte, error) {
	return os.ReadFile(name)
}

func defaultParams(params map[string]any) map[string]any {
	if params == nil {
		return map[string]any{}
	}
	return params
}

func normalizeAgent(agent string) string {
	if strings.TrimSpace(agent) == "" {
		return "*"
	}
	return agent
}

func renderCommand(params map[string]any) string {
	if params == nil {
		return ""
	}
	if command, ok := params["command"].(string); ok {
		return command
	}
	if path, ok := params["path"].(string); ok {
		return path
	}
	if url, ok := params["url"].(string); ok {
		return url
	}
	return ""
}
