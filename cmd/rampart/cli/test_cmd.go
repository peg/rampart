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
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/policies"
	"github.com/spf13/cobra"
)

func newTestCmd(opts *rootOptions) *cobra.Command {
	var (
		toolName string
		noColor  bool
		verbose  bool
		run      string
		jsonOut  bool
	)

	cmd := &cobra.Command{
		Use:   "test [command-or-path | test-file.yaml]",
		Short: "Test how policies evaluate commands or run a test suite",
		Long: `Dry-run a tool call through the policy engine and display the result.

By default, the argument is treated as an exec command. Use --tool to
change the tool type (read, write) in which case the argument is a path.

If the argument is a YAML file, it is loaded as a test suite containing
multiple test cases. A policy file with an inline "tests:" key can also
be passed directly.

When called with no arguments, looks for rampart-tests.yaml then rampart.yaml
in the current directory.

Examples:
  rampart test "rm -rf /"
  rampart test "git status"
  rampart test --tool read "/etc/shadow"
  rampart test tests.yaml
  rampart test --verbose tests.yaml
  rampart test --run "blocks*" tests.yaml
  rampart test --json tests.yaml
  rampart test                    # auto-discovers rampart-tests.yaml or rampart.yaml`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Zero-arg: discover test file from CWD.
			var arg string
			if len(args) == 0 {
				discovered, err := discoverTestFile()
				if err != nil {
					return err
				}
				arg = discovered
			} else {
				arg = args[0]
			}

			if isYAMLFile(arg) {
				return runTestSuite(cmd.OutOrStdout(), cmd.ErrOrStderr(), opts, arg, noColor, verbose, run, jsonOut)
			}
			return runTest(cmd.OutOrStdout(), cmd.ErrOrStderr(), opts, arg, toolName, noColor, jsonOut)
		},
	}

	cmd.Flags().StringVar(&toolName, "tool", "exec", "Tool type: exec, read, write")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Disable color output")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show match details for each test case")
	cmd.Flags().StringVar(&run, "run", "", "Run only tests matching this glob pattern")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output results as JSON")

	return cmd
}

// discoverTestFile looks for a test/policy file in the current directory.
func discoverTestFile() (string, error) {
	candidates := []string{"rampart-tests.yaml", "rampart.yaml"}
	for _, name := range candidates {
		if _, err := os.Stat(name); err == nil {
			return name, nil
		}
	}
	return "", fmt.Errorf("test: no test file found; pass a file path or create rampart-tests.yaml")
}

func isYAMLFile(arg string) bool {
	lower := strings.ToLower(arg)
	return strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml")
}

// testJSONResult is the per-test result for --json output.
type testJSONResult struct {
	Name     string `json:"name"`
	Passed   bool   `json:"passed"`
	Expected string `json:"expected,omitempty"`
	Got      string `json:"got,omitempty"`
	Message  string `json:"message,omitempty"`
	Error    string `json:"error,omitempty"`
}

// testJSONSummary is the top-level --json output structure.
type testJSONSummary struct {
	Passed int              `json:"passed"`
	Failed int              `json:"failed"`
	Errors int              `json:"errors"`
	Total  int              `json:"total"`
	Tests  []testJSONResult `json:"tests"`
}

func runTestSuite(w, errW io.Writer, opts *rootOptions, arg string, noColor, verbose bool, runFilter string, jsonOut bool) error {
	suite, err := engine.LoadTestSuite(arg)
	if err != nil {
		suite, err = engine.LoadInlineTests(arg)
		if err != nil {
			return fmt.Errorf("test: %w", err)
		}
		if suite == nil {
			return fmt.Errorf("test: %s contains no tests", arg)
		}
	}

	policyPath := suite.Policy
	if policyPath == "" {
		policyPath = arg
	}

	if runFilter != "" {
		var filtered []engine.TestCase
		for _, tc := range suite.Tests {
			matched, _ := filepath.Match(runFilter, tc.Name)
			if matched {
				filtered = append(filtered, tc)
			}
		}
		if len(filtered) == 0 {
			return fmt.Errorf("test: no tests match filter %q", runFilter)
		}
		suite.Tests = filtered
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	store := engine.NewFileStore(policyPath)
	eng, err := engine.New(store, nil)
	if err != nil {
		return fmt.Errorf("test: load policy: %w", err)
	}

	results := engine.RunTests(eng, suite)

	passed, failed, errored := 0, 0, 0
	var jsonTests []testJSONResult

	for _, r := range results {
		if !jsonOut {
			printSuiteResult(w, r, noColor, verbose)
		}

		jr := testJSONResult{Name: r.Case.Name, Passed: r.Passed}
		if r.Error != nil {
			errored++
			jr.Error = r.Error.Error()
		} else if r.Passed {
			passed++
		} else {
			failed++
			jr.Expected = r.ExpectedAction.String()
			jr.Got = r.Decision.Action.String()
			jr.Message = r.Decision.Message
		}
		if jsonOut {
			jsonTests = append(jsonTests, jr)
		}
	}

	if jsonOut {
		summary := testJSONSummary{
			Passed: passed,
			Failed: failed,
			Errors: errored,
			Total:  len(results),
			Tests:  jsonTests,
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(summary)
	} else {
		fmt.Fprintln(w)
		if noColor {
			fmt.Fprintf(w, "%d passed, %d failed", passed, failed)
		} else {
			fmt.Fprintf(w, "\033[32m%d passed\033[0m, \033[31m%d failed\033[0m", passed, failed)
		}
		if errored > 0 {
			fmt.Fprintf(w, ", %d error(s)", errored)
		}
		fmt.Fprintf(w, " (%d total)\n", len(results))
	}

	if failed > 0 || errored > 0 {
		return exitCodeError{code: 1}
	}
	return nil
}

func printSuiteResult(w io.Writer, r engine.TestResult, noColor, verbose bool) {
	var (
		icon  string
		color string
		reset string
	)

	if !noColor {
		reset = "\033[0m"
	}

	if r.Error != nil {
		icon = "⚠️"
		if !noColor {
			color = "\033[33m"
		}
		fmt.Fprintf(w, "  %s %s%s%s — %v\n", icon, color, r.Case.Name, reset, r.Error)
		return
	}

	if r.Passed {
		icon = "✅"
		if !noColor {
			color = "\033[32m"
		}
		fmt.Fprintf(w, "  %s %s%s%s\n", icon, color, r.Case.Name, reset)
	} else {
		icon = "❌"
		if !noColor {
			color = "\033[31m"
		}
		fmt.Fprintf(w, "  %s %s%s%s — expected %s, got %s\n", icon, color, r.Case.Name, reset,
			r.ExpectedAction, r.Decision.Action)
	}

	if verbose {
		if r.Decision.Message != "" {
			fmt.Fprintf(w, "       message: %s\n", r.Decision.Message)
		}
		if len(r.Decision.MatchedPolicies) > 0 {
			fmt.Fprintf(w, "       matched: %s\n", strings.Join(r.Decision.MatchedPolicies, ", "))
		}
		fmt.Fprintf(w, "       eval:    %s\n", formatDuration(r.Decision.EvalDuration))
	}
}

// bareCmdJSONResult is the JSON output for a single bare-command test (--json with no YAML file).
type bareCmdJSONResult struct {
	Command         string   `json:"command"`
	Action          string   `json:"action"`
	Message         string   `json:"message"`
	MatchedPolicies []string `json:"matched_policies"`
	PolicyScope     string   `json:"policy_scope"`
}

func runTest(w, errW io.Writer, opts *rootOptions, arg, toolName string, noColor, jsonOut bool) error {
	policyPath, cleanup, err := resolveTestPolicyPath(opts.configPath)
	if err != nil {
		return err
	}
	defer cleanup()

	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	store := engine.NewFileStore(policyPath)
	eng, err := engine.New(store, nil)
	if err != nil {
		return fmt.Errorf("test: create engine: %w", err)
	}

	call := engine.ToolCall{
		Tool:      toolName,
		Params:    make(map[string]any),
		Timestamp: time.Now(),
	}

	switch toolName {
	case "read", "write":
		call.Params["path"] = arg
	default:
		call.Params["command"] = arg
	}

	decision := eng.Evaluate(call)

	if jsonOut {
		matched := decision.MatchedPolicies
		if matched == nil {
			matched = []string{}
		}
		result := bareCmdJSONResult{
			Command:         arg,
			Action:          decision.Action.String(),
			Message:         decision.Message,
			MatchedPolicies: matched,
			PolicyScope:     "global",
		}
		enc := json.NewEncoder(w)
		_ = enc.Encode(result)
		return nil // exit 0 — dry-run, not enforcement
	}

	printTestResult(w, decision, noColor)

	if decision.Action == engine.ActionDeny {
		return exitCodeError{code: 1}
	}
	return nil
}

func resolveTestPolicyPath(path string) (string, func(), error) {
	if strings.TrimSpace(path) == "" {
		path = "rampart.yaml"
	}

	_, err := os.Stat(path)
	if err == nil {
		return path, func() {}, nil
	}
	if !os.IsNotExist(err) {
		return "", nil, fmt.Errorf("test: check policy config %s: %w", path, err)
	}

	home, err := os.UserHomeDir()
	if err == nil {
		stdPath := home + "/.rampart/policies/standard.yaml"
		if _, statErr := os.Stat(stdPath); statErr == nil {
			return stdPath, func() {}, nil
		}
	}

	fmt.Fprintf(os.Stderr, "⚠ No policy file found — using embedded standard policy\n\n")
	data, err := policies.Profile("standard")
	if err != nil {
		return "", nil, fmt.Errorf("test: no policy found. Run 'rampart init' to create one")
	}

	tmp, err := os.CreateTemp("", "rampart-test-policy-*.yaml")
	if err != nil {
		return "", nil, fmt.Errorf("test: create temporary policy file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", nil, fmt.Errorf("test: write temporary policy file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return "", nil, fmt.Errorf("test: close temporary policy file: %w", err)
	}

	return tmp.Name(), func() { _ = os.Remove(tmp.Name()) }, nil
}

func printTestResult(w io.Writer, d engine.Decision, noColor bool) {
	var (
		icon  string
		color string
		reset string
		label string
	)

	if !noColor {
		reset = "\033[0m"
	}

	switch d.Action {
	case engine.ActionDeny:
		icon = "🛡️"
		label = "DENY"
		if !noColor {
			color = "\033[31m"
		}
	case engine.ActionWatch:
		icon = "📝"
		label = "LOG"
		if !noColor {
			color = "\033[33m"
		}
	default:
		icon = "✅"
		label = "ALLOW"
		if !noColor {
			color = "\033[32m"
		}
	}

	msg := d.Message
	if msg == "" {
		msg = "no details"
	}

	fmt.Fprintf(w, "%s %s%s%s — %s\n", icon, color, label, reset, msg)

	if len(d.MatchedPolicies) > 0 {
		fmt.Fprintf(w, "   Policy: %s\n", strings.Join(d.MatchedPolicies, ", "))
	}

	fmt.Fprintf(w, "   Eval: %s\n", formatDuration(d.EvalDuration))
}

func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%dμs", d.Microseconds())
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}
