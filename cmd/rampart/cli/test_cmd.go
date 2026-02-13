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
	"fmt"
	"io"
	"log/slog"
	"os"
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
	)

	cmd := &cobra.Command{
		Use:   "test <command-or-path>",
		Short: "Test how policies evaluate a command without executing it",
		Long: `Dry-run a tool call through the policy engine and display the result.

By default, the argument is treated as an exec command. Use --tool to
change the tool type (read, write) in which case the argument is a path.

Examples:
  rampart test "rm -rf /"
  rampart test "git status"
  rampart test --tool read "/etc/shadow"
  rampart test --tool write "/etc/passwd"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTest(cmd.OutOrStdout(), cmd.ErrOrStderr(), opts, args[0], toolName, noColor)
		},
	}

	cmd.Flags().StringVar(&toolName, "tool", "exec", "Tool type: exec, read, write")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Disable color output")

	return cmd
}

func runTest(w, errW io.Writer, opts *rootOptions, arg, toolName string, noColor bool) error {
	// Resolve policy path with fallback.
	policyPath, cleanup, err := resolveTestPolicyPath(opts.configPath)
	if err != nil {
		return err
	}
	defer cleanup()

	// Suppress engine startup logs for clean test output.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	store := engine.NewFileStore(policyPath)
	eng, err := engine.New(store, nil)
	if err != nil {
		return fmt.Errorf("test: create engine: %w", err)
	}

	// Build the tool call.
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

	// Evaluate.
	decision := eng.Evaluate(call)

	// Format output.
	printTestResult(w, decision, noColor)

	// Exit code 1 for deny.
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

	// Fall back to ~/.rampart/policies/standard.yaml.
	home, err := os.UserHomeDir()
	if err == nil {
		stdPath := home + "/.rampart/policies/standard.yaml"
		if _, statErr := os.Stat(stdPath); statErr == nil {
			return stdPath, func() {}, nil
		}
	}

	// Fall back to embedded standard policy.
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
			color = "\033[31m" // red
		}
	case engine.ActionLog:
		icon = "📝"
		label = "LOG"
		if !noColor {
			color = "\033[33m" // yellow
		}
	default:
		icon = "✅"
		label = "ALLOW"
		if !noColor {
			color = "\033[32m" // green
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
