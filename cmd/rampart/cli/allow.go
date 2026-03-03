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
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/peg/rampart/internal/policy"
	"github.com/spf13/cobra"
)

// makePatternArgs returns a cobra.Args function that validates pattern arguments
// and provides helpful error messages.
func makePatternArgs(cmdName string) cobra.PositionalArgs {
	examples := map[string][]string{
		"allow": {"npm install *", "go test ./...", "/tmp/**"},
		"block": {"curl * | bash", "rm -rf *", "/etc/**"},
	}
	exs := examples[cmdName]
	if exs == nil {
		exs = []string{"pattern *"}
	}

	return func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf(`missing pattern argument

Usage: rampart %s <pattern>

Examples:
  rampart %s "%s"
  rampart %s "%s"
  rampart %s "%s"

Run 'rampart %s --help' for more options.`,
				cmdName, cmdName, exs[0], cmdName, exs[1], cmdName, exs[2], cmdName)
		}
		if len(args) > 1 {
			return fmt.Errorf("too many arguments: got %d, expected 1 pattern\n\nDid you forget to quote the pattern? Try: rampart %s \"%s\"",
				len(args), cmdName, strings.Join(args, " "))
		}
		return nil
	}
}

// allowBlockOptions holds shared flags for the allow/block commands.
type allowBlockOptions struct {
	global  bool
	project bool
	tool    string
	message string
	yes     bool
	apiAddr string
	token   string
	forDur  string // --for duration (e.g. "1h", "30m")
	once    bool   // --once single-use rule
}

func newAllowCmd(_ *rootOptions) *cobra.Command {
	opts := &allowBlockOptions{}

	cmd := &cobra.Command{
		Use:   "allow <pattern>",
		Short: "Add an allow rule to your custom policy",
		Long: `Add a glob pattern as an explicit allow rule in your custom policy.

Patterns are matched against commands (exec tool) or file paths (read/write/edit).
Auto-detects path vs command based on whether the pattern contains a '/'.

Examples:
  rampart allow "npm install *"        # allow npm install commands
  rampart allow "go test ./..."        # allow go test
  rampart allow "/tmp/**"              # allow reading/writing anything in /tmp
  rampart allow "curl https://api.example.com/*"

Changes take effect immediately if 'rampart serve' is running.`,
		Args: makePatternArgs("allow"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAllowBlock(cmd, args[0], "allow", opts)
		},
	}

	addAllowBlockFlags(cmd, opts)
	return cmd
}

func addAllowBlockFlags(cmd *cobra.Command, opts *allowBlockOptions) {
	cmd.Flags().BoolVar(&opts.global, "global", false, "Write to global policy (~/.rampart/policies/custom.yaml)")
	cmd.Flags().BoolVar(&opts.project, "project", false, "Write to project policy (.rampart/policy.yaml)")
	cmd.Flags().StringVar(&opts.tool, "tool", "", "Tool type: exec, read, write, edit (default: auto-detect)")
	cmd.Flags().StringVar(&opts.message, "message", "", "Optional reason displayed when the rule matches")
	cmd.Flags().BoolVarP(&opts.yes, "yes", "y", false, "Skip confirmation prompt")
	cmd.Flags().StringVar(&opts.apiAddr, "api", "http://127.0.0.1:9090", "Rampart serve API address for reload")
	cmd.Flags().StringVar(&opts.token, "token", "", "API auth token (or set RAMPART_TOKEN)")
	cmd.Flags().StringVar(&opts.forDur, "for", "", "Rule expires after duration (e.g. 1h, 30m, 24h)")
	cmd.Flags().BoolVar(&opts.once, "once", false, "Single-use rule — removed after first match")
}

// runAllowBlock is the shared implementation for `rampart allow` and `rampart block`.
func runAllowBlock(cmd *cobra.Command, pattern, action string, opts *allowBlockOptions) error {
	out := cmd.OutOrStdout()

	// Validate pattern.
	if strings.TrimSpace(pattern) == "" {
		return fmt.Errorf("pattern cannot be empty")
	}
	if err := validateGlobPattern(pattern); err != nil {
		return fmt.Errorf("invalid glob pattern: %w", err)
	}

	// Validate tool flag if provided.
	if opts.tool != "" {
		validTools := map[string]bool{"exec": true, "read": true, "write": true, "edit": true}
		if !validTools[opts.tool] {
			return fmt.Errorf("invalid --tool value %q; valid values are: exec, read, write, edit", opts.tool)
		}
	}

	// Auto-detect tool from pattern.
	detectedTool := opts.tool
	if detectedTool == "" {
		detectedTool = policy.DetectTool(pattern)
	}
	// Normalize "path" to "read" for display (DetectTool returns "path" for path patterns)
	if detectedTool == "path" {
		detectedTool = "read"
	}

	// Resolve target policy file.
	policyPath, scope, err := resolvePolicyPath(cmd, opts)
	if err != nil {
		return err
	}

	// Print what we're about to do.
	useColor := !noColor() && isTerminal(os.Stdout)
	printRuleSummary(out, action, pattern, detectedTool, opts.message, scope, policyPath, useColor)

	// Print temporal info.
	if opts.forDur != "" {
		dur, _ := time.ParseDuration(opts.forDur)
		exp := time.Now().UTC().Add(dur)
		fmt.Fprintf(out, "    Expires: %s (in %s)\n", exp.Format(time.RFC3339), opts.forDur)
	}
	if opts.once {
		fmt.Fprintf(out, "    Single-use: will be removed after first match\n")
	}

	// Warn if pattern is overly permissive.
	warnIfOverlyPermissive(out, pattern, useColor)

	// Ask for confirmation unless --yes or non-interactive.
	if !opts.yes && isTerminal(os.Stdin) {
		if !promptConfirm(cmd.InOrStdin(), out, "Add this rule?") {
			fmt.Fprintln(out, "  Aborted.")
			return nil
		}
	}

	// Load (or create) the custom policy file.
	p, err := policy.LoadCustomPolicy(policyPath)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}

	// Check for duplicate pattern.
	if exists, existingAction, existingTool := p.HasPattern(pattern); exists {
		fmt.Fprintf(out, "\n  ⚠️  Pattern already exists: %s %s %q\n", existingAction, existingTool, pattern)
		fmt.Fprintln(out, "  Use 'rampart rules' to view existing rules.")
		return nil
	}

	// Build the message.
	msg := opts.message
	if msg == "" {
		msg = defaultMessage(action, pattern, detectedTool)
	}

	// Add the rule with optional temporal constraints.
	temporal := policy.TemporalOpts{Once: opts.once}
	if opts.forDur != "" {
		dur, err := time.ParseDuration(opts.forDur)
		if err != nil {
			return fmt.Errorf("invalid --for duration %q: %w", opts.forDur, err)
		}
		if dur <= 0 {
			return fmt.Errorf("--for duration must be positive")
		}
		exp := time.Now().UTC().Add(dur)
		temporal.ExpiresAt = &exp
	}

	if temporal.ExpiresAt != nil || temporal.Once {
		if err := p.AddRuleTemporal(action, pattern, msg, opts.tool, temporal); err != nil {
			return fmt.Errorf("add rule: %w", err)
		}
	} else {
		if err := p.AddRule(action, pattern, msg, opts.tool); err != nil {
			return fmt.Errorf("add rule: %w", err)
		}
	}

	// Save.
	if err := policy.SaveCustomPolicy(policyPath, p); err != nil {
		return fmt.Errorf("save policy: %w", err)
	}

	// Print success (brief - details already shown in printRuleSummary).
	ruleCount := p.TotalRules()
	suffix := ""
	if opts.forDur != "" {
		suffix = fmt.Sprintf(" (expires in %s)", opts.forDur)
	} else if opts.once {
		suffix = " (single-use)"
	}
	if useColor {
		fmt.Fprintf(out, "\n  %s✓%s Rule added to %s%s\n", colorGreen, colorReset, filepath.Base(policyPath), suffix)
	} else {
		fmt.Fprintf(out, "\n  ✓ Rule added to %s%s\n", filepath.Base(policyPath), suffix)
	}

	// Try to reload the daemon.
	token := resolveToken(opts.token)
	addr := resolveAddrAllow(opts.apiAddr)
	reloaded, reloadErr := reloadPolicy(cmd, addr, token)
	if reloaded {
		fmt.Fprintf(out, "\n  Policy reloaded (%d rules active)\n", ruleCount)
	} else if reloadErr != nil {
		// Daemon not running is not fatal — policy will load on next start.
		fmt.Fprintf(out, "\n  Saved to %s\n", policyPath)
		fmt.Fprintln(out, "  (Run 'rampart serve' to activate changes immediately)")
	} else {
		fmt.Fprintf(out, "\n  Saved to %s\n", policyPath)
	}

	return nil
}

// resolvePolicyPath determines where to write the rule based on flags and context.
func resolvePolicyPath(cmd *cobra.Command, opts *allowBlockOptions) (path, scope string, err error) {
	if opts.global && opts.project {
		return "", "", fmt.Errorf("--global and --project are mutually exclusive")
	}

	if opts.global {
		home, e := os.UserHomeDir()
		if e != nil {
			return "", "", fmt.Errorf("resolve home: %w", e)
		}
		return filepath.Join(home, ".rampart", "policies", "custom.yaml"), "global", nil
	}

	if opts.project {
		// suppress unused parameter warning
		_ = cmd
		return ".rampart" + string(filepath.Separator) + "policy.yaml", "project", nil
	}

	// Auto-detect: prefer project if we're in a git repo, else global.
	if inGitRepo() {
		_ = cmd
		return ".rampart" + string(filepath.Separator) + "policy.yaml", "project", nil
	}

	home, e := os.UserHomeDir()
	if e != nil {
		return "", "", fmt.Errorf("resolve home: %w", e)
	}
	return filepath.Join(home, ".rampart", "policies", "custom.yaml"), "global", nil
}

// inGitRepo returns true when the current working directory (or a parent)
// contains a .git directory or file (worktrees use a .git file).
func inGitRepo() bool {
	dir, err := os.Getwd()
	if err != nil {
		return false
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return false
}

// validateGlobPattern checks for common invalid glob patterns.
func validateGlobPattern(pattern string) error {
	depth := 0
	for _, ch := range pattern {
		switch ch {
		case '[':
			depth++
		case ']':
			if depth == 0 {
				return fmt.Errorf("unexpected ']' — missing opening bracket")
			}
			depth--
		}
	}
	if depth > 0 {
		return fmt.Errorf("missing closing bracket ']'")
	}
	return nil
}

// warnIfOverlyPermissive prints a warning if the pattern would match too broadly.
// Returns true if a warning was printed.
func warnIfOverlyPermissive(w io.Writer, pattern string, useColor bool) bool {
	var warnings []string

	// Patterns that match everything
	if pattern == "*" || pattern == "**" || pattern == "**/**" {
		warnings = append(warnings, "matches ALL commands/paths — effectively disables policy")
	}

	// Root wildcards for paths
	if pattern == "/*" || pattern == "/**" {
		warnings = append(warnings, "matches ALL paths under / — very broad")
	}

	// Home directory wildcards
	if pattern == "~/*" || pattern == "~/**" || pattern == "$HOME/*" || pattern == "$HOME/**" {
		warnings = append(warnings, "matches ALL paths under home directory")
	}

	// Leading ** without specificity
	if strings.HasPrefix(pattern, "**") && !strings.Contains(pattern[2:], "/") && len(pattern) < 5 {
		warnings = append(warnings, "leading ** without path specificity — very broad")
	}

	if len(warnings) == 0 {
		return false
	}

	fmt.Fprintln(w)
	if useColor {
		fmt.Fprintf(w, "  %s⚠️  Warning: Overly permissive pattern%s\n", colorYellow, colorReset)
	} else {
		fmt.Fprintln(w, "  ⚠️  Warning: Overly permissive pattern")
	}
	for _, warn := range warnings {
		fmt.Fprintf(w, "     • %s\n", warn)
	}
	fmt.Fprintln(w)
	return true
}

// printRuleSummary prints what rule will be added before prompting.
func printRuleSummary(w io.Writer, action, pattern, tool, message, scope, path string, useColor bool) {
	fmt.Fprintln(w)
	if useColor {
		fmt.Fprintf(w, "  Adding rule to %s policy (%s%s%s):\n\n", scope, colorDim, path, colorReset)
		fmt.Fprintf(w, "    Action:  %s%s%s\n", actionColor(action, useColor), action, colorReset)
		fmt.Fprintf(w, "    Pattern: %s\n", pattern)
		fmt.Fprintf(w, "    Tool:    %s\n", tool)
		if message != "" {
			fmt.Fprintf(w, "    Message: %s%s%s\n", colorDim, message, colorReset)
		}
	} else {
		fmt.Fprintf(w, "  Adding rule to %s policy (%s):\n\n", scope, path)
		fmt.Fprintf(w, "    Action:  %s\n", action)
		fmt.Fprintf(w, "    Pattern: %s\n", pattern)
		fmt.Fprintf(w, "    Tool:    %s\n", tool)
		if message != "" {
			fmt.Fprintf(w, "    Message: %s\n", message)
		}
	}
	fmt.Fprintln(w)
}

// promptConfirm asks the user a yes/no question and returns true for yes.
func promptConfirm(r io.Reader, w io.Writer, question string) bool {
	fmt.Fprintf(w, "  %s [y/N] ", question)
	scanner := bufio.NewScanner(r)
	if scanner.Scan() {
		ans := strings.TrimSpace(strings.ToLower(scanner.Text()))
		return ans == "y" || ans == "yes"
	}
	return false
}

// reloadPolicy calls POST /v1/policy/reload on the running daemon.
// Returns (true, nil) on success, (false, err) if the daemon is unreachable.
// Returns (false, nil) if no token is configured (daemon auth not set up).
func reloadPolicy(cmd *cobra.Command, addr, token string) (bool, error) {
	if token == "" {
		return false, nil
	}

	url := strings.TrimRight(addr, "/") + "/v1/policy/reload"
	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodPost, url, bytes.NewReader([]byte("{}")))
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		return true, nil
	}
	return false, fmt.Errorf("reload returned HTTP %d", resp.StatusCode)
}

// actionColor returns the ANSI color code for an action label.
func actionColor(action string, useColor bool) string {
	if !useColor {
		return ""
	}
	switch action {
	case "allow":
		return colorGreen
	case "deny":
		return colorRed
	default:
		return colorYel
	}
}

// defaultMessage generates a sensible rule message if none was supplied.
func defaultMessage(action, pattern, tool string) string {
	switch action {
	case "allow":
		return fmt.Sprintf("User-allowed: %s", pattern)
	case "deny":
		return fmt.Sprintf("User-blocked: %s", pattern)
	default:
		return fmt.Sprintf("Custom %s rule: %s (%s)", action, pattern, tool)
	}
}

// resolveAddrAllow returns the effective API address.
// Respects the RAMPART_API environment variable when the addr is the default.
func resolveAddrAllow(addr string) string {
	if env := os.Getenv("RAMPART_API"); env != "" && addr == "http://127.0.0.1:9090" {
		return env
	}
	if addr == "" {
		return "http://127.0.0.1:9090"
	}
	return addr
}
