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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	custompolicy "github.com/peg/rampart/internal/policy"
	"github.com/spf13/cobra"
)

// ─── Styles ──────────────────────────────────────────────────────────────────

var (
	rulesHeaderStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15"))
	rulesDivStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	rulesSourceStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	rulesNumStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	rulesAllowStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
	rulesDenyStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	rulesToolStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("14"))
	rulesPatStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("7"))
	rulesTimeStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	rulesOkStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
	rulesHintStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
)

// ─── Entry type ──────────────────────────────────────────────────────────────

// rulesEntry is an indexed, source-annotated wrapper around a CustomRule.
type rulesEntry struct {
	Index   int    // 1-based display index
	Source  string // "global" or "project"
	Action  string
	Tool    string
	Pattern string
	Message string
	AddedAt time.Time
}

// ─── Command builders ─────────────────────────────────────────────────────────

func newRulesCmd(opts *rootOptions) *cobra.Command {
	var globalOnly bool
	var projectOnly bool
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "rules",
		Short: "List and manage custom policy rules",
		Long:  "View rules added via 'rampart allow' and 'rampart block'.\nUse 'rampart rules remove <#>' to delete a specific rule.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRulesList(cmd.OutOrStdout(), opts, globalOnly, projectOnly, jsonOut)
		},
	}

	cmd.Flags().BoolVar(&globalOnly, "global", false, "Show only global rules")
	cmd.Flags().BoolVar(&projectOnly, "project", false, "Show only project rules")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON for scripting")
	cmd.MarkFlagsMutuallyExclusive("global", "project")

	cmd.AddCommand(newRulesListCmd(opts))
	cmd.AddCommand(newRulesRemoveCmd(opts))
	cmd.AddCommand(newRulesResetCmd(opts))

	return cmd
}

// newRulesListCmd creates the "rules list" subcommand as an alias for "rules".
func newRulesListCmd(opts *rootOptions) *cobra.Command {
	var globalOnly bool
	var projectOnly bool
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List custom policy rules (alias for 'rampart rules')",
		Long:  "View rules added via 'rampart allow' and 'rampart block'.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRulesList(cmd.OutOrStdout(), opts, globalOnly, projectOnly, jsonOut)
		},
	}

	cmd.Flags().BoolVar(&globalOnly, "global", false, "Show only global rules")
	cmd.Flags().BoolVar(&projectOnly, "project", false, "Show only project rules")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON for scripting")
	cmd.MarkFlagsMutuallyExclusive("global", "project")

	return cmd
}

// ─── List ────────────────────────────────────────────────────────────────────

func runRulesList(out io.Writer, opts *rootOptions, globalOnly, projectOnly, jsonOut bool) error {
	globalEntries, projectEntries, err := loadAllEntries(globalOnly, projectOnly)
	if err != nil {
		return err
	}

	all := append(globalEntries, projectEntries...) //nolint:gocritic

	if jsonOut {
		return printRulesJSON(out, all)
	}

	return printRulesTable(out, opts, globalEntries, projectEntries, globalOnly, projectOnly)
}

// loadAllEntries reads custom rules from both (or one) source.
// Indices are always global (sequential across all sources) to ensure
// consistency between `rampart rules` and `rampart rules remove <index>`.
func loadAllEntries(globalOnly, projectOnly bool) (globalEntries, projectEntries []rulesEntry, err error) {
	// Always load both sources to compute correct global indices,
	// but only return the requested entries.
	idx := 1

	gPath, pathErr := custompolicy.GlobalCustomPath()
	if pathErr != nil {
		return nil, nil, pathErr
	}
	gp, loadErr := custompolicy.LoadCustomPolicy(gPath)
	if loadErr != nil {
		return nil, nil, fmt.Errorf("rules: load global custom rules: %w", loadErr)
	}
	for _, r := range gp.FlattenRules() {
		entry := rulesEntry{
			Index:   idx,
			Source:  "global",
			Action:  r.Action,
			Tool:    r.Tool,
			Pattern: r.Pattern,
			Message: r.Message,
			AddedAt: r.AddedAt,
		}
		if !projectOnly {
			globalEntries = append(globalEntries, entry)
		}
		idx++
	}

	pPath := custompolicy.ProjectCustomPath()
	pp, loadErr := custompolicy.LoadCustomPolicy(pPath)
	if loadErr != nil {
		return nil, nil, fmt.Errorf("rules: load project custom rules: %w", loadErr)
	}
	for _, r := range pp.FlattenRules() {
		entry := rulesEntry{
			Index:   idx,
			Source:  "project",
			Action:  r.Action,
			Tool:    r.Tool,
			Pattern: r.Pattern,
			Message: r.Message,
			AddedAt: r.AddedAt,
		}
		if !globalOnly {
			projectEntries = append(projectEntries, entry)
		}
		idx++
	}

	return globalEntries, projectEntries, nil
}

// printRulesTable renders the lipgloss-styled table.
func printRulesTable(out io.Writer, opts *rootOptions, globalEntries, projectEntries []rulesEntry, globalOnly, projectOnly bool) error {
	all := append(globalEntries, projectEntries...) //nolint:gocritic

	div := rulesDivStyle.Render(strings.Repeat("─", 62))

	fmt.Fprintln(out)
	fmt.Fprintf(out, "  %s\n", rulesHeaderStyle.Render("Custom Rules"))
	fmt.Fprintf(out, "  %s\n", div)

	if len(all) == 0 {
		fmt.Fprintln(out)
		fmt.Fprintf(out, "  %s\n", rulesHintStyle.Render("No custom rules found."))
		fmt.Fprintln(out)
		fmt.Fprintf(out, "  %s\n", rulesHintStyle.Render("Add rules with:"))
		fmt.Fprintf(out, "    %s\n", rulesHintStyle.Render("rampart allow \"command pattern\""))
		fmt.Fprintf(out, "    %s\n", rulesHintStyle.Render("rampart block \"command pattern\""))
		fmt.Fprintln(out)
		return nil
	}

	printSection := func(entries []rulesEntry, label, path string) {
		if len(entries) == 0 {
			return
		}
		fmt.Fprintln(out)
		fmt.Fprintf(out, "  %s\n", rulesSourceStyle.Render(label))
		fmt.Fprintf(out, "  %s\n", rulesHintStyle.Render(path))
		fmt.Fprintln(out)
		// Header row
		fmt.Fprintf(out, "  %-4s  %-7s  %-8s  %-36s  %s\n",
			rulesNumStyle.Render("#"),
			rulesHeaderStyle.Render("ACTION"),
			rulesHeaderStyle.Render("TOOL"),
			rulesHeaderStyle.Render("PATTERN"),
			rulesHeaderStyle.Render("ADDED"),
		)
		for _, e := range entries {
			actionStr := rulesActionStyle(e.Action)
			toolStr := rulesToolStyle.Render(padRight(e.Tool, 8))
			patStr := rulesPatStyle.Render(truncateStr(e.Pattern, 36))
			timeStr := rulesTimeStyle.Render(rulesRelTime(e.AddedAt))
			fmt.Fprintf(out, "  %-4s  %-7s  %s  %-36s  %s\n",
				rulesNumStyle.Render(padLeft(fmt.Sprintf("%d", e.Index), 4)),
				actionStr,
				toolStr,
				patStr,
				timeStr,
			)
			// Show message as subline if present
			if e.Message != "" {
				fmt.Fprintf(out, "        %s\n", rulesHintStyle.Render("→ "+truncateStr(e.Message, 60)))
			}
		}
	}

	if !projectOnly {
		gPath, _ := custompolicy.GlobalCustomPath()
		printSection(globalEntries, "Global", gPath)
	}

	if !globalOnly {
		pPath := custompolicy.ProjectCustomPath()
		printSection(projectEntries, "Project", pPath)
	}

	fmt.Fprintln(out)
	fmt.Fprintf(out, "  %s\n", div)

	// Summary line: count custom vs total
	totalCustom := len(all)
	standardCount := countStandardRules(opts)
	if standardCount > 0 {
		fmt.Fprintf(out, "  %s\n", rulesHintStyle.Render(
			fmt.Sprintf("Total: %d rules (%d standard + %d custom)", standardCount+totalCustom, standardCount, totalCustom),
		))
	} else {
		fmt.Fprintf(out, "  %s\n", rulesHintStyle.Render(
			fmt.Sprintf("Total: %d custom rule(s)", totalCustom),
		))
	}
	if totalCustom > 0 {
		fmt.Fprintf(out, "  %s\n", rulesHintStyle.Render("Manage: rampart rules remove <#>"))
	}
	fmt.Fprintln(out)

	return nil
}

func printRulesJSON(out io.Writer, entries []rulesEntry) error {
	type jsonEntry struct {
		Index   int    `json:"index"`
		Source  string `json:"source"`
		Action  string `json:"action"`
		Tool    string `json:"tool"`
		Pattern string `json:"pattern"`
		Message string `json:"message,omitempty"`
		AddedAt string `json:"added_at"`
	}
	result := make([]jsonEntry, 0, len(entries))
	for _, e := range entries {
		result = append(result, jsonEntry{
			Index:   e.Index,
			Source:  e.Source,
			Action:  e.Action,
			Tool:    e.Tool,
			Pattern: e.Pattern,
			Message: e.Message,
			AddedAt: e.AddedAt.UTC().Format(time.RFC3339),
		})
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// ─── Remove ──────────────────────────────────────────────────────────────────

func newRulesRemoveCmd(opts *rootOptions) *cobra.Command {
	var force bool
	var apiAddr string
	var token string

	cmd := &cobra.Command{
		Use:   "remove <index>",
		Short: "Remove a custom rule by index",
		Long:  "Remove a specific custom rule shown by 'rampart rules'.",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf(`missing index argument

Usage: rampart rules remove <index>

First run 'rampart rules' to see rule numbers, then:
  rampart rules remove 1    # Remove rule #1
  rampart rules remove 3    # Remove rule #3`)
			}
			// Check if argument looks like a negative number (user mistake)
			if strings.HasPrefix(args[0], "-") && len(args[0]) > 1 {
				// Check if it's a number
				if _, err := strconv.Atoi(args[0]); err == nil {
					return fmt.Errorf("rules: invalid index %q — must be a positive integer", args[0])
				}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRulesRemove(cmd, opts, args[0], force, apiAddr, token)
		},
		SilenceUsage: true,
	}

	cmd.Flags().BoolVar(&force, "force", false, "Skip confirmation prompt")
	cmd.Flags().StringVar(&apiAddr, "api", "", "Rampart API address override for reload (default: auto-discover via url/config/state)")
	cmd.Flags().StringVar(&token, "token", "", "API auth token (or set RAMPART_TOKEN)")

	// Custom error handler to catch negative numbers being parsed as flags
	cmd.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		errStr := err.Error()
		// Check if error is about a flag that looks like a negative number
		if strings.Contains(errStr, "unknown shorthand flag") ||
			strings.Contains(errStr, "unknown flag") {
			// Extract what they tried to use
			if strings.Contains(errStr, "-") {
				return fmt.Errorf("rules: invalid index — must be a positive integer (indices start at 1)")
			}
		}
		return err
	})

	return cmd
}

func runRulesRemove(cmd *cobra.Command, opts *rootOptions, indexStr string, force bool, apiAddr, token string) error {
	displayIdx, err := strconv.Atoi(indexStr)
	if err != nil || displayIdx < 1 {
		return fmt.Errorf("rules: invalid index %q — must be a positive integer", indexStr)
	}

	// Load all entries to find which source the index belongs to.
	globalEntries, projectEntries, err := loadAllEntries(false, false)
	if err != nil {
		return err
	}

	var target *rulesEntry
	for i := range globalEntries {
		if globalEntries[i].Index == displayIdx {
			e := globalEntries[i]
			target = &e
			break
		}
	}
	if target == nil {
		for i := range projectEntries {
			if projectEntries[i].Index == displayIdx {
				e := projectEntries[i]
				target = &e
				break
			}
		}
	}

	if target == nil {
		total := len(globalEntries) + len(projectEntries)
		return fmt.Errorf("rules: index %d not found (have %d rule(s))", displayIdx, total)
	}

	out := cmd.OutOrStdout()
	fmt.Fprintln(out)
	fmt.Fprintf(out, "  %s\n\n", rulesHeaderStyle.Render("Remove this rule?"))
	fmt.Fprintf(out, "    Action:  %s\n", rulesActionStyle(target.Action))
	fmt.Fprintf(out, "    Tool:    %s\n", rulesToolStyle.Render(target.Tool))
	fmt.Fprintf(out, "    Pattern: %s\n", rulesPatStyle.Render(target.Pattern))
	fmt.Fprintf(out, "    Added:   %s\n", rulesTimeStyle.Render(rulesRelTime(target.AddedAt)))
	fmt.Fprintf(out, "    Source:  %s\n\n", rulesHintStyle.Render(target.Source))

	if !force {
		ok, promptErr := confirmPrompt(cmd.InOrStdin(), out, "[y/N] ")
		if promptErr != nil {
			return promptErr
		}
		if !ok {
			fmt.Fprintf(out, "  %s\n\n", rulesHintStyle.Render("Cancelled."))
			return nil
		}
	}

	// Determine zero-based index within the source file.
	var sourceIdx int
	if target.Source == "global" {
		for i, e := range globalEntries {
			if e.Index == displayIdx {
				sourceIdx = i
				break
			}
		}
	} else {
		for i, e := range projectEntries {
			if e.Index == displayIdx {
				sourceIdx = i
				break
			}
		}
	}

	if err := removeRuleFromSource(target.Source, sourceIdx); err != nil {
		return err
	}

	totalAfter := len(globalEntries) + len(projectEntries) - 1
	standardCount := countStandardRules(opts)
	fmt.Fprintf(out, "  %s\n", rulesOkStyle.Render("✓ Rule removed"))

	// Try to reload the daemon.
	resolvedToken := resolveToken(token)
	resolvedAddr, err := resolveAddrAllow(apiAddr)
	if err != nil {
		return fmt.Errorf("rules: resolve reload API address: %w", err)
	}
	reloaded, _ := reloadPolicy(cmd, resolvedAddr, resolvedToken)
	if reloaded {
		fmt.Fprintf(out, "  %s\n\n", rulesOkStyle.Render(
			fmt.Sprintf("✓ Policy reloaded (%d rules active)", standardCount+totalAfter),
		))
	} else {
		fmt.Fprintf(out, "  %s\n\n", rulesHintStyle.Render(
			fmt.Sprintf("Saved (%d rules). Run 'rampart serve' to activate.", standardCount+totalAfter),
		))
	}

	return nil
}

func removeRuleFromSource(source string, sourceIdx int) error {
	var path string
	if source == "global" {
		gPath, err := custompolicy.GlobalCustomPath()
		if err != nil {
			return err
		}
		path = gPath
	} else {
		path = custompolicy.ProjectCustomPath()
	}

	cp, err := custompolicy.LoadCustomPolicy(path)
	if err != nil {
		return err
	}
	if err := custompolicy.RemoveRuleAt(cp, sourceIdx); err != nil {
		return err
	}
	return custompolicy.SaveCustomPolicy(path, cp)
}

// ─── Reset ───────────────────────────────────────────────────────────────────

func newRulesResetCmd(opts *rootOptions) *cobra.Command {
	var force bool
	var apiAddr string
	var token string

	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Remove all custom rules",
		Long:  "Remove all custom rules added via 'rampart allow' and 'rampart block'.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRulesReset(cmd, opts, force, apiAddr, token)
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Skip confirmation prompt")
	cmd.Flags().StringVar(&apiAddr, "api", "", "Rampart API address override for reload (default: auto-discover via url/config/state)")
	cmd.Flags().StringVar(&token, "token", "", "API auth token (or set RAMPART_TOKEN)")
	return cmd
}

func runRulesReset(cmd *cobra.Command, opts *rootOptions, force bool, apiAddr, token string) error {
	globalEntries, projectEntries, err := loadAllEntries(false, false)
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	totalCustom := len(globalEntries) + len(projectEntries)

	if totalCustom == 0 {
		fmt.Fprintf(out, "\n  %s\n\n", rulesHintStyle.Render("No custom rules to remove."))
		return nil
	}

	fmt.Fprintln(out)
	fmt.Fprintf(out, "  %s\n\n", rulesHeaderStyle.Render("This will remove all custom rules:"))
	if len(globalEntries) > 0 {
		fmt.Fprintf(out, "    Global:  %d rule(s)\n", len(globalEntries))
	}
	if len(projectEntries) > 0 {
		fmt.Fprintf(out, "    Project: %d rule(s)\n", len(projectEntries))
	}
	standardCount := countStandardRules(opts)
	if standardCount > 0 {
		fmt.Fprintf(out, "\n  %s\n\n",
			rulesHintStyle.Render(fmt.Sprintf("Standard policy (%d rules) will not be affected.", standardCount)),
		)
	} else {
		fmt.Fprintln(out)
	}

	if !force {
		ok, promptErr := confirmPrompt(cmd.InOrStdin(), out, "Reset? [y/N] ")
		if promptErr != nil {
			return promptErr
		}
		if !ok {
			fmt.Fprintf(out, "  %s\n\n", rulesHintStyle.Render("Cancelled."))
			return nil
		}
	}

	// Clear global rules.
	if len(globalEntries) > 0 {
		gPath, pathErr := custompolicy.GlobalCustomPath()
		if pathErr != nil {
			return pathErr
		}
		if saveErr := custompolicy.SaveCustomPolicy(gPath, &custompolicy.CustomPolicy{Version: "1"}); saveErr != nil {
			return fmt.Errorf("rules: clear global custom rules: %w", saveErr)
		}
	}

	// Clear project rules.
	if len(projectEntries) > 0 {
		pPath := custompolicy.ProjectCustomPath()
		if saveErr := custompolicy.SaveCustomPolicy(pPath, &custompolicy.CustomPolicy{Version: "1"}); saveErr != nil {
			return fmt.Errorf("rules: clear project custom rules: %w", saveErr)
		}
	}

	fmt.Fprintf(out, "  %s\n", rulesOkStyle.Render(fmt.Sprintf("✓ Removed %d custom rule(s)", totalCustom)))

	// Try to reload the daemon.
	resolvedToken := resolveToken(token)
	resolvedAddr, err := resolveAddrAllow(apiAddr)
	if err != nil {
		return fmt.Errorf("rules: resolve reload API address: %w", err)
	}
	reloaded, _ := reloadPolicy(cmd, resolvedAddr, resolvedToken)
	if reloaded {
		fmt.Fprintf(out, "  %s\n\n", rulesOkStyle.Render(
			fmt.Sprintf("✓ Policy reloaded (%d rules active)", standardCount),
		))
	} else {
		fmt.Fprintf(out, "  %s\n\n", rulesHintStyle.Render(
			fmt.Sprintf("Saved (%d rules). Run 'rampart serve' to activate.", standardCount),
		))
	}

	return nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// rulesRelTime formats a timestamp as a human-friendly relative string.
func rulesRelTime(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		m := int(d.Minutes())
		if m == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", m)
	case d < 24*time.Hour:
		h := int(d.Hours())
		if h == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", h)
	case d < 7*24*time.Hour:
		days := int(d.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	case d < 30*24*time.Hour:
		weeks := int(d.Hours() / 24 / 7)
		if weeks == 1 {
			return "1 week ago"
		}
		return fmt.Sprintf("%d weeks ago", weeks)
	default:
		return t.Local().Format("2006-01-02")
	}
}

// rulesActionStyle returns the coloured action string.
func rulesActionStyle(action string) string {
	switch strings.ToLower(action) {
	case "allow":
		return rulesAllowStyle.Render(padRight("allow", 7))
	case "deny", "block":
		return rulesDenyStyle.Render(padRight("deny", 7))
	default:
		return rulesNumStyle.Render(padRight(action, 7))
	}
}

// countStandardRules returns the number of rules in the configured policy file.
func countStandardRules(opts *rootOptions) int {
	if opts == nil || opts.configPath == "" {
		return 0
	}
	data, err := os.ReadFile(opts.configPath)
	if err != nil {
		return 0
	}
	// Quick heuristic: count "- action:" occurrences (each rule has one).
	return strings.Count(string(data), "- action:")
}

// confirmPrompt prints prompt and reads a y/n answer from r.
func confirmPrompt(r io.Reader, out io.Writer, prompt string) (bool, error) {
	fmt.Fprint(out, "  "+prompt)
	reader := bufio.NewReader(r)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return false, fmt.Errorf("rules: read confirmation: %w", err)
	}
	ans := strings.ToLower(strings.TrimSpace(line))
	return ans == "y" || ans == "yes", nil
}

func padRight(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

func padLeft(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return strings.Repeat(" ", width-len(s)) + s
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}
