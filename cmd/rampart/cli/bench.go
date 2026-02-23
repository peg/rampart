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
	"sort"
	"strings"
	"time"

	"github.com/peg/rampart/internal/engine"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type benchCorpusEntry struct {
	Command        string `yaml:"command" json:"command"`
	ExpectedAction string `yaml:"expected_action" json:"expected_action"`
	Category       string `yaml:"category" json:"category"`
	Description    string `yaml:"description" json:"description"`
}

type benchCorpusDocument struct {
	Entries []benchCorpusEntry `yaml:"entries"`
}

type benchCategorySummary struct {
	Category       string  `json:"category"`
	Total          int     `json:"total"`
	Matched        int     `json:"matched"`
	Mismatched     int     `json:"mismatched"`
	Blocked        int     `json:"blocked"`
	Approval       int     `json:"approval"`
	Watched        int     `json:"watched"`
	Allowed        int     `json:"allowed"`
	DenyTotal      int     `json:"deny_total"`
	HardDenied     int     `json:"hard_denied"`
	ApprovalGated  int     `json:"approval_gated"`
	Unhandled      int     `json:"unhandled"`
	Coverage       float64 `json:"coverage"`
	HardDeniedPct  float64 `json:"hard_denied_pct"`
	ApprovalPct    float64 `json:"approval_gated_pct"`
	UnhandledPct   float64 `json:"unhandled_pct"`
	ExactMatchRate float64 `json:"exact_match_rate"`
}

type benchGap struct {
	Category       string `json:"category"`
	Description    string `json:"description"`
	Command        string `json:"command"`
	ExpectedAction string `json:"expected_action"`
	ActualAction   string `json:"actual_action"`
	Message        string `json:"message"`
}

type benchCaseResult struct {
	Category       string `json:"category"`
	Description    string `json:"description"`
	Command        string `json:"command"`
	ExpectedAction string `json:"expected_action"`
	ActualAction   string `json:"actual_action"`
	Matched        bool   `json:"matched"`
	Message        string `json:"message"`
}

type benchSummary struct {
	PolicyPath       string                 `json:"policy_path"`
	CorpusPath       string                 `json:"corpus_path"`
	Category         string                 `json:"category,omitempty"`
	Strict           bool                   `json:"strict"`
	Total            int                    `json:"total"`
	Matched          int                    `json:"matched"`
	Mismatched       int                    `json:"mismatched"`
	Score            float64                `json:"score"`
	Blocked          int                    `json:"blocked"`
	BlockedPct       float64                `json:"blocked_pct"`
	Approval         int                    `json:"approval"`
	ApprovalPct      float64                `json:"approval_pct"`
	Watched          int                    `json:"watched"`
	WatchedPct       float64                `json:"watched_pct"`
	Allowed          int                    `json:"allowed"`
	AllowedPct       float64                `json:"allowed_pct"`
	DenyTotal        int                    `json:"deny_total"`
	HardDenied       int                    `json:"hard_denied"`
	HardDeniedPct    float64                `json:"hard_denied_pct"`
	ApprovalGated    int                    `json:"approval_gated"`
	ApprovalGatedPct float64                `json:"approval_gated_pct"`
	Unhandled        int                    `json:"unhandled"`
	UnhandledPct     float64                `json:"unhandled_pct"`
	Coverage         float64                `json:"coverage"`
	ByCategory       []benchCategorySummary `json:"by_category"`
	Gaps             []benchGap             `json:"gaps"`
	Results          []benchCaseResult      `json:"results,omitempty"`
}

type benchRunOptions struct {
	PolicyPath string
	CorpusPath string
	Category   string
	Verbose    bool
	Strict     bool
}

func newBenchCmd(_ *rootOptions) *cobra.Command {
	var (
		policyPath string
		corpusPath string
		category   string
		jsonOut    bool
		verbose    bool
		strict     bool
	)

	cmd := &cobra.Command{
		Use:   "bench",
		Short: "Score policy coverage against an attack corpus",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			summary, err := runBench(benchRunOptions{
				PolicyPath: policyPath,
				CorpusPath: corpusPath,
				Category:   category,
				Verbose:    verbose,
				Strict:     strict,
			})
			if err != nil {
				return err
			}

			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(summary); err != nil {
					return fmt.Errorf("bench: write JSON output: %w", err)
				}
			} else {
				if err := printBenchSummary(cmd.OutOrStdout(), summary, verbose); err != nil {
					return err
				}
			}

			if summary.Mismatched > 0 {
				return exitCodeError{code: 1}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&policyPath, "policy", "~/.rampart/policies/standard.yaml", "Path to policy file")
	cmd.Flags().StringVar(&corpusPath, "corpus", "bench/corpus.yaml", "Path to benchmark corpus YAML")
	cmd.Flags().StringVar(&category, "category", "", "Filter to a single corpus category")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output results as JSON")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "Include per-case results")
	cmd.Flags().BoolVar(&strict, "strict", false, "Treat require_approval as a miss for deny expectations")

	return cmd
}

func runBench(opts benchRunOptions) (benchSummary, error) {
	policyPath, err := expandBenchPath(opts.PolicyPath)
	if err != nil {
		return benchSummary{}, err
	}

	corpusPath, err := expandBenchPath(opts.CorpusPath)
	if err != nil {
		return benchSummary{}, err
	}

	store := engine.NewFileStore(policyPath)
	eng, err := engine.New(store, nil)
	if err != nil {
		return benchSummary{}, fmt.Errorf("bench: load policy: %w", err)
	}

	entries, err := loadBenchCorpus(corpusPath)
	if err != nil {
		return benchSummary{}, err
	}

	category := strings.ToLower(strings.TrimSpace(opts.Category))
	if category != "" {
		filtered := make([]benchCorpusEntry, 0, len(entries))
		for _, entry := range entries {
			if strings.EqualFold(entry.Category, category) {
				filtered = append(filtered, entry)
			}
		}
		entries = filtered
	}

	if len(entries) == 0 {
		if category != "" {
			return benchSummary{}, fmt.Errorf("bench: no corpus entries found for category %q", category)
		}
		return benchSummary{}, fmt.Errorf("bench: corpus contains no entries")
	}

	type categoryCounter struct {
		Total         int
		Matched       int
		Mismatched    int
		Blocked       int
		Approval      int
		Watched       int
		Allowed       int
		DenyTotal     int
		HardDenied    int
		ApprovalGated int
		Unhandled     int
	}

	byCategory := make(map[string]*categoryCounter)
	summary := benchSummary{
		PolicyPath: policyPath,
		CorpusPath: corpusPath,
		Category:   category,
		Strict:     opts.Strict,
		Total:      len(entries),
	}
	if opts.Verbose {
		summary.Results = make([]benchCaseResult, 0, len(entries))
	}

	for _, entry := range entries {
		decision := eng.Evaluate(engine.ToolCall{
			Agent:     "*",
			Tool:      "exec",
			Params:    map[string]any{"command": entry.Command},
			Timestamp: time.Now().UTC(),
		})

		actual := decision.Action.String()
		matched := benchExpectedMatch(entry.ExpectedAction, actual, opts.Strict)

		cat := strings.ToLower(strings.TrimSpace(entry.Category))
		if byCategory[cat] == nil {
			byCategory[cat] = &categoryCounter{}
		}
		categoryStats := byCategory[cat]
		categoryStats.Total++
		if matched {
			categoryStats.Matched++
		} else {
			categoryStats.Mismatched++
		}

		switch actual {
		case "deny":
			summary.Blocked++
			categoryStats.Blocked++
		case "require_approval":
			summary.Approval++
			categoryStats.Approval++
		case "watch":
			summary.Watched++
			categoryStats.Watched++
		default:
			summary.Allowed++
			categoryStats.Allowed++
		}

		if entry.ExpectedAction == "deny" {
			summary.DenyTotal++
			categoryStats.DenyTotal++
			switch actual {
			case "deny":
				summary.HardDenied++
				categoryStats.HardDenied++
			case "require_approval":
				summary.ApprovalGated++
				categoryStats.ApprovalGated++
			default:
				summary.Unhandled++
				categoryStats.Unhandled++
			}
		}

		if matched {
			summary.Matched++
		} else {
			summary.Mismatched++
			summary.Gaps = append(summary.Gaps, benchGap{
				Category:       entry.Category,
				Description:    entry.Description,
				Command:        entry.Command,
				ExpectedAction: entry.ExpectedAction,
				ActualAction:   actual,
				Message:        decision.Message,
			})
		}

		if opts.Verbose {
			summary.Results = append(summary.Results, benchCaseResult{
				Category:       entry.Category,
				Description:    entry.Description,
				Command:        entry.Command,
				ExpectedAction: entry.ExpectedAction,
				ActualAction:   actual,
				Matched:        matched,
				Message:        decision.Message,
			})
		}
	}

	summary.Score = percent(summary.Matched, summary.Total)
	summary.BlockedPct = percent(summary.Blocked, summary.Total)
	summary.ApprovalPct = percent(summary.Approval, summary.Total)
	summary.WatchedPct = percent(summary.Watched, summary.Total)
	summary.AllowedPct = percent(summary.Allowed, summary.Total)
	summary.HardDeniedPct = percent(summary.HardDenied, summary.DenyTotal)
	summary.ApprovalGatedPct = percent(summary.ApprovalGated, summary.DenyTotal)
	summary.UnhandledPct = percent(summary.Unhandled, summary.DenyTotal)
	if opts.Strict {
		summary.Coverage = percent(summary.HardDenied, summary.DenyTotal)
	} else {
		summary.Coverage = percent(summary.HardDenied+summary.ApprovalGated, summary.DenyTotal)
	}

	categories := make([]string, 0, len(byCategory))
	for name := range byCategory {
		categories = append(categories, name)
	}
	sort.Strings(categories)

	summary.ByCategory = make([]benchCategorySummary, 0, len(categories))
	for _, name := range categories {
		stats := byCategory[name]
		var coverage float64
		if opts.Strict {
			coverage = percent(stats.HardDenied, stats.DenyTotal)
		} else {
			coverage = percent(stats.HardDenied+stats.ApprovalGated, stats.DenyTotal)
		}
		summary.ByCategory = append(summary.ByCategory, benchCategorySummary{
			Category:       name,
			Total:          stats.Total,
			Matched:        stats.Matched,
			Mismatched:     stats.Mismatched,
			Blocked:        stats.Blocked,
			Approval:       stats.Approval,
			Watched:        stats.Watched,
			Allowed:        stats.Allowed,
			DenyTotal:      stats.DenyTotal,
			HardDenied:     stats.HardDenied,
			ApprovalGated:  stats.ApprovalGated,
			Unhandled:      stats.Unhandled,
			Coverage:       coverage,
			HardDeniedPct:  percent(stats.HardDenied, stats.DenyTotal),
			ApprovalPct:    percent(stats.ApprovalGated, stats.DenyTotal),
			UnhandledPct:   percent(stats.Unhandled, stats.DenyTotal),
			ExactMatchRate: percent(stats.Matched, stats.Total),
		})
	}

	return summary, nil
}

func printBenchSummary(w io.Writer, summary benchSummary, verbose bool) error {
	if _, err := fmt.Fprintln(w, "Rampart Bench"); err != nil {
		return fmt.Errorf("bench: write output: %w", err)
	}
	if _, err := fmt.Fprintf(w, "Policy: %s\n", summary.PolicyPath); err != nil {
		return fmt.Errorf("bench: write output: %w", err)
	}
	if _, err := fmt.Fprintf(w, "Corpus: %s\n", summary.CorpusPath); err != nil {
		return fmt.Errorf("bench: write output: %w", err)
	}
	if summary.Category != "" {
		if _, err := fmt.Fprintf(w, "Category: %s\n", summary.Category); err != nil {
			return fmt.Errorf("bench: write output: %w", err)
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return fmt.Errorf("bench: write output: %w", err)
	}
	if _, err := fmt.Fprintf(w, "Total: %d\n", summary.Total); err != nil {
		return fmt.Errorf("bench: write output: %w", err)
	}
	if summary.Strict {
		if _, err := fmt.Fprintln(w, "Mode: strict (require_approval counts as unhandled)"); err != nil {
			return fmt.Errorf("bench: write output: %w", err)
		}
	}
	if summary.DenyTotal == 0 {
		if _, err := fmt.Fprintln(w, "Coverage: n/a (no deny expectations in corpus)"); err != nil {
			return fmt.Errorf("bench: write output: %w", err)
		}
	} else {
		if _, err := fmt.Fprintf(
			w,
			"Coverage: %.1f%% (%.1f%% denied · %.1f%% approval-gated · %.1f%% unhandled)\n",
			summary.Coverage,
			summary.HardDeniedPct,
			summary.ApprovalGatedPct,
			summary.UnhandledPct,
		); err != nil {
			return fmt.Errorf("bench: write output: %w", err)
		}
		if _, err := fmt.Fprintf(
			w,
			"Counts: %d/%d denied · %d/%d approval-gated · %d/%d unhandled\n",
			summary.HardDenied,
			summary.DenyTotal,
			summary.ApprovalGated,
			summary.DenyTotal,
			summary.Unhandled,
			summary.DenyTotal,
		); err != nil {
			return fmt.Errorf("bench: write output: %w", err)
		}
	}
	if _, err := fmt.Fprintf(
		w,
		"Decisions: %.1f%% deny (%d) · %.1f%% require_approval (%d) · %.1f%% watch (%d) · %.1f%% allow (%d)\n",
		summary.BlockedPct,
		summary.Blocked,
		summary.ApprovalPct,
		summary.Approval,
		summary.WatchedPct,
		summary.Watched,
		summary.AllowedPct,
		summary.Allowed,
	); err != nil {
		return fmt.Errorf("bench: write output: %w", err)
	}

	if _, err := fmt.Fprintln(w, "\nBy category:"); err != nil {
		return fmt.Errorf("bench: write output: %w", err)
	}
	for _, item := range summary.ByCategory {
		if item.DenyTotal == 0 {
			if _, err := fmt.Fprintf(w,
				"  %-20s n/a    (0 deny, 0 approval, 0 missed)\n",
				item.Category,
			); err != nil {
				return fmt.Errorf("bench: write output: %w", err)
			}
			continue
		}
		if _, err := fmt.Fprintf(w,
			"  %-20s %5.1f%%  (%d/%d deny, %d/%d approval, %d/%d missed)\n",
			item.Category,
			item.Coverage,
			item.HardDenied,
			item.DenyTotal,
			item.ApprovalGated,
			item.DenyTotal,
			item.Unhandled,
			item.DenyTotal,
		); err != nil {
			return fmt.Errorf("bench: write output: %w", err)
		}
	}

	if len(summary.Gaps) > 0 {
		if _, err := fmt.Fprintf(w, "\nGaps (%d):\n", len(summary.Gaps)); err != nil {
			return fmt.Errorf("bench: write output: %w", err)
		}
		for _, gap := range summary.Gaps {
			if _, err := fmt.Fprintf(w,
				"  [%s] expected=%s got=%s\n    command: %s\n    note: %s\n",
				gap.Category,
				gap.ExpectedAction,
				gap.ActualAction,
				truncateBench(gap.Command, 200),
				gap.Description,
			); err != nil {
				return fmt.Errorf("bench: write output: %w", err)
			}
		}
	} else {
		if _, err := fmt.Fprintln(w, "\nGaps: none"); err != nil {
			return fmt.Errorf("bench: write output: %w", err)
		}
	}

	if verbose {
		if _, err := fmt.Fprintln(w, "\nCases:"); err != nil {
			return fmt.Errorf("bench: write output: %w", err)
		}
		for _, result := range summary.Results {
			status := "PASS"
			if !result.Matched {
				status = "FAIL"
			}
			if _, err := fmt.Fprintf(w,
				"  %-4s [%s] expected=%s got=%s :: %s\n",
				status,
				result.Category,
				result.ExpectedAction,
				result.ActualAction,
				truncateBench(result.Command, 200),
			); err != nil {
				return fmt.Errorf("bench: write output: %w", err)
			}
		}
	}

	return nil
}

func loadBenchCorpus(path string) ([]benchCorpusEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("bench: read corpus: %w", err)
	}

	var doc benchCorpusDocument
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("bench: parse corpus YAML: %w", err)
	}

	entries := doc.Entries
	if len(entries) == 0 {
		if err := yaml.Unmarshal(data, &entries); err != nil {
			return nil, fmt.Errorf("bench: parse corpus YAML: %w", err)
		}
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("bench: corpus contains no entries")
	}

	for i := range entries {
		entries[i].Command = strings.TrimSpace(entries[i].Command)
		entries[i].ExpectedAction = strings.ToLower(strings.TrimSpace(entries[i].ExpectedAction))
		entries[i].Category = strings.ToLower(strings.TrimSpace(entries[i].Category))
		entries[i].Description = strings.TrimSpace(entries[i].Description)

		if entries[i].Command == "" {
			return nil, fmt.Errorf("bench: corpus entry %d has empty command", i)
		}
		if entries[i].Category == "" {
			return nil, fmt.Errorf("bench: corpus entry %d has empty category", i)
		}
		action, err := engine.ParseAction(entries[i].ExpectedAction)
		if err != nil {
			return nil, fmt.Errorf("bench: corpus entry %d has invalid expected_action %q", i, entries[i].ExpectedAction)
		}
		if action != engine.ActionAllow && action != engine.ActionDeny && action != engine.ActionWatch {
			return nil, fmt.Errorf("bench: corpus entry %d expected_action must be allow, deny, or watch", i)
		}
	}

	return entries, nil
}

func percent(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) * 100 / float64(total)
}

func benchExpectedMatch(expected, actual string, strict bool) bool {
	if actual == expected {
		return true
	}
	if !strict && expected == "deny" && actual == "require_approval" {
		return true
	}
	return false
}

func truncateBench(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

func expandBenchPath(path string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", fmt.Errorf("bench: path cannot be empty")
	}
	if trimmed == "~" || strings.HasPrefix(trimmed, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("bench: resolve home dir: %w", err)
		}
		if trimmed == "~" {
			trimmed = home
		} else {
			trimmed = filepath.Join(home, strings.TrimPrefix(trimmed, "~/"))
		}
	}
	return trimmed, nil
}
