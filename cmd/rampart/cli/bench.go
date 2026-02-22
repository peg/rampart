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
	Category   string  `json:"category"`
	Total      int     `json:"total"`
	Matched    int     `json:"matched"`
	Mismatched int     `json:"mismatched"`
	Blocked    int     `json:"blocked"`
	Watched    int     `json:"watched"`
	Allowed    int     `json:"allowed"`
	Score      float64 `json:"score"`
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
	PolicyPath string                 `json:"policy_path"`
	CorpusPath string                 `json:"corpus_path"`
	Category   string                 `json:"category,omitempty"`
	Total      int                    `json:"total"`
	Matched    int                    `json:"matched"`
	Mismatched int                    `json:"mismatched"`
	Score      float64                `json:"score"`
	Blocked    int                    `json:"blocked"`
	BlockedPct float64                `json:"blocked_pct"`
	Watched    int                    `json:"watched"`
	WatchedPct float64                `json:"watched_pct"`
	Allowed    int                    `json:"allowed"`
	AllowedPct float64                `json:"allowed_pct"`
	ByCategory []benchCategorySummary `json:"by_category"`
	Gaps       []benchGap             `json:"gaps"`
	Results    []benchCaseResult      `json:"results,omitempty"`
}

type benchRunOptions struct {
	PolicyPath string
	CorpusPath string
	Category   string
	Verbose    bool
}

func newBenchCmd(_ *rootOptions) *cobra.Command {
	var (
		policyPath string
		corpusPath string
		category   string
		jsonOut    bool
		verbose    bool
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
		Total      int
		Matched    int
		Mismatched int
		Blocked    int
		Watched    int
		Allowed    int
	}

	byCategory := make(map[string]*categoryCounter)
	summary := benchSummary{
		PolicyPath: policyPath,
		CorpusPath: corpusPath,
		Category:   category,
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
		matched := actual == entry.ExpectedAction

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
		case "watch":
			summary.Watched++
			categoryStats.Watched++
		default:
			summary.Allowed++
			categoryStats.Allowed++
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
	summary.WatchedPct = percent(summary.Watched, summary.Total)
	summary.AllowedPct = percent(summary.Allowed, summary.Total)

	categories := make([]string, 0, len(byCategory))
	for name := range byCategory {
		categories = append(categories, name)
	}
	sort.Strings(categories)

	summary.ByCategory = make([]benchCategorySummary, 0, len(categories))
	for _, name := range categories {
		stats := byCategory[name]
		summary.ByCategory = append(summary.ByCategory, benchCategorySummary{
			Category:   name,
			Total:      stats.Total,
			Matched:    stats.Matched,
			Mismatched: stats.Mismatched,
			Blocked:    stats.Blocked,
			Watched:    stats.Watched,
			Allowed:    stats.Allowed,
			Score:      percent(stats.Matched, stats.Total),
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
	if _, err := fmt.Fprintf(w, "Score: %.1f%% (%d/%d matched)\n", summary.Score, summary.Matched, summary.Total); err != nil {
		return fmt.Errorf("bench: write output: %w", err)
	}
	if _, err := fmt.Fprintf(w, "Blocked: %.1f%% (%d)\n", summary.BlockedPct, summary.Blocked); err != nil {
		return fmt.Errorf("bench: write output: %w", err)
	}
	if _, err := fmt.Fprintf(w, "Watched: %.1f%% (%d)\n", summary.WatchedPct, summary.Watched); err != nil {
		return fmt.Errorf("bench: write output: %w", err)
	}
	if _, err := fmt.Fprintf(w, "Allowed: %.1f%% (%d)\n", summary.AllowedPct, summary.Allowed); err != nil {
		return fmt.Errorf("bench: write output: %w", err)
	}

	if _, err := fmt.Fprintln(w, "\nBy category:"); err != nil {
		return fmt.Errorf("bench: write output: %w", err)
	}
	for _, item := range summary.ByCategory {
		if _, err := fmt.Fprintf(w,
			"  %-20s total:%3d score:%5.1f%% deny:%3d watch:%3d allow:%3d\n",
			item.Category,
			item.Total,
			item.Score,
			item.Blocked,
			item.Watched,
			item.Allowed,
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
