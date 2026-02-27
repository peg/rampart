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
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/peg/rampart/bench"
	"github.com/peg/rampart/internal/engine"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type benchCorpusV1Entry struct {
	Command        string `yaml:"command"`
	ExpectedAction string `yaml:"expected_action"`
	Category       string `yaml:"category"`
	Description    string `yaml:"description"`
}

type benchCorpusV1Document struct {
	Entries []benchCorpusV1Entry `yaml:"entries"`
}

type benchCorpusV2Input struct {
	Command string `yaml:"command"`
	Path    string `yaml:"path"`
	Content string `yaml:"content"`
}

type benchCorpusV2Case struct {
	ID          string             `yaml:"id"`
	Name        string             `yaml:"name"`
	Description string             `yaml:"description,omitempty"`
	Category    string             `yaml:"category"`
	Technique   string             `yaml:"technique,omitempty"`
	Severity    string             `yaml:"severity"`
	OS          string             `yaml:"os"`
	Tool        string             `yaml:"tool"`
	Input       benchCorpusV2Input `yaml:"input"`
	Expected    string             `yaml:"expected"`
}

type benchCorpusV2Defaults struct {
	OS       string `yaml:"os"`
	Expected string `yaml:"expected"`
}

type benchCorpusV2Document struct {
	Version     string                `yaml:"version"`
	Name        string                `yaml:"name"`
	Description string                `yaml:"description"`
	Defaults    benchCorpusV2Defaults `yaml:"defaults"`
	Cases       []benchCorpusV2Case   `yaml:"cases"`
}

type benchCase struct {
	ID          string
	Name        string
	Description string
	Category    string
	Technique   string
	Severity    string
	OS          string
	Tool        string
	Input       benchCorpusV2Input
	Expected    string
}

type benchCategorySummary struct {
	Category         string  `json:"category"`
	Total            int     `json:"total"`
	Covered          int     `json:"covered"`
	Coverage         float64 `json:"coverage"`
	WeightedCovered  float64 `json:"weighted_covered"`
	WeightedTotal    float64 `json:"weighted_total"`
	WeightedCoverage float64 `json:"weighted_coverage"`
}

type benchGap struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Category  string `json:"category"`
	Severity  string `json:"severity"`
	Technique string `json:"technique,omitempty"`
	Tool      string `json:"tool"`
	Input     string `json:"input"`
	Expected  string `json:"expected"`
	Actual    string `json:"actual"`
	Message   string `json:"message"`
}

type benchCaseResult struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Tool     string `json:"tool"`
	Input    string `json:"input"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
	Covered  bool   `json:"covered"`
	Message  string `json:"message"`
}

type benchSummary struct {
	PolicyPath       string                 `json:"policy_path"`
	CorpusPath       string                 `json:"corpus_path"`
	Category         string                 `json:"category,omitempty"`
	OSFilter         string                 `json:"os_filter"`
	Severity         string                 `json:"severity"`
	IDPrefix         string                 `json:"id_prefix,omitempty"`
	Strict           bool                   `json:"strict"`
	MinCoverage      float64                `json:"min_coverage"`
	Total            int                    `json:"total"`
	Covered          int                    `json:"covered"`
	Coverage         float64                `json:"coverage"`
	WeightedCovered  float64                `json:"weighted_covered"`
	WeightedTotal    float64                `json:"weighted_total"`
	WeightedCoverage float64                `json:"weighted_coverage"`
	Blocked          int                    `json:"blocked"`
	Approval         int                    `json:"approval"`
	Watched          int                    `json:"watched"`
	Allowed          int                    `json:"allowed"`
	ByCategory       []benchCategorySummary `json:"by_category"`
	Gaps             []benchGap             `json:"gaps"`
	Results          []benchCaseResult      `json:"results,omitempty"`
}

type benchRunOptions struct {
	PolicyPath        string
	CorpusPath        string
	Category          string
	Verbose           bool
	Strict            bool
	UseEmbeddedCorpus bool
	OSFilter          string
	MinCoverage       float64
	Severity          string
	IDPrefix          string
}

func newBenchCmd(_ *rootOptions) *cobra.Command {
	var (
		policyPath  string
		corpusPath  string
		category    string
		jsonOut     bool
		verbose     bool
		strict      bool
		osFilter    string
		minCoverage float64
		severity    string
		idPrefix    string
	)

	cmd := &cobra.Command{
		Use:   "bench",
		Short: "Score policy coverage against an attack corpus",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			summary, err := runBench(benchRunOptions{
				PolicyPath:        policyPath,
				CorpusPath:        corpusPath,
				Category:          category,
				Verbose:           verbose,
				Strict:            strict,
				UseEmbeddedCorpus: !cmd.Flags().Changed("corpus"),
				OSFilter:          osFilter,
				MinCoverage:       minCoverage,
				Severity:          severity,
				IDPrefix:          idPrefix,
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

			if summary.Coverage < summary.MinCoverage {
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
	cmd.Flags().BoolVar(&strict, "strict", false, "Count only deny as covered")
	cmd.Flags().StringVar(&osFilter, "os", currentBenchOS(), "Filter cases by OS: linux|darwin|windows|*")
	cmd.Flags().Float64Var(&minCoverage, "min-coverage", 0, "Exit 1 if coverage is below this percent")
	cmd.Flags().StringVar(&severity, "severity", "medium", "Minimum severity: critical|high|medium")
	cmd.Flags().StringVar(&idPrefix, "id", "", "Run only cases with this ID prefix")

	return cmd
}

func runBench(opts benchRunOptions) (benchSummary, error) {
	policyPath, err := expandBenchPath(opts.PolicyPath)
	if err != nil {
		return benchSummary{}, err
	}

	osFilter, err := normalizeBenchOS(opts.OSFilter)
	if err != nil {
		return benchSummary{}, err
	}
	severity, err := normalizeBenchSeverity(opts.Severity)
	if err != nil {
		return benchSummary{}, err
	}
	if opts.MinCoverage < 0 || opts.MinCoverage > 100 {
		return benchSummary{}, fmt.Errorf("bench: --min-coverage must be between 0 and 100")
	}

	store := engine.NewFileStore(policyPath)
	eng, err := engine.New(store, nil)
	if err != nil {
		return benchSummary{}, fmt.Errorf("bench: load policy: %w", err)
	}

	var (
		cases      []benchCase
		corpusPath string
	)
	if opts.UseEmbeddedCorpus {
		corpusPath = "built-in"
		cases, err = parseBenchCorpus(bench.CorpusYAML)
	} else {
		corpusPath, err = expandBenchPath(opts.CorpusPath)
		if err != nil {
			return benchSummary{}, err
		}
		cases, err = loadBenchCorpus(corpusPath)
	}
	if err != nil {
		return benchSummary{}, err
	}

	cases = filterBenchCases(cases, benchFilterOptions{
		Category: opts.Category,
		OSFilter: osFilter,
		Severity: severity,
		IDPrefix: opts.IDPrefix,
	})
	if len(cases) == 0 {
		return benchSummary{}, fmt.Errorf("bench: corpus contains no entries after filters")
	}

	type categoryCounter struct {
		Total         int
		Covered       int
		WeightedTotal float64
		WeightedCover float64
	}

	byCategory := make(map[string]*categoryCounter)
	summary := benchSummary{
		PolicyPath:  policyPath,
		CorpusPath:  corpusPath,
		Category:    strings.ToLower(strings.TrimSpace(opts.Category)),
		OSFilter:    osFilter,
		Severity:    severity,
		IDPrefix:    strings.ToUpper(strings.TrimSpace(opts.IDPrefix)),
		Strict:      opts.Strict,
		MinCoverage: opts.MinCoverage,
		Total:       len(cases),
	}
	if opts.Verbose {
		summary.Results = make([]benchCaseResult, 0, len(cases))
	}

	for _, tc := range cases {
		decision := eng.Evaluate(benchToolCall(tc))
		actual := decision.Action.String()
		covered := benchCovered(actual, opts.Strict)
		weight := benchSeverityWeight(tc.Severity)

		summary.WeightedTotal += weight
		cat := strings.ToLower(strings.TrimSpace(tc.Category))
		if byCategory[cat] == nil {
			byCategory[cat] = &categoryCounter{}
		}
		stats := byCategory[cat]
		stats.Total++
		stats.WeightedTotal += weight

		switch actual {
		case "deny":
			summary.Blocked++
		case "require_approval":
			summary.Approval++
		case "watch":
			summary.Watched++
		default:
			summary.Allowed++
		}

		if covered {
			summary.Covered++
			summary.WeightedCovered += weight
			stats.Covered++
			stats.WeightedCover += weight
		} else {
			summary.Gaps = append(summary.Gaps, benchGap{
				ID:        tc.ID,
				Name:      tc.Name,
				Category:  tc.Category,
				Severity:  tc.Severity,
				Technique: tc.Technique,
				Tool:      tc.Tool,
				Input:     benchCaseInputString(tc),
				Expected:  tc.Expected,
				Actual:    actual,
				Message:   decision.Message,
			})
		}

		if opts.Verbose {
			summary.Results = append(summary.Results, benchCaseResult{
				ID:       tc.ID,
				Category: tc.Category,
				Severity: tc.Severity,
				Tool:     tc.Tool,
				Input:    benchCaseInputString(tc),
				Expected: tc.Expected,
				Actual:   actual,
				Covered:  covered,
				Message:  decision.Message,
			})
		}
	}

	summary.Coverage = percent(summary.Covered, summary.Total)
	summary.WeightedCoverage = percentFloat(summary.WeightedCovered, summary.WeightedTotal)

	categories := make([]string, 0, len(byCategory))
	for name := range byCategory {
		categories = append(categories, name)
	}
	sort.Strings(categories)

	summary.ByCategory = make([]benchCategorySummary, 0, len(categories))
	for _, name := range categories {
		stats := byCategory[name]
		summary.ByCategory = append(summary.ByCategory, benchCategorySummary{
			Category:         name,
			Total:            stats.Total,
			Covered:          stats.Covered,
			Coverage:         percent(stats.Covered, stats.Total),
			WeightedCovered:  stats.WeightedCover,
			WeightedTotal:    stats.WeightedTotal,
			WeightedCoverage: percentFloat(stats.WeightedCover, stats.WeightedTotal),
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
	if _, err := fmt.Fprintf(w, "OS: %s\n", summary.OSFilter); err != nil {
		return fmt.Errorf("bench: write output: %w", err)
	}
	if _, err := fmt.Fprintf(w, "Severity: %s+\n", summary.Severity); err != nil {
		return fmt.Errorf("bench: write output: %w", err)
	}
	if summary.Category != "" {
		if _, err := fmt.Fprintf(w, "Category: %s\n", summary.Category); err != nil {
			return fmt.Errorf("bench: write output: %w", err)
		}
	}
	if summary.IDPrefix != "" {
		if _, err := fmt.Fprintf(w, "ID Prefix: %s\n", summary.IDPrefix); err != nil {
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
		if _, err := fmt.Fprintln(w, "Mode: strict (only deny counts as covered)"); err != nil {
			return fmt.Errorf("bench: write output: %w", err)
		}
	}
	if _, err := fmt.Fprintf(w, "Coverage: %.1f%% (%d/%d)\n", summary.Coverage, summary.Covered, summary.Total); err != nil {
		return fmt.Errorf("bench: write output: %w", err)
	}
	if _, err := fmt.Fprintf(w, "Weighted: %.1f%% (%.1f/%.1f)\n", summary.WeightedCoverage, summary.WeightedCovered, summary.WeightedTotal); err != nil {
		return fmt.Errorf("bench: write output: %w", err)
	}
	if _, err := fmt.Fprintf(w, "Decisions: deny=%d require_approval=%d watch=%d allow=%d\n", summary.Blocked, summary.Approval, summary.Watched, summary.Allowed); err != nil {
		return fmt.Errorf("bench: write output: %w", err)
	}
	if summary.MinCoverage > 0 {
		if _, err := fmt.Fprintf(w, "Threshold: %.1f%% (%s)\n", summary.MinCoverage, benchPassFail(summary.Coverage >= summary.MinCoverage)); err != nil {
			return fmt.Errorf("bench: write output: %w", err)
		}
	}

	if _, err := fmt.Fprintln(w, "\nBy category:"); err != nil {
		return fmt.Errorf("bench: write output: %w", err)
	}
	for _, item := range summary.ByCategory {
		if _, err := fmt.Fprintf(w, "  %-20s raw=%5.1f%% weighted=%5.1f%% (%d/%d)\n", item.Category, item.Coverage, item.WeightedCoverage, item.Covered, item.Total); err != nil {
			return fmt.Errorf("bench: write output: %w", err)
		}
	}

	if len(summary.Gaps) > 0 {
		if _, err := fmt.Fprintf(w, "\nGaps (%d):\n", len(summary.Gaps)); err != nil {
			return fmt.Errorf("bench: write output: %w", err)
		}
		for _, gap := range summary.Gaps {
			if _, err := fmt.Fprintf(w, "  [%s] %s (%s, %s)", gap.ID, gap.Name, gap.Category, gap.Severity); err != nil {
				return fmt.Errorf("bench: write output: %w", err)
			}
			if gap.Technique != "" {
				if _, err := fmt.Fprintf(w, " technique=%s", gap.Technique); err != nil {
					return fmt.Errorf("bench: write output: %w", err)
				}
			}
			if _, err := fmt.Fprintf(w, "\n    tool=%s input=%s expected=%s got=%s\n", gap.Tool, truncateBench(gap.Input, 160), gap.Expected, gap.Actual); err != nil {
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
			status := "FAIL"
			if result.Covered {
				status = "PASS"
			}
			if _, err := fmt.Fprintf(w, "  %-4s [%s] %s %s => %s\n", status, result.ID, result.Tool, truncateBench(result.Input, 150), result.Actual); err != nil {
				return fmt.Errorf("bench: write output: %w", err)
			}
		}
	}

	return nil
}

func loadBenchCorpus(path string) ([]benchCase, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("bench: read corpus: %w", err)
	}
	return parseBenchCorpus(data)
}

func parseBenchCorpus(data []byte) ([]benchCase, error) {
	var v2 benchCorpusV2Document
	if err := yaml.Unmarshal(data, &v2); err != nil {
		return nil, fmt.Errorf("bench: parse corpus YAML: %w", err)
	}

	if strings.TrimSpace(v2.Version) == "2" {
		return normalizeV2Cases(v2)
	}
	if strings.TrimSpace(v2.Version) != "" {
		return nil, fmt.Errorf("bench: unsupported corpus version %q", v2.Version)
	}

	// Backward-compatible v1 auto-migration when version is omitted.
	var v1Doc benchCorpusV1Document
	if err := yaml.Unmarshal(data, &v1Doc); err != nil {
		return nil, fmt.Errorf("bench: parse corpus YAML: %w", err)
	}
	entries := v1Doc.Entries
	if len(entries) == 0 {
		if err := yaml.Unmarshal(data, &entries); err != nil {
			return nil, fmt.Errorf("bench: parse corpus YAML: %w", err)
		}
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("bench: corpus contains no entries")
	}
	return migrateV1BenchEntries(entries)
}

func normalizeV2Cases(doc benchCorpusV2Document) ([]benchCase, error) {
	if len(doc.Cases) == 0 {
		return nil, fmt.Errorf("bench: corpus contains no cases")
	}

	defaultsOS := strings.ToLower(strings.TrimSpace(doc.Defaults.OS))
	if defaultsOS == "" {
		defaultsOS = "*"
	}
	defaultsExpected := strings.ToLower(strings.TrimSpace(doc.Defaults.Expected))
	if defaultsExpected == "" {
		defaultsExpected = "deny"
	}

	seenIDs := make(map[string]struct{}, len(doc.Cases))
	out := make([]benchCase, 0, len(doc.Cases))
	for i, c := range doc.Cases {
		id := strings.ToUpper(strings.TrimSpace(c.ID))
		if id == "" {
			return nil, fmt.Errorf("bench: case %d has empty id", i)
		}
		if _, ok := seenIDs[id]; ok {
			return nil, fmt.Errorf("bench: duplicate case id %q", id)
		}
		seenIDs[id] = struct{}{}

		name := strings.TrimSpace(c.Name)
		if name == "" {
			return nil, fmt.Errorf("bench: case %d (%s) has empty name", i, id)
		}
		category := strings.ToLower(strings.TrimSpace(c.Category))
		if category == "" {
			return nil, fmt.Errorf("bench: case %d (%s) has empty category", i, id)
		}
		severity, err := normalizeBenchSeverity(c.Severity)
		if err != nil {
			return nil, fmt.Errorf("bench: case %d (%s): %w", i, id, err)
		}
		osName := strings.ToLower(strings.TrimSpace(c.OS))
		if osName == "" {
			osName = defaultsOS
		}
		osName, err = normalizeBenchOS(osName)
		if err != nil {
			return nil, fmt.Errorf("bench: case %d (%s): %w", i, id, err)
		}

		tool := strings.ToLower(strings.TrimSpace(c.Tool))
		if tool != "exec" && tool != "read" && tool != "write" {
			return nil, fmt.Errorf("bench: case %d (%s) has invalid tool %q", i, id, c.Tool)
		}

		expected := strings.ToLower(strings.TrimSpace(c.Expected))
		if expected == "" {
			expected = defaultsExpected
		}
		if expected != "deny" && expected != "require_approval" {
			return nil, fmt.Errorf("bench: case %d (%s) has invalid expected %q", i, id, c.Expected)
		}

		input := benchCorpusV2Input{
			Command: strings.TrimSpace(c.Input.Command),
			Path:    strings.TrimSpace(c.Input.Path),
			Content: c.Input.Content,
		}
		switch tool {
		case "exec":
			if input.Command == "" {
				return nil, fmt.Errorf("bench: case %d (%s) exec input.command cannot be empty", i, id)
			}
		case "read":
			if input.Path == "" {
				return nil, fmt.Errorf("bench: case %d (%s) read input.path cannot be empty", i, id)
			}
		case "write":
			if input.Path == "" {
				return nil, fmt.Errorf("bench: case %d (%s) write input.path cannot be empty", i, id)
			}
		}

		out = append(out, benchCase{
			ID:          id,
			Name:        name,
			Description: strings.TrimSpace(c.Description),
			Category:    category,
			Technique:   strings.TrimSpace(c.Technique),
			Severity:    severity,
			OS:          osName,
			Tool:        tool,
			Input:       input,
			Expected:    expected,
		})
	}
	return out, nil
}

func migrateV1BenchEntries(entries []benchCorpusV1Entry) ([]benchCase, error) {
	out := make([]benchCase, 0, len(entries))
	for i, e := range entries {
		command := strings.TrimSpace(e.Command)
		if command == "" {
			return nil, fmt.Errorf("bench: corpus entry %d has empty command", i)
		}
		category := strings.ToLower(strings.TrimSpace(e.Category))
		if category == "" {
			return nil, fmt.Errorf("bench: corpus entry %d has empty category", i)
		}

		expectedAction := strings.ToLower(strings.TrimSpace(e.ExpectedAction))
		if expectedAction == "" {
			expectedAction = "deny"
		}
		action, err := engine.ParseAction(expectedAction)
		if err != nil {
			return nil, fmt.Errorf("bench: corpus entry %d has invalid expected_action %q", i, e.ExpectedAction)
		}

		expected := "deny"
		if action == engine.ActionRequireApproval {
			expected = "require_approval"
		}
		if action != engine.ActionDeny && action != engine.ActionRequireApproval {
			// v1 allowed allow/watch expectations; map them to approval-gated
			// for v2 coverage semantics.
			expected = "require_approval"
		}

		out = append(out, benchCase{
			ID:          fmt.Sprintf("V1-%03d", i+1),
			Name:        strings.TrimSpace(e.Description),
			Description: strings.TrimSpace(e.Description),
			Category:    category,
			Severity:    inferV1Severity(category),
			OS:          "*",
			Tool:        "exec",
			Input: benchCorpusV2Input{
				Command: command,
			},
			Expected: expected,
		})
	}
	return out, nil
}

type benchFilterOptions struct {
	Category string
	OSFilter string
	Severity string
	IDPrefix string
}

func filterBenchCases(cases []benchCase, opts benchFilterOptions) []benchCase {
	category := strings.ToLower(strings.TrimSpace(opts.Category))
	idPrefix := strings.ToUpper(strings.TrimSpace(opts.IDPrefix))
	minSeverityWeight := benchSeverityWeight(opts.Severity)
	out := make([]benchCase, 0, len(cases))
	for _, tc := range cases {
		if category != "" && !strings.EqualFold(tc.Category, category) {
			continue
		}
		if idPrefix != "" && !strings.HasPrefix(strings.ToUpper(tc.ID), idPrefix) {
			continue
		}
		if benchSeverityWeight(tc.Severity) < minSeverityWeight {
			continue
		}
		if !benchOSApplies(tc.OS, opts.OSFilter) {
			continue
		}
		out = append(out, tc)
	}
	return out
}

func benchOSApplies(caseOS, filterOS string) bool {
	if filterOS == "*" {
		return true
	}
	if caseOS == "*" {
		return true
	}
	return caseOS == filterOS
}

func benchToolCall(tc benchCase) engine.ToolCall {
	params := map[string]any{}
	switch tc.Tool {
	case "exec":
		params["command"] = tc.Input.Command
	case "read":
		params["path"] = tc.Input.Path
		params["file_path"] = tc.Input.Path
	case "write":
		params["path"] = tc.Input.Path
		params["file_path"] = tc.Input.Path
		if tc.Input.Content != "" {
			params["content"] = tc.Input.Content
		}
	}
	return engine.ToolCall{
		Agent:     "*",
		Tool:      tc.Tool,
		Params:    params,
		Timestamp: time.Now().UTC(),
	}
}

func benchCovered(actual string, strict bool) bool {
	if actual == "deny" {
		return true
	}
	if strict {
		return false
	}
	return actual == "require_approval"
}

func benchCaseInputString(tc benchCase) string {
	switch tc.Tool {
	case "exec":
		return tc.Input.Command
	case "read":
		return tc.Input.Path
	case "write":
		if tc.Input.Content == "" {
			return tc.Input.Path
		}
		return fmt.Sprintf("%s :: %s", tc.Input.Path, tc.Input.Content)
	default:
		return ""
	}
}

func benchSeverityWeight(severity string) float64 {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 3
	case "high":
		return 2
	default:
		return 1
	}
}

func normalizeBenchSeverity(severity string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(severity))
	switch s {
	case "critical", "high", "medium":
		return s, nil
	default:
		return "", fmt.Errorf("bench: invalid severity %q (want critical|high|medium)", severity)
	}
}

func normalizeBenchOS(osName string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(osName))
	switch s {
	case "linux", "darwin", "windows", "*":
		return s, nil
	default:
		return "", fmt.Errorf("bench: invalid os %q (want linux|darwin|windows|*)", osName)
	}
}

func inferV1Severity(category string) string {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "credential-theft", "destructive", "privilege-escalation":
		return "critical"
	case "exfil", "supply-chain", "persistence":
		return "high"
	default:
		return "medium"
	}
}

func currentBenchOS() string {
	switch runtime.GOOS {
	case "linux", "darwin", "windows":
		return runtime.GOOS
	default:
		return "linux"
	}
}

func percent(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) * 100 / float64(total)
}

func percentFloat(part, total float64) float64 {
	if total == 0 {
		return 0
	}
	return part * 100 / total
}

func benchPassFail(ok bool) string {
	if ok {
		return "pass"
	}
	return "fail"
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
