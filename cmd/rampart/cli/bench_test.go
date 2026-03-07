//go:build bench

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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestBenchV2CorpusLoadAndOSFilter(t *testing.T) {
	corpus := []byte(`
version: "2"
name: test
description: test
cases:
  - id: "LIN-001"
    name: "Linux case"
    category: execution
    severity: medium
    os: linux
    tool: exec
    input:
      command: "echo linux"
    expected: deny
  - id: "WIN-001"
    name: "Windows case"
    category: execution
    severity: medium
    os: windows
    tool: exec
    input:
      command: "echo windows"
    expected: deny
  - id: "ALL-001"
    name: "Cross-platform case"
    category: execution
    severity: medium
    os: "*"
    tool: exec
    input:
      command: "echo all"
    expected: deny
`)

	cases, err := parseBenchCorpus(corpus)
	if err != nil {
		t.Fatalf("parse v2 corpus: %v", err)
	}
	linuxCases := filterBenchCases(cases, benchFilterOptions{OSFilter: "linux", Severity: "medium"})
	if got := len(linuxCases); got != 2 {
		t.Fatalf("linux filtered cases = %d, want 2", got)
	}
	windowsCases := filterBenchCases(cases, benchFilterOptions{OSFilter: "windows", Severity: "medium"})
	if got := len(windowsCases); got != 2 {
		t.Fatalf("windows filtered cases = %d, want 2", got)
	}
	allCases := filterBenchCases(cases, benchFilterOptions{OSFilter: "*", Severity: "medium"})
	if got := len(allCases); got != 3 {
		t.Fatalf("all filtered cases = %d, want 3", got)
	}
}

func TestBenchV1Migration(t *testing.T) {
	v1 := []byte(`
entries:
  - command: "cat ~/.aws/credentials"
    expected_action: "deny"
    category: "credential-theft"
    description: "Read AWS credentials"
  - command: "echo hello"
    expected_action: "allow"
    category: "execution"
    description: "Benign command"
`)

	cases, err := parseBenchCorpus(v1)
	if err != nil {
		t.Fatalf("parse v1 corpus: %v", err)
	}
	if len(cases) != 2 {
		t.Fatalf("migrated cases = %d, want 2", len(cases))
	}
	if cases[0].ID != "V1-001" || cases[1].ID != "V1-002" {
		t.Fatalf("unexpected IDs after migration: %q, %q", cases[0].ID, cases[1].ID)
	}
	if cases[0].Tool != "exec" || cases[0].Input.Command == "" {
		t.Fatalf("expected migrated exec case, got %+v", cases[0])
	}
	if cases[0].Expected != "deny" {
		t.Fatalf("first case expected = %q, want deny", cases[0].Expected)
	}
	if cases[1].Expected != "require_approval" {
		t.Fatalf("second case expected = %q, want require_approval", cases[1].Expected)
	}
}

func TestBenchWeightedCoverageCalculation(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	corpusPath := filepath.Join(dir, "corpus.yaml")

	policy := `
default_action: allow
policies:
  - name: deny-critical
    match:
      tool: "exec"
    rules:
      - action: deny
        when:
          command_matches:
            - "critical-cmd"
`
	if err := os.WriteFile(policyPath, []byte(policy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	corpus := `
version: "2"
name: test
description: test
cases:
  - id: "CASE-001"
    name: "Critical"
    category: execution
    severity: critical
    os: "*"
    tool: exec
    input:
      command: "critical-cmd"
    expected: deny
  - id: "CASE-002"
    name: "Medium"
    category: execution
    severity: medium
    os: "*"
    tool: exec
    input:
      command: "medium-cmd"
    expected: deny
`
	if err := os.WriteFile(corpusPath, []byte(corpus), 0o644); err != nil {
		t.Fatalf("write corpus: %v", err)
	}

	summary, err := runBench(benchRunOptions{
		PolicyPath: policyPath,
		CorpusPath: corpusPath,
		OSFilter:   "*",
		Severity:   "medium",
	})
	if err != nil {
		t.Fatalf("run bench: %v", err)
	}
	if summary.Coverage != 50 {
		t.Fatalf("raw coverage = %.1f, want 50", summary.Coverage)
	}
	if summary.WeightedCoverage != 75 {
		t.Fatalf("weighted coverage = %.1f, want 75", summary.WeightedCoverage)
	}
}

func TestBenchMinCoverageExitBehavior(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	corpusPath := filepath.Join(dir, "corpus.yaml")

	policy := `
default_action: allow
policies:
  - name: deny-one
    match:
      tool: "exec"
    rules:
      - action: deny
        when:
          command_matches:
            - "covered"
`
	if err := os.WriteFile(policyPath, []byte(policy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	corpus := `
version: "2"
name: test
description: test
cases:
  - id: "CASE-001"
    name: "Covered"
    category: execution
    severity: medium
    os: "*"
    tool: exec
    input:
      command: "covered"
    expected: deny
  - id: "CASE-002"
    name: "Gap"
    category: execution
    severity: medium
    os: "*"
    tool: exec
    input:
      command: "gap"
    expected: deny
`
	if err := os.WriteFile(corpusPath, []byte(corpus), 0o644); err != nil {
		t.Fatalf("write corpus: %v", err)
	}

	_, _, err := runCLI(t, "bench", "--policy", policyPath, "--corpus", corpusPath, "--os", "*", "--min-coverage", "60")
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	var exitErr interface{ ExitCode() int }
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected exit-code error, got %T: %v", err, err)
	}
	if exitErr.ExitCode() != 1 {
		t.Fatalf("exit code = %d, want 1", exitErr.ExitCode())
	}

	_, _, err = runCLI(t, "bench", "--policy", policyPath, "--corpus", corpusPath, "--os", "*", "--min-coverage", "40")
	if err != nil {
		t.Fatalf("expected success with lower threshold: %v", err)
	}
}

func TestBenchStrictMode(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	corpusPath := filepath.Join(dir, "corpus.yaml")

	policy := `
default_action: allow
policies:
  - name: approval-only
    match:
      tool: "exec"
    rules:
      - action: require_approval
        when:
          command_matches:
            - "rm -rf *"
`
	if err := os.WriteFile(policyPath, []byte(policy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	corpus := `
version: "2"
name: test
description: test
cases:
  - id: "CASE-001"
    name: "Destructive"
    category: destructive
    severity: critical
    os: "*"
    tool: exec
    input:
      command: "rm -rf /tmp/foo"
    expected: deny
`
	if err := os.WriteFile(corpusPath, []byte(corpus), 0o644); err != nil {
		t.Fatalf("write corpus: %v", err)
	}

	nonStrict, err := runBench(benchRunOptions{PolicyPath: policyPath, CorpusPath: corpusPath, OSFilter: "*", Severity: "medium"})
	if err != nil {
		t.Fatalf("run non-strict bench: %v", err)
	}
	if nonStrict.Coverage != 100 {
		t.Fatalf("non-strict coverage = %.1f, want 100", nonStrict.Coverage)
	}

	strict, err := runBench(benchRunOptions{PolicyPath: policyPath, CorpusPath: corpusPath, OSFilter: "*", Severity: "medium", Strict: true})
	if err != nil {
		t.Fatalf("run strict bench: %v", err)
	}
	if strict.Coverage != 0 {
		t.Fatalf("strict coverage = %.1f, want 0", strict.Coverage)
	}
	if len(strict.Gaps) != 1 {
		t.Fatalf("strict gaps = %d, want 1", len(strict.Gaps))
	}
}

func TestBenchReadWriteToolEvaluation(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	corpusPath := filepath.Join(dir, "corpus.yaml")

	policy := `
default_action: allow
policies:
  - name: block-sensitive-read
    match:
      tool: "read"
    rules:
      - action: deny
        when:
          path_matches:
            - "**/.ssh/id_rsa"
  - name: block-cron-write
    match:
      tool: "write"
    rules:
      - action: deny
        when:
          path_matches:
            - "/etc/cron.d/*"
`
	if err := os.WriteFile(policyPath, []byte(policy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	corpus := `
version: "2"
name: test
description: test
cases:
  - id: "READ-001"
    name: "Read SSH key"
    category: credential-theft
    severity: critical
    os: "*"
    tool: read
    input:
      path: "~/.ssh/id_rsa"
    expected: deny
  - id: "WRITE-001"
    name: "Write cron"
    category: persistence
    severity: critical
    os: "*"
    tool: write
    input:
      path: "/etc/cron.d/evil"
      content: "* * * * * root evil"
    expected: deny
`
	if err := os.WriteFile(corpusPath, []byte(corpus), 0o644); err != nil {
		t.Fatalf("write corpus: %v", err)
	}

	summary, err := runBench(benchRunOptions{PolicyPath: policyPath, CorpusPath: corpusPath, OSFilter: "*", Severity: "medium"})
	if err != nil {
		t.Fatalf("run bench: %v", err)
	}
	if summary.Coverage != 100 {
		t.Fatalf("coverage = %.1f, want 100", summary.Coverage)
	}
}

func TestBenchSeverityFilter(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	corpusPath := filepath.Join(dir, "corpus.yaml")

	policy := `
default_action: allow
policies:
  - name: deny-critical
    match:
      tool: "exec"
    rules:
      - action: deny
        when:
          command_matches:
            - "critical-cmd"
`
	if err := os.WriteFile(policyPath, []byte(policy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	corpus := `
version: "2"
name: test
description: test
cases:
  - id: "CRIT-001"
    name: "Critical"
    category: execution
    severity: critical
    os: "*"
    tool: exec
    input:
      command: "critical-cmd"
    expected: deny
  - id: "MED-001"
    name: "Medium"
    category: execution
    severity: medium
    os: "*"
    tool: exec
    input:
      command: "medium-cmd"
    expected: deny
`
	if err := os.WriteFile(corpusPath, []byte(corpus), 0o644); err != nil {
		t.Fatalf("write corpus: %v", err)
	}

	highOnly, err := runBench(benchRunOptions{PolicyPath: policyPath, CorpusPath: corpusPath, OSFilter: "*", Severity: "high"})
	if err != nil {
		t.Fatalf("run high-severity bench: %v", err)
	}
	if highOnly.Total != 1 || highOnly.Coverage != 100 {
		t.Fatalf("high-only total/coverage = %d/%.1f, want 1/100", highOnly.Total, highOnly.Coverage)
	}

	all, err := runBench(benchRunOptions{PolicyPath: policyPath, CorpusPath: corpusPath, OSFilter: "*", Severity: "medium"})
	if err != nil {
		t.Fatalf("run medium-severity bench: %v", err)
	}
	if all.Total != 2 || all.Coverage != 50 {
		t.Fatalf("all total/coverage = %d/%.1f, want 2/50", all.Total, all.Coverage)
	}
}

func TestBenchIDPrefixFilter(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	corpusPath := filepath.Join(dir, "corpus.yaml")

	policy := `
default_action: deny
policies: []
`
	if err := os.WriteFile(policyPath, []byte(policy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	corpus := `
version: "2"
name: test
description: test
cases:
  - id: "WIN-CRED-001"
    name: "A"
    category: credential-theft
    severity: critical
    os: "*"
    tool: exec
    input:
      command: "a"
    expected: deny
  - id: "LIN-CRED-001"
    name: "B"
    category: credential-theft
    severity: critical
    os: "*"
    tool: exec
    input:
      command: "b"
    expected: deny
`
	if err := os.WriteFile(corpusPath, []byte(corpus), 0o644); err != nil {
		t.Fatalf("write corpus: %v", err)
	}

	summary, err := runBench(benchRunOptions{PolicyPath: policyPath, CorpusPath: corpusPath, OSFilter: "*", Severity: "medium", IDPrefix: "WIN-"})
	if err != nil {
		t.Fatalf("run bench: %v", err)
	}
	if summary.Total != 1 {
		t.Fatalf("total = %d, want 1", summary.Total)
	}
}

func TestBenchUsesEmbeddedCorpusWhenNoFlagSet(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	policy := `
version: "1"
default_action: allow
policies:
  - name: deny-rm
    match:
      tool: ["exec"]
    rules:
      - action: deny
        when:
          command_matches: ["rm -rf /*"]
`
	if err := os.WriteFile(policyPath, []byte(policy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	stdout, _, err := runCLI(t, "bench", "--policy", policyPath)
	if err != nil && strings.Contains(err.Error(), "no such file or directory") {
		t.Fatalf("bench used disk path instead of embedded corpus: %v", err)
	}
	if !strings.Contains(stdout, "built-in") {
		t.Fatalf("expected 'built-in' in bench output, got:\n%s", stdout)
	}
}

func TestCorpusFileHasV2CoverageAndSchema(t *testing.T) {
	path := filepath.Join("..", "..", "..", "bench", "corpus.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read corpus file: %v", err)
	}

	var doc benchCorpusV2Document
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if doc.Version != "2" {
		t.Fatalf("version = %q, want 2", doc.Version)
	}
	if len(doc.Cases) < 80 {
		t.Fatalf("cases = %d, want at least 80", len(doc.Cases))
	}

	hasLinux := false
	hasDarwin := false
	hasWindows := false
	hasAll := false
	for i, tc := range doc.Cases {
		if tc.ID == "" || tc.Name == "" || tc.Category == "" || tc.Severity == "" || tc.Tool == "" || tc.Expected == "" {
			t.Fatalf("case %d missing required fields: %+v", i, tc)
		}
		switch tc.OS {
		case "linux":
			hasLinux = true
		case "darwin":
			hasDarwin = true
		case "windows":
			hasWindows = true
		case "*":
			hasAll = true
		}
	}
	if !hasLinux || !hasWindows || !hasAll {
		t.Fatalf("expected linux/windows/* coverage: linux=%v windows=%v all=%v", hasLinux, hasWindows, hasAll)
	}
	if !hasDarwin {
		t.Fatalf("expected at least one darwin case")
	}
}

func TestBenchJSONOutput(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	corpusPath := filepath.Join(dir, "corpus.yaml")

	policy := `
default_action: allow
policies:
  - name: deny-one
    match:
      tool: "exec"
    rules:
      - action: deny
        when:
          command_matches:
            - "blocked"
`
	if err := os.WriteFile(policyPath, []byte(policy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	corpus := `
version: "2"
name: test
description: test
cases:
  - id: "CASE-001"
    name: "blocked"
    category: execution
    severity: critical
    os: "*"
    tool: exec
    input:
      command: "blocked"
    expected: deny
`
	if err := os.WriteFile(corpusPath, []byte(corpus), 0o644); err != nil {
		t.Fatalf("write corpus: %v", err)
	}

	stdout, _, err := runCLI(t, "bench", "--policy", policyPath, "--corpus", corpusPath, "--os", "*", "--json")
	if err != nil {
		t.Fatalf("run bench: %v", err)
	}
	var got benchSummary
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("parse json output: %v", err)
	}
	if got.Total != 1 || got.Coverage != 100 {
		t.Fatalf("total/coverage = %d/%.1f, want 1/100", got.Total, got.Coverage)
	}
}
