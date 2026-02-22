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

func TestRunBenchJSONSuccess(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	corpusPath := filepath.Join(dir, "corpus.yaml")

	policy := `
default_action: allow
policies:
  - name: block-creds
    match:
      tool: "exec"
    rules:
      - action: deny
        message: credential access denied
        when:
          command_matches:
            - "cat ~/.aws/credentials"
  - name: watch-npm
    match:
      tool: "exec"
    rules:
      - action: watch
        message: package install should be reviewed
        when:
          command_matches:
            - "npm install *"
`
	if err := os.WriteFile(policyPath, []byte(policy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	corpus := `
entries:
  - command: "cat ~/.aws/credentials"
    expected_action: "deny"
    category: "credential-theft"
    description: "should be blocked"
  - command: "npm install left-pad"
    expected_action: "watch"
    category: "supply-chain"
    description: "should be watched"
  - command: "echo hello"
    expected_action: "allow"
    category: "prompt-injection"
    description: "benign command"
`
	if err := os.WriteFile(corpusPath, []byte(corpus), 0o644); err != nil {
		t.Fatalf("write corpus: %v", err)
	}

	stdout, _, err := runCLI(t, "bench", "--policy", policyPath, "--corpus", corpusPath, "--json")
	if err != nil {
		t.Fatalf("run bench: %v", err)
	}

	var got benchSummary
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("parse JSON: %v\n%s", err, stdout)
	}

	if got.Total != 3 {
		t.Fatalf("total = %d, want 3", got.Total)
	}
	if got.Matched != 3 || got.Mismatched != 0 {
		t.Fatalf("matched/mismatched = %d/%d, want 3/0", got.Matched, got.Mismatched)
	}
	if got.Blocked != 1 || got.Watched != 1 || got.Allowed != 1 {
		t.Fatalf("decision counts = deny:%d watch:%d allow:%d, want 1/1/1", got.Blocked, got.Watched, got.Allowed)
	}
	if len(got.Gaps) != 0 {
		t.Fatalf("gaps = %d, want 0", len(got.Gaps))
	}
}

func TestBenchCommandReturnsExitCodeOnGaps(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	corpusPath := filepath.Join(dir, "corpus.yaml")

	policy := `
default_action: allow
policies:
  - name: deny-rm
    match:
      tool: "exec"
    rules:
      - action: deny
        message: destructive blocked
        when:
          command_matches:
            - "rm -rf *"
`
	if err := os.WriteFile(policyPath, []byte(policy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	corpus := `
entries:
  - command: "echo ok"
    expected_action: "deny"
    category: "destructive"
    description: "intentionally mismatched"
`
	if err := os.WriteFile(corpusPath, []byte(corpus), 0o644); err != nil {
		t.Fatalf("write corpus: %v", err)
	}

	_, _, err := runCLI(t, "bench", "--policy", policyPath, "--corpus", corpusPath)
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
}

func TestBenchCategoryFilter(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	corpusPath := filepath.Join(dir, "corpus.yaml")

	policy := `
default_action: allow
policies:
  - name: deny-shadow
    match:
      tool: "exec"
    rules:
      - action: deny
        message: denied
        when:
          command_matches:
            - "cat /etc/shadow"
`
	if err := os.WriteFile(policyPath, []byte(policy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	corpus := `
entries:
  - command: "cat /etc/shadow"
    expected_action: "deny"
    category: "credential-theft"
    description: "blocked"
  - command: "echo hi"
    expected_action: "allow"
    category: "prompt-injection"
    description: "allowed"
`
	if err := os.WriteFile(corpusPath, []byte(corpus), 0o644); err != nil {
		t.Fatalf("write corpus: %v", err)
	}

	stdout, _, err := runCLI(t, "bench", "--policy", policyPath, "--corpus", corpusPath, "--category", "credential-theft", "--json")
	if err != nil {
		t.Fatalf("run bench with category: %v", err)
	}

	var got benchSummary
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("parse JSON: %v", err)
	}
	if got.Total != 1 {
		t.Fatalf("total = %d, want 1", got.Total)
	}
	if got.Category != "credential-theft" {
		t.Fatalf("category = %q, want credential-theft", got.Category)
	}
}

func TestCorpusFileHasCoverageAndSchema(t *testing.T) {
	path := filepath.Join("..", "..", "..", "bench", "corpus.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read corpus file: %v", err)
	}

	var doc benchCorpusDocument
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}

	if len(doc.Entries) < 80 {
		t.Fatalf("entries = %d, want at least 80", len(doc.Entries))
	}

	required := map[string]bool{
		"exfil":                false,
		"credential-theft":     false,
		"supply-chain":         false,
		"persistence":          false,
		"prompt-injection":     false,
		"destructive":          false,
		"privilege-escalation": false,
	}

	for i, entry := range doc.Entries {
		if entry.Command == "" || entry.ExpectedAction == "" || entry.Category == "" || entry.Description == "" {
			t.Fatalf("entry %d missing required fields: %+v", i, entry)
		}
		if _, ok := required[entry.Category]; ok {
			required[entry.Category] = true
		}
	}

	for category, found := range required {
		if !found {
			t.Fatalf("missing category in corpus: %s", category)
		}
	}
}

func TestLoadBenchCorpusRejectsInvalidExpectedAction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invalid-corpus.yaml")
	content := `
entries:
  - command: "echo hi"
    expected_action: "block"
    category: "destructive"
    description: "invalid action"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write corpus: %v", err)
	}

	_, err := loadBenchCorpus(path)
	if err == nil {
		t.Fatal("expected error for invalid action")
	}
	if got, want := err.Error(), "invalid expected_action"; !strings.Contains(got, want) {
		t.Fatalf("error %q does not contain %q", got, want)
	}
}
