// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0

package assurance

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/peg/rampart/internal/engine"
	"github.com/peg/rampart/policies"
	"gopkg.in/yaml.v3"
)

const corpusSchemaVersion = "rampart.adversarial.v1"

type adversarialCorpus struct {
	SchemaVersion string              `yaml:"schema_version"`
	PolicySets    map[string][]string `yaml:"policy_sets"`
	Cases         []adversarialCase   `yaml:"cases"`
}

type adversarialCase struct {
	ID        string         `yaml:"id"`
	Category  string         `yaml:"category"`
	PolicySet string         `yaml:"policy_set"`
	Tool      string         `yaml:"tool"`
	Params    map[string]any `yaml:"params"`
	Expected  string         `yaml:"expected"`
	Rationale string         `yaml:"rationale"`
}

func loadCorpus(t *testing.T) adversarialCorpus {
	t.Helper()
	path := filepath.Join(repositoryRoot(t), "assurance", "corpus.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var corpus adversarialCorpus
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&corpus); err != nil {
		t.Fatalf("decode adversarial corpus: %v", err)
	}
	return corpus
}

func TestAdversarialCorpus(t *testing.T) {
	corpus := loadCorpus(t)
	if corpus.SchemaVersion != corpusSchemaVersion {
		t.Fatalf("schema_version = %q, want %q", corpus.SchemaVersion, corpusSchemaVersion)
	}
	if len(corpus.PolicySets) == 0 || len(corpus.Cases) == 0 {
		t.Fatal("adversarial corpus requires policy sets and cases")
	}

	engines := make(map[string]*engine.Engine, len(corpus.PolicySets))
	for name, profiles := range corpus.PolicySets {
		if !regexp.MustCompile(`^[a-z][a-z0-9_]*$`).MatchString(name) {
			t.Fatalf("invalid policy set name %q", name)
		}
		if len(profiles) == 0 {
			t.Fatalf("policy set %q has no profiles", name)
		}
		dir := t.TempDir()
		for _, profile := range profiles {
			content, err := policies.Profile(profile)
			if err != nil {
				t.Fatalf("policy set %q: %v", name, err)
			}
			if err := os.WriteFile(filepath.Join(dir, profile+".yaml"), content, 0o600); err != nil {
				t.Fatalf("policy set %q: write profile %q: %v", name, profile, err)
			}
		}
		eng, err := engine.New(engine.NewDirStore(dir, nil), nil)
		if err != nil {
			t.Fatalf("policy set %q: create engine: %v", name, err)
		}
		engines[name] = eng
		t.Cleanup(eng.Stop)
	}

	seen := make(map[string]bool, len(corpus.Cases))
	for _, testCase := range corpus.Cases {
		testCase := testCase
		t.Run(testCase.ID, func(t *testing.T) {
			if testCase.ID == "" || seen[testCase.ID] {
				t.Fatalf("case id is empty or duplicated: %q", testCase.ID)
			}
			seen[testCase.ID] = true
			if testCase.Category == "" || testCase.Rationale == "" {
				t.Fatal("category and rationale are required")
			}
			eng, ok := engines[testCase.PolicySet]
			if !ok {
				t.Fatalf("unknown policy_set %q", testCase.PolicySet)
			}
			expected, err := parseExpectedAction(testCase.Expected)
			if err != nil {
				t.Fatal(err)
			}
			decision := eng.Evaluate(engine.ToolCall{
				ID:        "assurance-" + testCase.ID,
				Agent:     "security-assurance",
				Session:   "security-assurance",
				Tool:      testCase.Tool,
				Params:    testCase.Params,
				Input:     testCase.Params,
				Timestamp: time.Unix(0, 0).UTC(),
			})
			if decision.Action != expected {
				t.Fatalf("decision = %s, want %s (%s); matched=%v message=%q",
					decision.Action, expected, testCase.Rationale, decision.MatchedPolicies, decision.Message)
			}
		})
	}
}

func parseExpectedAction(value string) (engine.Action, error) {
	switch value {
	case "allow":
		return engine.ActionAllow, nil
	case "deny":
		return engine.ActionDeny, nil
	case "ask":
		return engine.ActionAsk, nil
	case "watch":
		return engine.ActionWatch, nil
	case "require_approval":
		return engine.ActionRequireApproval, nil
	default:
		return 0, fmt.Errorf("unsupported expected action %q", value)
	}
}
