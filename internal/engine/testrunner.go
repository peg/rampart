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

package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// TestSuite is a collection of test cases to run against a policy.
type TestSuite struct {
	// Policy is the path to the policy file to test against.
	Policy string `yaml:"policy"`

	// Tests is the list of test cases.
	Tests []TestCase `yaml:"tests"`
}

// TestCase defines a single policy test expectation.
type TestCase struct {
	// Name describes what this test verifies.
	Name string `yaml:"name"`

	// Tool is the tool type (exec, read, write).
	Tool string `yaml:"tool"`

	// Agent is the agent identity for the test call (default: "test").
	Agent string `yaml:"agent,omitempty"`

	// Params are tool-specific parameters.
	Params map[string]any `yaml:"params"`

	// Expect is the expected action (allow, deny, log, require_approval, webhook).
	Expect string `yaml:"expect"`

	// ExpectMessage is an optional glob pattern to match against the decision message.
	ExpectMessage string `yaml:"expect_message,omitempty"`
}

// TestResult holds the outcome of running a single test case.
type TestResult struct {
	Case           TestCase
	Passed         bool
	Decision       Decision
	ExpectedAction Action
	Error          error
}

// LoadTestSuite reads a test suite from a YAML file.
func LoadTestSuite(path string) (*TestSuite, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read test file: %w", err)
	}

	var suite TestSuite
	if err := yaml.Unmarshal(data, &suite); err != nil {
		return nil, fmt.Errorf("parse test file: %w", err)
	}

	if len(suite.Tests) == 0 {
		return nil, fmt.Errorf("test file contains no tests")
	}

	// Resolve policy path relative to the test file's directory.
	if suite.Policy != "" && !filepath.IsAbs(suite.Policy) {
		dir := filepath.Dir(path)
		suite.Policy = filepath.Join(dir, suite.Policy)
	}

	return &suite, nil
}

// LoadInlineTests extracts inline tests from a policy file.
// Returns nil, nil if no tests key is present.
func LoadInlineTests(policyPath string) (*TestSuite, error) {
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}

	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse policy file: %w", err)
	}

	testsRaw, ok := raw["tests"]
	if !ok {
		return nil, nil
	}

	testsYAML, err := yaml.Marshal(testsRaw)
	if err != nil {
		return nil, fmt.Errorf("marshal inline tests: %w", err)
	}

	var cases []TestCase
	if err := yaml.Unmarshal(testsYAML, &cases); err != nil {
		return nil, fmt.Errorf("parse inline tests: %w", err)
	}

	if len(cases) == 0 {
		return nil, nil
	}

	abs, _ := filepath.Abs(policyPath)
	return &TestSuite{
		Policy: abs,
		Tests:  cases,
	}, nil
}

// RunTests executes all test cases in a suite against the given engine.
func RunTests(eng *Engine, suite *TestSuite) []TestResult {
	results := make([]TestResult, 0, len(suite.Tests))
	for _, tc := range suite.Tests {
		results = append(results, runSingleTest(eng, tc))
	}
	return results
}

func runSingleTest(eng *Engine, tc TestCase) TestResult {
	expectedAction, err := ParseAction(tc.Expect)
	if err != nil {
		return TestResult{Case: tc, Error: fmt.Errorf("invalid expect value %q: %w", tc.Expect, err)}
	}

	if tc.Tool == "" {
		return TestResult{Case: tc, Error: fmt.Errorf("test case %q: tool is required", tc.Name)}
	}

	agent := tc.Agent
	if agent == "" {
		agent = "test"
	}

	params := tc.Params
	if params == nil {
		params = make(map[string]any)
	}

	call := ToolCall{
		Tool:      tc.Tool,
		Agent:     agent,
		Params:    params,
		Timestamp: time.Now(),
	}

	decision := eng.Evaluate(call)
	passed := decision.Action == expectedAction

	if passed && tc.ExpectMessage != "" {
		matched, _ := filepath.Match(tc.ExpectMessage, decision.Message)
		if !matched {
			passed = false
		}
	}

	return TestResult{
		Case:           tc,
		Passed:         passed,
		Decision:       decision,
		ExpectedAction: expectedAction,
	}
}
