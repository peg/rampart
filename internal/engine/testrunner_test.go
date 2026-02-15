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
	"os"
	"path/filepath"
	"testing"
)

var testPolicy = `
default_action: allow
policies:
  - name: block-rm
    match:
      tool: ["exec"]
    rules:
      - action: deny
        when:
          command_matches:
            - "rm -rf *"
        message: "Blocked rm -rf"
  - name: block-secrets
    match:
      tool: ["read"]
    rules:
      - action: deny
        when:
          path_matches:
            - "/etc/shadow"
        message: "Blocked secret read"
  - name: approve-deploy
    match:
      tool: ["exec"]
    rules:
      - action: require_approval
        when:
          command_matches:
            - "kubectl apply *"
        message: "Deploy needs approval"
`

func setupTestEngine(t *testing.T) (*Engine, string) {
	t.Helper()
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyFile, []byte(testPolicy), 0644); err != nil {
		t.Fatal(err)
	}
	store := NewFileStore(policyFile)
	eng, err := New(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	return eng, dir
}

func TestRunTests_AllPass(t *testing.T) {
	eng, _ := setupTestEngine(t)

	suite := &TestSuite{
		Tests: []TestCase{
			{Name: "deny rm", Tool: "exec", Params: map[string]any{"command": "rm -rf /"}, Expect: "deny"},
			{Name: "allow git", Tool: "exec", Params: map[string]any{"command": "git status"}, Expect: "allow"},
			{Name: "deny shadow", Tool: "read", Params: map[string]any{"path": "/etc/shadow"}, Expect: "deny"},
			{Name: "approve kubectl", Tool: "exec", Params: map[string]any{"command": "kubectl apply -f app.yaml"}, Expect: "require_approval"},
		},
	}

	results := RunTests(eng, suite)
	for _, r := range results {
		if r.Error != nil {
			t.Errorf("test %q error: %v", r.Case.Name, r.Error)
		}
		if !r.Passed {
			t.Errorf("test %q failed: expected %s, got %s", r.Case.Name, r.ExpectedAction, r.Decision.Action)
		}
	}
}

func TestRunTests_Failure(t *testing.T) {
	eng, _ := setupTestEngine(t)

	suite := &TestSuite{
		Tests: []TestCase{
			{Name: "wrong expect", Tool: "exec", Params: map[string]any{"command": "rm -rf /"}, Expect: "allow"},
		},
	}

	results := RunTests(eng, suite)
	if len(results) != 1 {
		t.Fatal("expected 1 result")
	}
	if results[0].Passed {
		t.Error("expected test to fail")
	}
}

func TestRunTests_InvalidExpect(t *testing.T) {
	eng, _ := setupTestEngine(t)

	suite := &TestSuite{
		Tests: []TestCase{
			{Name: "bad expect", Tool: "exec", Params: map[string]any{"command": "ls"}, Expect: "bogus"},
		},
	}

	results := RunTests(eng, suite)
	if results[0].Error == nil {
		t.Error("expected error for invalid expect value")
	}
}

func TestRunTests_ExpectMessage(t *testing.T) {
	eng, _ := setupTestEngine(t)

	suite := &TestSuite{
		Tests: []TestCase{
			{Name: "msg match", Tool: "exec", Params: map[string]any{"command": "rm -rf /"}, Expect: "deny", ExpectMessage: "Blocked*"},
			{Name: "msg mismatch", Tool: "exec", Params: map[string]any{"command": "rm -rf /"}, Expect: "deny", ExpectMessage: "Wrong*"},
		},
	}

	results := RunTests(eng, suite)
	if !results[0].Passed {
		t.Error("expected message glob match to pass")
	}
	if results[1].Passed {
		t.Error("expected message glob mismatch to fail")
	}
}

func TestRunTests_MissingTool(t *testing.T) {
	eng, _ := setupTestEngine(t)

	suite := &TestSuite{
		Tests: []TestCase{
			{Name: "no tool", Params: map[string]any{"command": "ls"}, Expect: "allow"},
		},
	}

	results := RunTests(eng, suite)
	if results[0].Error == nil {
		t.Error("expected error for missing tool")
	}
}

func TestLoadTestSuite(t *testing.T) {
	dir := t.TempDir()

	policyFile := filepath.Join(dir, "policy.yaml")
	os.WriteFile(policyFile, []byte(testPolicy), 0644)

	suiteFile := filepath.Join(dir, "tests.yaml")
	os.WriteFile(suiteFile, []byte(`
policy: ./policy.yaml
tests:
  - name: "test1"
    tool: exec
    params:
      command: "rm -rf /"
    expect: deny
`), 0644)

	suite, err := LoadTestSuite(suiteFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(suite.Tests) != 1 {
		t.Fatalf("expected 1 test, got %d", len(suite.Tests))
	}
	if suite.Policy != filepath.Join(dir, "policy.yaml") {
		t.Errorf("policy path not resolved: %s", suite.Policy)
	}
}

func TestLoadInlineTests(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	os.WriteFile(policyFile, []byte(testPolicy+`
tests:
  - name: "inline test"
    tool: exec
    params:
      command: "rm -rf /"
    expect: deny
`), 0644)

	suite, err := LoadInlineTests(policyFile)
	if err != nil {
		t.Fatal(err)
	}
	if suite == nil {
		t.Fatal("expected inline tests")
	}
	if len(suite.Tests) != 1 {
		t.Fatalf("expected 1 test, got %d", len(suite.Tests))
	}
}

func TestLoadInlineTests_NoTests(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	os.WriteFile(policyFile, []byte(testPolicy), 0644)

	suite, err := LoadInlineTests(policyFile)
	if err != nil {
		t.Fatal(err)
	}
	if suite != nil {
		t.Error("expected nil for policy without tests")
	}
}

func TestRunTests_DefaultAgent(t *testing.T) {
	eng, _ := setupTestEngine(t)

	suite := &TestSuite{
		Tests: []TestCase{
			{Name: "default agent", Tool: "exec", Params: map[string]any{"command": "ls"}, Expect: "allow"},
			{Name: "custom agent", Tool: "exec", Agent: "myagent", Params: map[string]any{"command": "ls"}, Expect: "allow"},
		},
	}

	results := RunTests(eng, suite)
	for _, r := range results {
		if !r.Passed {
			t.Errorf("test %q failed", r.Case.Name)
		}
	}
}
