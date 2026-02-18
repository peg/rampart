package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peg/rampart/internal/engine"
)

func TestIsYAMLFile(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"test.yaml", true},
		{"test.yml", true},
		{"test.YAML", true},
		{"test.YML", true},
		{"test.json", false},
		{"rm -rf /", false},
		{"ls", false},
		{".yaml", true},
	}
	for _, tt := range tests {
		if got := isYAMLFile(tt.input); got != tt.want {
			t.Errorf("isYAMLFile(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestPrintSuiteResult_Pass(t *testing.T) {
	var buf bytes.Buffer
	r := engine.TestResult{
		Case:   engine.TestCase{Name: "test-pass"},
		Passed: true,
		Decision: engine.Decision{
			Action:       engine.ActionDeny,
			Message:      "blocked",
			EvalDuration: 5 * time.Microsecond,
		},
	}
	printSuiteResult(&buf, r, true, false)
	if !strings.Contains(buf.String(), "test-pass") {
		t.Errorf("output = %q", buf.String())
	}
}

func TestPrintSuiteResult_Fail(t *testing.T) {
	var buf bytes.Buffer
	r := engine.TestResult{
		Case:           engine.TestCase{Name: "test-fail"},
		Passed:         false,
		ExpectedAction: engine.ActionDeny,
		Decision: engine.Decision{
			Action:          engine.ActionAllow,
			Message:         "allowed",
			MatchedPolicies: []string{"policy1"},
			EvalDuration:    10 * time.Microsecond,
		},
	}
	printSuiteResult(&buf, r, true, true) // verbose
	out := buf.String()
	if !strings.Contains(out, "test-fail") {
		t.Errorf("missing name: %s", out)
	}
	if !strings.Contains(out, "expected") {
		t.Errorf("missing expected: %s", out)
	}
	if !strings.Contains(out, "message:") {
		t.Errorf("missing verbose message: %s", out)
	}
}

func TestPrintSuiteResult_Error(t *testing.T) {
	var buf bytes.Buffer
	r := engine.TestResult{
		Case:  engine.TestCase{Name: "test-error"},
		Error: fmt.Errorf("something went wrong"),
	}
	printSuiteResult(&buf, r, true, false)
	if !strings.Contains(buf.String(), "something went wrong") {
		t.Errorf("output = %q", buf.String())
	}
}

func TestRunTestSuite(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "rampart.yaml")
	os.WriteFile(policyFile, []byte(`
version: "1"
default_action: allow
policies:
  - name: block-rm
    match:
      tool: ["exec"]
    rules:
      - action: deny
        message: blocked
        when:
          command_matches:
            - "rm -rf *"
tests:
  - name: blocks rm -rf
    tool: exec
    params:
      command: "rm -rf /"
    expect: deny
  - name: allows ls
    tool: exec
    params:
      command: "ls"
    expect: allow
`), 0o644)

	var out, errOut bytes.Buffer
	opts := &rootOptions{configPath: policyFile}
	err := runTestSuite(&out, &errOut, opts, policyFile, true, false, "", false)
	if err != nil {
		t.Logf("output: %s", out.String())
		t.Logf("stderr: %s", errOut.String())
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out.String(), "2 passed") {
		t.Errorf("output = %q", out.String())
	}
}

func TestRunTestSuite_WithFilter(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "rampart.yaml")
	os.WriteFile(policyFile, []byte(`
version: "1"
default_action: allow
policies:
  - name: block-rm
    match:
      tool: ["exec"]
    rules:
      - action: deny
        message: blocked
        when:
          command_matches:
            - "rm -rf *"
tests:
  - name: blocks rm
    tool: exec
    params:
      command: "rm -rf /"
    expect: deny
  - name: allows ls
    tool: exec
    params:
      command: "ls"
    expect: allow
`), 0o644)

	var out, errOut bytes.Buffer
	opts := &rootOptions{configPath: policyFile}
	err := runTestSuite(&out, &errOut, opts, policyFile, true, false, "blocks*", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out.String(), "1 passed") {
		t.Errorf("output = %q", out.String())
	}
}

func TestRunTestSuite_NoMatch(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "rampart.yaml")
	os.WriteFile(policyFile, []byte(`
version: "1"
default_action: allow
policies: []
tests:
  - name: test1
    tool: exec
    params:
      command: "ls"
    expect: allow
`), 0o644)

	var out, errOut bytes.Buffer
	opts := &rootOptions{configPath: policyFile}
	err := runTestSuite(&out, &errOut, opts, policyFile, true, false, "nonexistent*", false)
	if err == nil {
		t.Fatal("expected error for no matching tests")
	}
}
