// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package engine

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestGeneralizeCommand(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"kubectl apply -f deployment.yaml", "kubectl apply*"},
		{"npm install express", "npm install*"},
		{"git push origin main", "git push*"},
		{"ls", "ls"},
		{"cat /etc/passwd", "cat /etc/passwd*"},
		{"", "*"},
		{"  kubectl   apply  -f  foo  ", "kubectl apply*"},
		// Dangerous commands: never generalized.
		{"rm -rf /tmp/build", "rm -rf /tmp/build"},
		{"rm foo.txt", "rm foo.txt"},
		{"chmod 755 /usr/bin/foo", "chmod 755 /usr/bin/foo"},
		{"kill 1234", "kill 1234"},
		{"reboot", "reboot"},
		{"systemctl stop nginx", "systemctl stop nginx"},
	}
	for _, tt := range tests {
		got := GeneralizeCommand(tt.input)
		if got != tt.want {
			t.Errorf("GeneralizeCommand(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestGenerateAllowRule_Exec(t *testing.T) {
	call := ToolCall{
		Tool:   "exec",
		Params: map[string]any{"command": "kubectl apply -f deploy.yaml"},
	}
	p, err := GenerateAllowRule(call)
	require.NoError(t, err)

	if len(p.Match.Tool) != 1 || p.Match.Tool[0] != "exec" {
		t.Fatalf("expected tool match [exec], got %v", p.Match.Tool)
	}
	if len(p.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(p.Rules))
	}
	if p.Rules[0].Action != "allow" {
		t.Errorf("expected allow action, got %s", p.Rules[0].Action)
	}
	if len(p.Rules[0].When.CommandMatches) != 1 || p.Rules[0].When.CommandMatches[0] != "kubectl apply -f deploy.yaml" {
		t.Errorf("expected exact command match, got %v", p.Rules[0].When.CommandMatches)
	}
	if !strings.HasPrefix(p.Name, "auto-allow-kubectl-apply-") {
		t.Errorf("unexpected name: %s", p.Name)
	}
}

func TestGenerateAllowRule_Read(t *testing.T) {
	call := ToolCall{
		Tool:   "read",
		Params: map[string]any{"path": "/etc/passwd"},
	}
	p, err := GenerateAllowRule(call)
	require.NoError(t, err)

	if p.Match.Tool[0] != "read" {
		t.Fatalf("expected tool read, got %v", p.Match.Tool)
	}
	if p.Rules[0].When.PathMatches[0] != "/etc/passwd" {
		t.Errorf("expected exact path, got %v", p.Rules[0].When.PathMatches)
	}
}

func TestGenerateAllowRule_Write(t *testing.T) {
	call := ToolCall{
		Tool:   "write",
		Params: map[string]any{"path": "/tmp/output.txt"},
	}
	p, err := GenerateAllowRule(call)
	require.NoError(t, err)

	if p.Match.Tool[0] != "write" {
		t.Fatalf("expected tool write, got %v", p.Match.Tool)
	}
	if p.Rules[0].When.PathMatches[0] != "/tmp/output.txt" {
		t.Errorf("expected exact path, got %v", p.Rules[0].When.PathMatches)
	}
}

func TestGenerateAllowRuleRejectsUnsupportedTool(t *testing.T) {
	call := ToolCall{
		Tool:   "mcp.my_custom_tool",
		Params: map[string]any{},
	}
	_, err := GenerateAllowRule(call)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "explicit policy")
}

func TestGenerateAllowRuleRejectsEmptyAuthority(t *testing.T) {
	tests := []ToolCall{
		{},
		{Tool: "exec", Params: map[string]any{"command": "   "}},
		{Tool: "read", Params: map[string]any{}},
		{Tool: "write", Params: map[string]any{"path": ""}},
		{Tool: "edit", Params: map[string]any{"file_path": "   "}},
	}
	for _, call := range tests {
		_, err := GenerateAllowRule(call)
		require.Error(t, err, "call %#v must not create an unscoped allow", call)
	}
}

func TestAppendAllowRuleIsExactByDefault(t *testing.T) {
	tests := []struct {
		name    string
		call    ToolCall
		allowed ToolCall
		denied  ToolCall
	}{
		{
			name:    "ordinary command",
			call:    ToolCall{Tool: "exec", Params: map[string]any{"command": "npm install lodash"}},
			allowed: ToolCall{Tool: "exec", Params: map[string]any{"command": "npm install lodash"}},
			denied:  ToolCall{Tool: "exec", Params: map[string]any{"command": "npm install malware"}},
		},
		{
			name:    "privilege wrapper",
			call:    ToolCall{Tool: "exec", Params: map[string]any{"command": "sudo apt-get install nmap"}},
			allowed: ToolCall{Tool: "exec", Params: map[string]any{"command": "sudo apt-get install nmap"}},
			denied:  ToolCall{Tool: "exec", Params: map[string]any{"command": "sudo apt-get install netcat"}},
		},
		{
			name:    "destructive command",
			call:    ToolCall{Tool: "exec", Params: map[string]any{"command": "rm -rf /tmp/build"}},
			allowed: ToolCall{Tool: "exec", Params: map[string]any{"command": "rm -rf /tmp/build"}},
			denied:  ToolCall{Tool: "exec", Params: map[string]any{"command": "rm -rf /"}},
		},
		{
			name:    "literal shell wildcard",
			call:    ToolCall{Tool: "exec", Params: map[string]any{"command": "echo *.txt"}},
			allowed: ToolCall{Tool: "exec", Params: map[string]any{"command": "echo *.txt"}},
			denied:  ToolCall{Tool: "exec", Params: map[string]any{"command": "echo secrets.txt"}},
		},
		{
			name:    "edit path",
			call:    ToolCall{Tool: "edit", Params: map[string]any{"file_path": "/tmp/config[1].yaml"}},
			allowed: ToolCall{Tool: "edit", Params: map[string]any{"file_path": "/tmp/config[1].yaml"}},
			denied:  ToolCall{Tool: "edit", Params: map[string]any{"file_path": "/tmp/config1.yaml"}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "auto-allowed.yaml")
			require.NoError(t, AppendAllowRule(path, test.call))
			eng, err := New(NewFileStore(path), nil)
			require.NoError(t, err)
			assert.Equal(t, ActionAllow, eng.Evaluate(test.allowed).Action)
			assert.Equal(t, ActionDeny, eng.Evaluate(test.denied).Action)
		})
	}
}

func TestAppendAllowRule(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auto-allowed.yaml")

	call1 := ToolCall{
		Tool:   "exec",
		Params: map[string]any{"command": "kubectl apply -f foo"},
	}
	if err := AppendAllowRule(path, call1); err != nil {
		t.Fatal(err)
	}

	// Verify file is valid YAML and loadable.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("generated YAML is invalid: %v", err)
	}
	if len(cfg.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(cfg.Policies))
	}

	// Append a second rule.
	call2 := ToolCall{
		Tool:   "read",
		Params: map[string]any{"path": "/etc/hosts"},
	}
	if err := AppendAllowRule(path, call2); err != nil {
		t.Fatal(err)
	}

	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg2 Config
	if err := yaml.Unmarshal(data, &cfg2); err != nil {
		t.Fatalf("generated YAML is invalid after append: %v", err)
	}
	if len(cfg2.Policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(cfg2.Policies))
	}

	// Verify the config is loadable by the engine's validator.
	if err := cfg2.validate(); err != nil {
		t.Fatalf("generated config fails validation: %v", err)
	}
}

func TestAppendAllowRuleConcurrentWritersDoNotLoseUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auto-allowed.yaml")

	const writers = 32
	start := make(chan struct{})
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs <- AppendAllowRule(path, ToolCall{
				Tool:   "read",
				Params: map[string]any{"path": fmt.Sprintf("/tmp/concurrent-%d", i)},
			})
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent append failed: %v", err)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("generated YAML is invalid: %v", err)
	}
	if len(cfg.Policies) != writers {
		t.Fatalf("expected %d policies after concurrent appends, got %d", writers, len(cfg.Policies))
	}
}

func TestAppendAllowRuleAcrossProcessesDoesNotLoseUpdates(t *testing.T) {
	if os.Getenv("RAMPART_APPEND_PROCESS_HELPER") == "1" {
		runAppendAllowRuleProcessHelper()
		return
	}

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "auto-allowed.yaml")
	startPath := filepath.Join(dir, "start")
	const writers = 12
	type child struct {
		cmd    *exec.Cmd
		stderr bytes.Buffer
	}
	children := make([]child, writers)
	for i := range children {
		readyPath := filepath.Join(dir, "ready-"+strconv.Itoa(i))
		children[i].cmd = exec.Command(os.Args[0], "-test.run=^TestAppendAllowRuleAcrossProcessesDoesNotLoseUpdates$")
		children[i].cmd.Env = append(os.Environ(),
			"RAMPART_APPEND_PROCESS_HELPER=1",
			"RAMPART_APPEND_POLICY="+policyPath,
			"RAMPART_APPEND_START="+startPath,
			"RAMPART_APPEND_READY="+readyPath,
			"RAMPART_APPEND_INDEX="+strconv.Itoa(i),
		)
		children[i].cmd.Stderr = &children[i].stderr
		if err := children[i].cmd.Start(); err != nil {
			t.Fatal(err)
		}
	}

	deadline := time.Now().Add(10 * time.Second)
	for i := range children {
		readyPath := filepath.Join(dir, "ready-"+strconv.Itoa(i))
		for {
			if _, err := os.Stat(readyPath); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for helper %d", i)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	if err := os.WriteFile(startPath, []byte("go"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := range children {
		if err := children[i].cmd.Wait(); err != nil {
			t.Fatalf("helper %d failed: %v\nstderr: %s", i, err, children[i].stderr.String())
		}
	}

	data, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Policies) != writers {
		t.Fatalf("expected %d policies after process appends, got %d", writers, len(cfg.Policies))
	}
}

func runAppendAllowRuleProcessHelper() {
	if err := os.WriteFile(os.Getenv("RAMPART_APPEND_READY"), []byte("ready"), 0o600); err != nil {
		os.Exit(20)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(os.Getenv("RAMPART_APPEND_START")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			os.Exit(21)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := AppendAllowRule(os.Getenv("RAMPART_APPEND_POLICY"), ToolCall{
		Tool:   "read",
		Params: map[string]any{"path": "/tmp/process-" + os.Getenv("RAMPART_APPEND_INDEX")},
	}); err != nil {
		os.Exit(22)
	}
	os.Exit(0)
}

func TestAppendAllowRule_CreatesDirectories(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deep", "nested", "auto-allowed.yaml")

	call := ToolCall{
		Tool:   "exec",
		Params: map[string]any{"command": "echo hello"},
	}
	if err := AppendAllowRule(path, call); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not created: %v", err)
	}
}

func TestPolicyMutationsPreserveRichConfig(t *testing.T) {
	operations := []struct {
		name string
		run  func(string) error
	}{
		{
			name: "append allow rule",
			run: func(path string) error {
				return AppendAllowRule(path, ToolCall{Tool: "read", Params: map[string]any{"path": "/tmp/extra"}})
			},
		},
		{
			name: "migrate legacy glob",
			run: func(path string) error {
				_, err := MigrateAllowRuleGlobs(path)
				return err
			},
		},
		{
			name: "clean expired rule",
			run: func(path string) error {
				_, err := CleanExpiredRules(path)
				return err
			},
		},
		{
			name: "remove rule",
			run: func(path string) error {
				return RemoveRule(path, "rich-policy", 0)
			},
		},
	}

	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			cfg, richRule := richPersistenceConfig()
			path := filepath.Join(t.TempDir(), "policy.yaml")
			require.NoError(t, writeConfigAtomic(path, cfg))
			require.NoError(t, operation.run(path))

			data, err := os.ReadFile(path)
			require.NoError(t, err)
			var got Config
			require.NoError(t, safeUnmarshal(data, &got))

			assert.Equal(t, cfg.Version, got.Version)
			assert.Equal(t, cfg.DefaultAction, got.DefaultAction)
			assert.Equal(t, cfg.Notify, got.Notify)
			assert.Equal(t, cfg.Tests, got.Tests)

			var richPolicy *Policy
			for index := range got.Policies {
				if got.Policies[index].Name == "rich-policy" {
					richPolicy = &got.Policies[index]
					break
				}
			}
			require.NotNil(t, richPolicy)
			assert.Equal(t, cfg.Policies[0].Description, richPolicy.Description)
			assert.Equal(t, cfg.Policies[0].Priority, richPolicy.Priority)
			assert.Equal(t, cfg.Policies[0].Enabled, richPolicy.Enabled)
			assert.Equal(t, cfg.Policies[0].Match, richPolicy.Match)

			var preserved *Rule
			for index := range richPolicy.Rules {
				if richPolicy.Rules[index].Message == richRule.Message {
					preserved = &richPolicy.Rules[index]
					break
				}
			}
			require.NotNil(t, preserved)
			assert.Equal(t, richRule, *preserved)
		})
	}
}

func richPersistenceConfig() (*Config, Rule) {
	enabled := true
	failOpen := true
	depthGTE := 1
	depthLTE := 4
	future := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	past := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	richRule := Rule{
		Action: "webhook",
		Ask: AskActionConfig{
			Audit:        true,
			HeadlessOnly: true,
		},
		When: Condition{
			CommandMatches:        []string{"deploy*"},
			CommandNotMatches:     []string{"deploy --dry-run*"},
			CommandContains:       []string{"production"},
			CommandEnvAssignments: []string{"DEPLOY_*"},
			PathMatches:           []string{"/srv/**"},
			PathNotMatches:        []string{"/srv/safe/**"},
			URLMatches:            []string{"https://example.com/**"},
			DomainMatches:         []string{"example.com"},
			ResponseMatches:       []string{"secret-[0-9]+"},
			ResponseNotMatches:    []string{"public-secret"},
			SessionMatches:        []string{"release-*"},
			SessionNotMatches:     []string{"release-dry-run"},
			AgentDepth: &IntRangeCondition{
				Gte: &depthGTE,
				Lte: &depthLTE,
			},
			ToolParamMatches: map[string]string{"environment": "prod*"},
			CallCount: &CallCountCondition{
				Tool:   "exec",
				Gte:    2,
				Window: "5m",
			},
		},
		Message: "rich rule",
		Webhook: &WebhookActionConfig{
			URL:      "https://example.com/decision",
			Timeout:  Duration{Duration: 2 * time.Second},
			FailOpen: &failOpen,
		},
		ExpiresAt: &future,
		Once:      true,
	}

	return &Config{
		Version:       "1",
		DefaultAction: "deny",
		Notify: &NotifyConfig{
			URL:      "https://example.com/notify",
			Platform: "webhook",
			On:       []string{"deny", "ask"},
		},
		Tests: []TestCase{{
			Name:   "inline metadata survives",
			Tool:   "exec",
			Agent:  "release-agent",
			Params: map[string]any{"command": "deploy production"},
			Expect: "webhook",
		}},
		Policies: []Policy{{
			Name:        "rich-policy",
			Description: "all supported fields survive persistence",
			Priority:    7,
			Enabled:     &enabled,
			Match: Match{
				Agent:   "release-*",
				Session: "release/main",
				Tool:    StringOrSlice{"exec", "write"},
			},
			Rules: []Rule{
				{
					Action:    "allow",
					When:      Condition{CommandMatches: []string{"legacy *"}},
					Message:   "expired legacy rule",
					ExpiresAt: &past,
				},
				richRule,
			},
		}},
	}, richRule
}

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/etc/passwd", "etc-passwd"},
		{"mcp.tool.name", "mcp-tool-name"},
		{"", "unknown"},
	}
	for _, tt := range tests {
		got := sanitizeName(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
