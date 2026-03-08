package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpiredRuleIsSkipped(t *testing.T) {
	past := time.Now().UTC().Add(-1 * time.Hour)
	e := setupEngine(t, fmt.Sprintf(`
version: "1"
default_action: deny
policies:
  - name: temp-allow
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["npm install *"]
        expires_at: %s
`, past.Format(time.RFC3339)))

	dec := e.Evaluate(execCall("test", "npm install express"))
	assert.Equal(t, ActionDeny, dec.Action, "expired rule should be skipped, falling to default deny")
}

func TestActiveTemporalRuleMatches(t *testing.T) {
	future := time.Now().UTC().Add(1 * time.Hour)
	e := setupEngine(t, fmt.Sprintf(`
version: "1"
default_action: deny
policies:
  - name: temp-allow
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["npm install *"]
        expires_at: %s
`, future.Format(time.RFC3339)))

	dec := e.Evaluate(execCall("test", "npm install express"))
	assert.Equal(t, ActionAllow, dec.Action, "non-expired rule should match")
}

func TestOnceRuleSetsConsumedFlag(t *testing.T) {
	e := setupEngine(t, `
version: "1"
default_action: deny
policies:
  - name: one-shot
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["npm publish"]
        once: true
`)

	dec := e.Evaluate(execCall("test", "npm publish"))
	assert.Equal(t, ActionAllow, dec.Action)
	assert.True(t, dec.ConsumedOnce, "once rule should set ConsumedOnce flag")
	assert.Equal(t, "one-shot", dec.ConsumedRulePolicy)
	assert.Equal(t, 0, dec.ConsumedRuleIndex)
}

func TestRuleIsExpiredMethod(t *testing.T) {
	tests := []struct {
		name     string
		rule     Rule
		expected bool
	}{
		{"no expiry", Rule{Action: "allow"}, false},
		{"future expiry", Rule{Action: "allow", ExpiresAt: timePtr(time.Now().UTC().Add(1 * time.Hour))}, false},
		{"past expiry", Rule{Action: "allow", ExpiresAt: timePtr(time.Now().UTC().Add(-1 * time.Hour))}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.rule.IsExpired())
		})
	}
}

func TestCleanExpiredRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")

	past := time.Now().UTC().Add(-1 * time.Hour)
	future := time.Now().UTC().Add(1 * time.Hour)

	cfg := &Config{
		Version:       "1",
		DefaultAction: "deny",
		Policies: []Policy{
			{
				Name:  "expired-policy",
				Match: Match{Tool: StringOrSlice{"exec"}},
				Rules: []Rule{{
					Action:    "allow",
					When:      Condition{CommandMatches: []string{"old *"}},
					ExpiresAt: &past,
				}},
			},
			{
				Name:  "active-policy",
				Match: Match{Tool: StringOrSlice{"exec"}},
				Rules: []Rule{{
					Action:    "allow",
					When:      Condition{CommandMatches: []string{"new *"}},
					ExpiresAt: &future,
				}},
			},
		},
	}

	err := writeConfigAtomic(path, cfg)
	require.NoError(t, err)

	removed, err := CleanExpiredRules(path)
	require.NoError(t, err)
	assert.Equal(t, 1, removed)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(data), "active-policy")
	assert.NotContains(t, string(data), "expired-policy")
}

func TestRemoveRule(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")

	cfg := &Config{
		Version:       "1",
		DefaultAction: "deny",
		Policies: []Policy{{
			Name:  "test-policy",
			Match: Match{Tool: StringOrSlice{"exec"}},
			Rules: []Rule{
				{Action: "allow", When: Condition{CommandMatches: []string{"first *"}}},
				{Action: "allow", When: Condition{CommandMatches: []string{"second *"}}, Once: true},
			},
		}},
	}

	err := writeConfigAtomic(path, cfg)
	require.NoError(t, err)

	err = RemoveRule(path, "test-policy", 1)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(data), "first")
	assert.NotContains(t, string(data), "second")
}

func TestRemoveRuleRemovesEmptyPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")

	cfg := &Config{
		Version:       "1",
		DefaultAction: "deny",
		Policies: []Policy{{
			Name:  "single-rule",
			Match: Match{Tool: StringOrSlice{"exec"}},
			Rules: []Rule{
				{Action: "allow", When: Condition{CommandMatches: []string{"only *"}}, Once: true},
			},
		}},
	}

	err := writeConfigAtomic(path, cfg)
	require.NoError(t, err)

	err = RemoveRule(path, "single-rule", 0)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "single-rule")
}

func TestCleanExpiredRulesNoFile(t *testing.T) {
	removed, err := CleanExpiredRules("/nonexistent/path.yaml")
	assert.NoError(t, err)
	assert.Equal(t, 0, removed)
}

func TestExpiredRuleInAutoAllowSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auto-allowed.yaml")

	past := time.Now().UTC().Add(-1 * time.Hour)
	cfg := &Config{
		Version:       "1",
		DefaultAction: "deny",
		Policies: []Policy{{
			Name:  "temp",
			Match: Match{Tool: StringOrSlice{"exec"}},
			Rules: []Rule{{
				Action:    "allow",
				When:      Condition{CommandMatches: []string{"docker *"}},
				ExpiresAt: &past,
			}},
		}},
	}

	err := writeConfigAtomic(path, cfg)
	require.NoError(t, err)

	call := ToolCall{Tool: "exec", Params: map[string]any{"command": "docker ps"}}
	assert.False(t, MatchesAutoAllowFile(path, call), "expired auto-allow should not match")
}

func TestConsumeOnceRuleRemovesFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	yaml := `
version: "1"
default_action: deny
policies:
  - name: one-shot
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["npm publish"]
        once: true
      - action: allow
        when:
          command_matches: ["npm test"]
`
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0o644))

	store := NewFileStore(path)
	eng, err := New(store, nil)
	require.NoError(t, err)

	// Evaluate — should match and set ConsumedOnce.
	dec := eng.Evaluate(execCall("test", "npm publish"))
	assert.Equal(t, ActionAllow, dec.Action)
	assert.True(t, dec.ConsumedOnce)

	// Consume the rule.
	err = eng.ConsumeOnceRule(dec.ConsumedRulePolicy, dec.ConsumedRuleIndex)
	require.NoError(t, err)

	// Verify: rule is gone from file and engine.
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "npm publish")
	assert.Contains(t, string(data), "npm test", "non-once rule should survive")

	// Second evaluation should deny (rule consumed).
	dec2 := eng.Evaluate(execCall("test", "npm publish"))
	assert.Equal(t, ActionDeny, dec2.Action, "consumed once rule should no longer match")
}

func TestConsumeOnceRuleNoFilePath(t *testing.T) {
	// Load via setupEngine (which sets FilePath), then clear it to simulate
	// an inline/embedded config with no backing file.
	eng := setupEngine(t, `
version: "1"
default_action: deny
policies:
  - name: inline
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["echo hi"]
        once: true
`)

	// Clear FilePath to simulate no backing file.
	eng.mu.Lock()
	for i := range eng.config.Policies {
		eng.config.Policies[i].FilePath = ""
	}
	eng.mu.Unlock()

	dec := eng.Evaluate(execCall("test", "echo hi"))
	assert.Equal(t, ActionAllow, dec.Action)
	assert.True(t, dec.ConsumedOnce)

	// ConsumeOnceRule should fail gracefully — no file to modify.
	err := eng.ConsumeOnceRule(dec.ConsumedRulePolicy, dec.ConsumedRuleIndex)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no file path")
}

func TestConsumeOnceRuleLastRuleRemovesPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	yaml := `
version: "1"
default_action: deny
policies:
  - name: one-and-done
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["deploy *"]
        once: true
  - name: permanent
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["git *"]
`
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0o644))

	store := NewFileStore(path)
	eng, err := New(store, nil)
	require.NoError(t, err)

	dec := eng.Evaluate(execCall("test", "deploy prod"))
	require.True(t, dec.ConsumedOnce)

	err = eng.ConsumeOnceRule(dec.ConsumedRulePolicy, dec.ConsumedRuleIndex)
	require.NoError(t, err)

	// The entire "one-and-done" policy should be gone (it had only one rule).
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "one-and-done")
	assert.Contains(t, string(data), "permanent", "other policies should survive")
}

func TestFileStoreSetFilePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")

	yaml := `
version: "1"
default_action: deny
policies:
  - name: test-fp
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["ls *"]
`
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0o644))

	store := NewFileStore(path)
	cfg, err := store.Load()
	require.NoError(t, err)

	// FileStore should set FilePath on loaded policies.
	require.Len(t, cfg.Policies, 1)
	absPath, _ := filepath.Abs(path)
	assert.Equal(t, absPath, cfg.Policies[0].FilePath)
}

func TestLayeredStoreSetFilePathOnProjectPolicies(t *testing.T) {
	dir := t.TempDir()

	// Base policy file.
	basePath := filepath.Join(dir, "base.yaml")
	baseYAML := `
version: "1"
default_action: deny
policies:
  - name: base-policy
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["git *"]
`
	require.NoError(t, os.WriteFile(basePath, []byte(baseYAML), 0o644))

	// Project policy file (layered on top).
	projectPath := filepath.Join(dir, "project.yaml")
	projectYAML := `
version: "1"
policies:
  - name: project-policy
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["npm *"]
        once: true
`
	require.NoError(t, os.WriteFile(projectPath, []byte(projectYAML), 0o644))

	base := NewFileStore(basePath)
	store := NewLayeredStore(base, projectPath, nil)
	cfg, err := store.Load()
	require.NoError(t, err)

	// Both policies should have FilePath set.
	require.Len(t, cfg.Policies, 2)

	absBase, _ := filepath.Abs(basePath)
	absProject, _ := filepath.Abs(projectPath)

	var basePolicy, projectPolicy *Policy
	for i := range cfg.Policies {
		switch cfg.Policies[i].Name {
		case "base-policy":
			basePolicy = &cfg.Policies[i]
		case "project-policy":
			projectPolicy = &cfg.Policies[i]
		}
	}

	require.NotNil(t, basePolicy, "base policy should exist")
	require.NotNil(t, projectPolicy, "project policy should exist")
	assert.Equal(t, absBase, basePolicy.FilePath, "base policy should point to base file")
	assert.Equal(t, absProject, projectPolicy.FilePath, "project policy should point to project file")
}

func TestConsumeOnceRuleThroughLayeredStore(t *testing.T) {
	dir := t.TempDir()

	// Base policy — permanent rules.
	basePath := filepath.Join(dir, "base.yaml")
	baseYAML := `
version: "1"
default_action: deny
policies:
  - name: base
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["git *"]
`
	require.NoError(t, os.WriteFile(basePath, []byte(baseYAML), 0o644))

	// Project policy — once rule (this is what `rampart allow --once` creates).
	projectPath := filepath.Join(dir, "project.yaml")
	projectYAML := `
version: "1"
policies:
  - name: custom-allow
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["echo deploy-now"]
        once: true
`
	require.NoError(t, os.WriteFile(projectPath, []byte(projectYAML), 0o644))

	base := NewFileStore(basePath)
	store := NewLayeredStore(base, projectPath, nil)
	eng, err := New(store, nil)
	require.NoError(t, err)

	// Should allow and flag as consumed.
	dec := eng.Evaluate(execCall("test", "echo deploy-now"))
	assert.Equal(t, ActionAllow, dec.Action)
	assert.True(t, dec.ConsumedOnce)
	assert.Equal(t, "custom-allow", dec.ConsumedRulePolicy)

	// Consume — should remove from project file only.
	err = eng.ConsumeOnceRule(dec.ConsumedRulePolicy, dec.ConsumedRuleIndex)
	require.NoError(t, err)

	// Project file should be cleaned up.
	data, err := os.ReadFile(projectPath)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "deploy-now")

	// Base file should be untouched.
	baseData, err := os.ReadFile(basePath)
	require.NoError(t, err)
	assert.Contains(t, string(baseData), "git")

	// Re-evaluation should deny.
	dec2 := eng.Evaluate(execCall("test", "echo deploy-now"))
	assert.Equal(t, ActionDeny, dec2.Action)
}

func BenchmarkEvaluateWithTemporalRules(b *testing.B) {
	future := time.Now().UTC().Add(1 * time.Hour)
	past := time.Now().UTC().Add(-1 * time.Hour)

	dir := b.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	// Mix of expired, active temporal, and permanent rules.
	yaml := fmt.Sprintf(`
version: "1"
default_action: deny
policies:
  - name: expired-rule
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["old *"]
        expires_at: %s
  - name: active-temporal
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["npm *"]
        expires_at: %s
  - name: permanent
    match:
      tool: exec
    rules:
      - action: allow
        when:
          command_matches: ["git *"]
`, past.Format(time.RFC3339), future.Format(time.RFC3339))

	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		b.Fatal(err)
	}
	store := NewFileStore(path)
	eng, err := New(store, nil)
	if err != nil {
		b.Fatal(err)
	}

	call := execCall("bench", "git push origin main")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.Evaluate(call)
	}
}

func timePtr(t time.Time) *time.Time {
	return &t
}
