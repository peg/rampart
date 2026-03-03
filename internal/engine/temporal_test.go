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
