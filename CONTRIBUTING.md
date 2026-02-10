# Contributing to Rampart

Thank you for your interest in Rampart. This document covers the code style, patterns, and conventions that all contributions must follow.

## Contributor License Agreement

By submitting a contribution, you agree that your work is licensed under Apache 2.0 and you grant the project maintainers the right to relicense your contributions.

## Code Style

Rampart code is tight, purposeful, and readable. Every line earns its place.

### The Golden Rules

1. **Stdlib first.** If the standard library can do it, use the standard library.
2. **No magic.** A reader should understand any function without scrolling.
3. **Errors are values.** Handle them explicitly. Never swallow them.
4. **Comments explain WHY, not WHAT.** The code says what. Comments say why.
5. **50-line functions.** If a function is longer, it does too much. Extract.

### Good Code Looks Like This

```go
// matchGlob reports whether name matches the glob pattern.
// Extends filepath.Match with support for command-style patterns
// where "git *" matches "git push origin main".
func matchGlob(pattern, name string) bool {
	if pattern == "" {
		return false
	}
	if pattern == "*" {
		return true
	}

	// Command patterns: "git *" should match "git push origin main".
	// filepath.Match requires exact segment matching, so we handle
	// trailing wildcards as prefix checks.
	if strings.HasSuffix(pattern, " *") {
		prefix := strings.TrimSuffix(pattern, " *")
		return name == prefix || strings.HasPrefix(name, prefix+" ")
	}

	matched, err := filepath.Match(pattern, name)
	if err != nil {
		return false // invalid pattern = no match, not a panic
	}
	return matched
}
```

Why this is good:
- Godoc comment on the function.
- Comment in the body explains the *why* (filepath.Match doesn't handle this case).
- Early returns for simple cases.
- Handles errors without panicking.
- 20 lines. Does one thing.

### Bad Code Looks Like This

```go
// DON'T DO THIS
func processToolCall(call ToolCall, config *Config, logger *slog.Logger, auditSink AuditSink) (interface{}, error) {
	// check if the tool call is valid
	if call.Tool == "" {
		logger.Error("tool is empty")
		return nil, errors.New("tool is empty")
	}
	result := Decision{}
	for _, p := range config.Policies {
		if p.Enabled != nil && !*p.Enabled {
			continue
		}
		// ... 150 more lines
	}
	// ... audit logging mixed in here
	// ... approval flow mixed in here
	return result, nil
}
```

Why this is bad:
- `interface{}` instead of `any`.
- Does too many things (evaluate + audit + approve).
- 150-line function.
- Generic name (`processToolCall`).
- Comment restates the code (`check if the tool call is valid`).

### Naming Conventions

```go
// Package names: lowercase, single word.
package engine  // ✓
package policyEngine  // ✗

// Types: exported, descriptive, noun.
type PolicyEngine struct{}  // ✓
type PE struct{}  // ✗

// Functions: verb-noun for actions, noun for getters.
func (e *Engine) Evaluate(call ToolCall) Decision  // ✓
func (e *Engine) DoEvaluation(call ToolCall) Decision  // ✗
func (p Policy) IsEnabled() bool  // ✓
func (p Policy) GetEnabled() bool  // ✗ (Java-style getters don't belong in Go)

// Errors: Err prefix for sentinels, wrap with component prefix.
var ErrDenied = errors.New("rampart: denied")  // ✓
return fmt.Errorf("engine: load policy: %w", err)  // ✓
return fmt.Errorf("failed to load: %w", err)  // ✗ (no component prefix)
```

### Error Handling

```go
// Always wrap errors with context and component prefix.
cfg, err := store.Load()
if err != nil {
	return nil, fmt.Errorf("engine: reload failed: %w", err)
}

// Use errors.Is/As for checking, not string matching.
if errors.Is(err, os.ErrNotExist) {
	// handle missing file
}

// Never panic in library code. Return errors.
// Panics are only acceptable in main() for unrecoverable startup failures.
```

### Testing

```go
func TestEvaluate_DenyWinsOverAllow(t *testing.T) {
	tests := []struct {
		name     string
		policies []Policy
		call     ToolCall
		want     Action
	}{
		{
			name: "deny beats allow at same priority",
			policies: []Policy{
				{Name: "allow-all", Rules: []Rule{{Action: "allow", When: Condition{Default: true}}}},
				{Name: "deny-rm", Rules: []Rule{{Action: "deny", When: Condition{CommandMatches: []string{"rm *"}}}}},
			},
			call: ToolCall{Tool: "exec", Params: map[string]any{"command": "rm -rf /"}},
			want: ActionDeny,
		},
		// ... more cases
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// setup and assertion
		})
	}
}
```

- Table-driven tests with descriptive names.
- Test file lives next to source: `engine.go` → `engine_test.go`.
- Use `testify/assert` for assertions, `testify/require` for fatal checks.
- Benchmark critical paths:

```go
func BenchmarkEvaluate(b *testing.B) {
	engine := setupBenchEngine(b)
	call := ToolCall{Tool: "exec", Params: map[string]any{"command": "git push"}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Evaluate(call)
	}
}
```

### File Organization

- Max ~300 lines per file. Split by responsibility.
- One type per file when the type has significant methods.
- Test files next to source: `engine.go` → `engine_test.go`.

```
internal/engine/
├── engine.go      # Engine struct + Evaluate + Reload
├── decision.go    # ToolCall, Decision, Action types
├── policy.go      # Policy, Rule, Config, FileStore types + loading
├── matcher.go     # Glob matching functions
└── engine_test.go # All engine tests
```

### Dependencies

**Allowed:**
- `gopkg.in/yaml.v3` — YAML parsing
- `github.com/spf13/cobra` — CLI framework
- `github.com/fsnotify/fsnotify` — file watching
- `github.com/stretchr/testify` — test assertions
- `github.com/oklog/ulid/v2` — event IDs
- `github.com/charmbracelet/bubbletea` — TUI (watch command only)

**Not allowed (overkill for this project):**
- gin, echo, chi — use `net/http`
- gorm — no database in MVP
- viper — use `gopkg.in/yaml.v3` directly
- logrus, zap — use `log/slog`

### Git Commits

```
feat: add deny-wins evaluation to policy engine
fix: handle empty command in exec interceptor
test: add benchmark for policy evaluation hot path
docs: update architecture with behavioral vision
refactor: extract glob matching into matcher.go
```

- Conventional commit prefixes: `feat:`, `fix:`, `test:`, `docs:`, `refactor:`, `ci:`, `chore:`
- One logical change per commit.
- All tests pass before committing.
- No WIP commits in the final history.
