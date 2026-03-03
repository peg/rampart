# Contributing to Rampart

Rampart is a security product. Code quality isn't optional — it's the product. Every PR is reviewed with the assumption that adversaries will read the source looking for weaknesses.

## Contributor License Agreement

By submitting a contribution, you agree that your work is licensed under Apache 2.0 and you grant the project maintainers the right to relicense your contributions.

## Philosophy

Rampart code is tight, purposeful, and readable. Every line earns its place.

### The Golden Rules

1. **Stdlib first.** If the standard library can do it, use the standard library.
2. **No magic.** A reader should understand any function without scrolling.
3. **Errors are values.** Handle them explicitly. Never swallow them.
4. **Comments explain WHY, not WHAT.** The code says what. Comments say why.
5. **Extract business logic.** CLI commands wire things together. Logic belongs in `internal/` packages where it can be tested independently.

## Code Style

### Functions

Keep functions focused. A function that does one thing is easy to test, easy to review, and easy to trust.

**Business logic functions** (engine evaluation, audit writing, policy parsing): aim for **50 lines or fewer**. If you're over 50, you're probably mixing concerns. Extract.

**CLI command handlers** (cobra RunE functions): these are inherently longer because they wire flags, validation, setup, and execution. That's fine — but the *logic they call* should be extracted into testable functions. A 200-line RunE that calls 10 well-tested functions is better than a 50-line RunE that does too little.

**Test functions**: no length limit. Readability matters more than brevity in tests.

### Files

Organize by responsibility, not by arbitrary line counts. A 600-line file that owns one coherent responsibility is better than three 200-line files that force readers to jump around.

Signs a file should be split:
- It has multiple unrelated type definitions
- You need to scroll past code you don't care about to find what you need
- Different contributors would work on different sections simultaneously
- The file mixes concerns (HTTP handlers + business logic + data access)

### Examples

**Good:**

```go
// matchGlob reports whether name matches the glob pattern.
// Extends filepath.Match with "git *" matching "git push origin main",
// which filepath.Match can't express with its segment-based wildcards.
func matchGlob(pattern, name string) bool {
    if pattern == "" {
        return false
    }
    if pattern == "*" {
        return true
    }

    // Trailing wildcard: "git *" should match any git subcommand.
    if strings.HasSuffix(pattern, " *") {
        prefix := strings.TrimSuffix(pattern, " *")
        return name == prefix || strings.HasPrefix(name, prefix+" ")
    }

    matched, err := filepath.Match(pattern, name)
    if err != nil {
        return false
    }
    return matched
}
```

- Godoc says what and why.
- Early returns for simple cases.
- One comment in the body explains the non-obvious behavior.
- Handles errors without panicking.

**Bad:**

```go
func processToolCall(call ToolCall, config *Config, logger *slog.Logger, sink AuditSink) (any, error) {
    // validate
    if call.Tool == "" {
        return nil, errors.New("tool is empty")
    }
    // ... 150 lines mixing evaluation, audit logging, and approval flow
}
```

- Does three things (evaluate + audit + approve).
- Comment restates the code.
- Too many parameters — if you need config, logger, and sink, it's a method on a struct.

### Naming

```go
package engine              // ✓ lowercase, single word
package policyEngine        // ✗

type Engine struct{}         // ✓ exported, descriptive, noun
type PE struct{}             // ✗

func (e *Engine) Evaluate(call ToolCall) Decision  // ✓ verb-noun
func (p Policy) IsEnabled() bool                   // ✓ predicate
func (p Policy) GetEnabled() bool                  // ✗ Java-style getter
```

### Error Handling

```go
// Wrap with component prefix so errors are traceable through the call stack.
cfg, err := store.Load()
if err != nil {
    return fmt.Errorf("engine: reload: %w", err)
}

// Use errors.Is/As, not string matching.
if errors.Is(err, os.ErrNotExist) { ... }

// Never panic in library code. Return errors.
// Panics are only for unrecoverable startup failures in main().
```

## Testing

### Requirements

- **All new code must have tests.** No exceptions.
- **Critical paths must have benchmarks.** The engine's <10µs eval time is a product guarantee, not a nice-to-have. If your change touches the eval hot path, add or update a benchmark.
- **Table-driven tests** for anything with multiple input/output cases.
- **`testify/assert`** for assertions, **`testify/require`** for fatal preconditions.

### Test naming

```go
func TestEvaluate_DenyWinsOverAllow(t *testing.T)     // ✓ Unit_Behavior
func TestInitFromAudit_EmptyFile(t *testing.T)         // ✓ Feature_EdgeCase
func BenchmarkEvaluate(b *testing.B)                   // ✓ always benchmark hot paths
```

### What to test

- **Always test:** edge cases, error paths, security-relevant logic, anything in `internal/engine/`
- **Always benchmark:** anything in the eval hot path, anything that runs per-tool-call
- **Skip:** trivial getters, cobra flag wiring, string formatting

## Performance

Rampart sits in the critical path of every agent tool call. Performance isn't a feature — it's a constraint.

- **Policy evaluation: <10µs per call.** This is tested by `BenchmarkEvaluate`. Any PR that regresses this will be rejected.
- **No allocations in the hot path** unless unavoidable. Check with `go test -benchmem`.
- **No network calls during evaluation.** Webhooks and notifications happen asynchronously, after the allow/deny decision.

## Security

This is a security product. Every PR should be reviewed through an adversarial lens.

### Checklist for security-relevant changes

- [ ] Input validation: can a malicious agent craft a tool call that bypasses policy?
- [ ] Path traversal: does the change handle `../` and symlinks correctly?
- [ ] Glob safety: can a pattern be crafted to match unintended commands/paths?
- [ ] Timing: does the change introduce timing side-channels in auth or matching?
- [ ] Audit integrity: does the change preserve the hash chain?
- [ ] Fail closed: on error, does the system deny (not allow)?

### Secrets

- Never log secrets, tokens, or credentials — even at debug level.
- API tokens are compared with `crypto/subtle.ConstantTimeCompare`.
- Key material uses 0600 file permissions (skip on Windows).

## Dependencies

### Allowed (direct)

| Dependency | Purpose |
|-----------|---------|
| `gopkg.in/yaml.v3` | YAML parsing |
| `github.com/spf13/cobra` | CLI framework |
| `github.com/fsnotify/fsnotify` | File watching |
| `github.com/stretchr/testify` | Test assertions |
| `github.com/oklog/ulid/v2` | Time-ordered event IDs |
| `github.com/charmbracelet/bubbletea` | TUI (watch command) |
| `github.com/charmbracelet/huh` | Interactive prompts |
| `github.com/charmbracelet/lipgloss` | Terminal styling |
| `github.com/gorilla/websocket` | WebSocket client (daemon mode) |
| `github.com/prometheus/client_golang` | Metrics endpoint |

### Not allowed

- **HTTP frameworks** (gin, echo, chi) — use `net/http`
- **ORMs** (gorm, ent) — no database
- **Config libraries** (viper) — use `gopkg.in/yaml.v3`
- **Logging frameworks** (logrus, zap) — use `log/slog`

Adding a new dependency requires maintainer approval and a justification in the PR description.

## Git Conventions

### Commits

```
feat: add temporal allows (--for, --once)
fix: handle empty command in exec interceptor
test: add benchmark for policy evaluation hot path
docs: update architecture with behavioral vision
refactor: extract approval handlers from server.go
ci: add Docker image build on version tags
chore: update Go to 1.24
```

- **Conventional commit prefixes:** `feat:`, `fix:`, `test:`, `docs:`, `refactor:`, `ci:`, `chore:`
- One logical change per commit.
- All tests must pass before committing (`go test ./... && go vet ./...`).
- No WIP commits in the final history. Squash or rebase before merging.

### Branches

- Feature branches off `staging`: `feat/short-name`, `fix/short-name`
- PRs target `staging`
- `staging` → `main` merges are maintainer-only

### PR checklist

- [ ] `go test ./...` passes
- [ ] `go vet ./...` is clean
- [ ] New code has tests
- [ ] Hot path changes include benchmarks
- [ ] Security-relevant changes include the security checklist above
- [ ] Commit messages follow conventional format
- [ ] No new dependencies without justification

## Architecture

```
cmd/rampart/cli/     CLI command handlers (cobra wiring + flags)
internal/engine/     Policy evaluation core (HOT PATH — <10µs)
internal/intercept/  Tool-type normalizers (exec/fs/http)
internal/proxy/      HTTP server, SSE hub, approval flow
internal/audit/      Hash-chained JSONL audit trail
internal/approval/   Human approval queue
internal/mcp/        MCP JSON-RPC proxy
internal/daemon/     OpenClaw WebSocket integration
internal/tlsutil/    TLS certificate management
internal/policy/     Custom policy file management
pkg/sdk/             Public Go SDK
policies/            Built-in policy presets
```

**The deny-wins rule:** Any deny from any policy = denied. No exceptions. This is the core invariant of the engine and must never be violated.

## Known Tech Debt

We track these so contributors know where improvement is welcome:

- `internal/proxy/server.go` is 1,600+ lines — approval handlers and webhook logic should be extracted into separate files
- `cmd/rampart/cli/hook.go` mixes CLI wiring with business logic
- `internal/engine/matcher.go` is approaching 700 lines
- Some cobra RunE functions exceed 200 lines of wiring

If you want to tackle any of these, open an issue first to discuss the approach.
