# Rampart Backlog

*Last updated: 2026-02-11*

## v0.1.1 Blockers

- [ ] Credential sanitization in webhook payloads (strip passwords, tokens, API keys from notification text)
- [ ] `ParseAction` should return error on invalid input instead of defaulting to allow
- [ ] Rate limit webhook notifications (cap at ~10/min to avoid Slack/Discord rate limits)
- [ ] Detect package: handle missing home dir, permission denied, broken symlinks gracefully

## Post-v0.1.1 — Short Term

### Webhook Improvements
- [ ] Wire notifications into `wrap.go` and `mcp.go` CLI paths (currently only proxy sink) — PR #4 addresses this
- [ ] Add `notify_helper.go` unit tests (extractCommand edge cases)
- [ ] Retry with exponential backoff for failed webhook deliveries
- [ ] Configurable HTTP timeout for webhooks (currently hardcoded 5s)

### Test Coverage
- [ ] `internal/report/` — currently no tests for HTML generation (added basic tests, need more)
- [ ] `internal/detect/` — 49% coverage, needs Environment() tests and edge cases
- [ ] `cmd/rampart/cli/` — 37.8% coverage, needs integration tests
- [ ] MCP proxy has no tests (flagged in pre-launch review)

### Code Organization
- [ ] `wrap.go` (604 lines) could be split into wrapper + intercept modules
- [ ] HTML template in `internal/report/html.go` is a 400-line string literal — consider `embed` directive

## Post-v0.1.1 — Medium Term

### Exfiltration Detection (v0.2.0)
- [ ] Detect secret patterns (AKIA, ghp_, xoxb_, private keys) in network-bound commands
- [ ] Only flag in curl/wget/nc/ssh contexts to minimize false positives
- [ ] Ship as `log` action first, let users promote to `deny`
- [ ] See `docs/MCP-SANDBOX-PROPOSAL.md` for full spec

### Shareability & Multiplayer
- [ ] `rampart report` improvements — export to PDF, email-friendly format
- [ ] GitHub Action — wrap AI agents in CI, post PR comment with tool call summary
- [ ] Community rules library — shareable policy patterns (like Sigma/YARA)

### Onboarding
- [ ] `rampart init --detect` improvements — detect more tools (Cursor, Windsurf, Codex CLI)
- [ ] Interactive init mode (prompt user through setup)
- [ ] `--suggest-policy` from MCP tool schemas

### MCP
- [ ] HTTP/SSE transport support (~5 day build)
- [ ] Rug pull detection — hash `tools/list` on connect, alert on changes
- [ ] Response sandboxing — inspect MCP server responses for injection attempts
- [ ] MCP proxy tests

### MCP Sandbox (v0.3.0+)
- [ ] Deno-style per-server permissions (network allowlist, filesystem restrict, no exec)
- [ ] Linux namespace isolation for MCP server processes
- [ ] macOS support via Lima/colima
- [ ] See `docs/MCP-SANDBOX-PROPOSAL.md` for full spec

## Won't Fix / Deferred Indefinitely

- **SSRF protection for webhook URLs** — user controls their own config, not untrusted input
- **TLS cert config for webhooks** — stdlib defaults are fine, adding options is scope creep
- **Goroutine pool for webhooks** — 5s HTTP timeout prevents leaks, pool is over-engineering
- **Lightweight hook-only binary** — cool optimization but 13MB is already small for Go CLI
- **Codex CLI support** — uses getpwuid(), no hook system, cannot be protected

## Dependencies (45 total)

No new deps added in v0.1.1. All new packages (notify, report, detect) use stdlib only.

Major deps:
- `github.com/spf13/cobra` — CLI framework (+ viper, pflag)
- `github.com/charmbracelet/bubbletea` — TUI for `rampart watch` (+ lipgloss, 13 transitive)
- `github.com/gorilla/websocket` — daemon WebSocket communication
- `github.com/oklog/ulid/v2` — time-ordered unique IDs for audit events
- `github.com/fsnotify/fsnotify` — file watching for audit tail
