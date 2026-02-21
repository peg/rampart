# Roadmap

What's coming next for Rampart. Priorities shift based on feedback — [open an issue](https://github.com/peg/rampart/issues) if something matters to you.

## Recently Shipped

- ✅ Native hooks for Claude Code (PreToolUse + PostToolUse) and Cline
- ✅ MCP protocol proxy with auto-policy generation (`rampart mcp scan`)
- ✅ Shell wrapper (`rampart wrap`) and LD_PRELOAD interception
- ✅ Live TUI dashboard and HTML reports
- ✅ Webhook notifications and webhook actions
- ✅ SIEM integration (syslog + CEF)
- ✅ Semantic verification sidecar ([rampart-verify](https://github.com/peg/rampart-verify))
- ✅ Human-in-the-loop approval flow with HMAC-signed resolve URLs
- ✅ Embedded web dashboard with security headers
- ✅ OpenClaw integration (auto-detection, chat-based approval)
- ✅ Shell-aware command normalization (prevents quote/backslash/env var evasion)
- ✅ Response-side scanning (detects credential leaks in tool output)
- ✅ Policy test framework (`rampart test`)
- ✅ Policy linter (`rampart policy lint`) with typo suggestions
- ✅ Prometheus metrics endpoint (opt-in via `--metrics`)
- ✅ Cross-platform release builds (goreleaser + Homebrew)
- ✅ Security audit — govulncheck CI, SHA-pinned actions, audit file hardening
- ✅ `rampart init --project` / project-local `.rampart/policy.yaml` (v0.3.0)
- ✅ Session conditions `session_matches` / `session_not_matches` (v0.3.0)
- ✅ `rampart doctor --json` and `rampart test --json` (v0.3.0)
- ✅ Run grouping / `run_id` on audit events — team run traceability (v0.4.0)
- ✅ `POST /v1/approvals/bulk-resolve` — resolve entire team run approvals in one call (v0.4.0)
- ✅ Auto-approve cache for team runs (v0.4.0)
- ✅ SSE live dashboard — real-time event streaming, no polling (v0.4.0)
- ✅ `rampart serve --background` / `rampart serve stop` (v0.4.3)
- ✅ `rampart upgrade` with `--no-policy-update` flag (v0.4.3/v0.4.4)
- ✅ `command_contains` condition type — substring matching, case-insensitive (v0.4.4)
- ✅ macOS hardening — 17 new built-in policies (Keychain, Gatekeeper, persistence, osascript) (v0.4.4)
- ✅ `custom.yaml` template created on `rampart setup` (v0.4.4)
- ✅ Policy files auto-refreshed on `rampart upgrade` (v0.4.4)
- ✅ `rampart setup codex` — wrapper at `~/.local/bin/codex` (v0.4.5)
- ✅ Upgrade archive fix — `rampart upgrade` now works correctly from v0.4.5 forward (v0.4.5)

## Up Next

- Shell-aware parsing for `$(...)` and process substitution
- Starter policy library for common stacks (web dev, infra, data science)
- Tutorial docs ("Protect your first agent in 5 minutes")
- Dashboard improvements
- CI/CD integration examples (GitHub Actions, GitLab CI)
- Fleet management and centralized policy distribution

## Non-Goals

Rampart is a policy engine for agents that operate in the real world. We don't chase full sandboxing — if an agent can be sandboxed, it doesn't need Rampart. We focus on the agents that *can't* be locked down because they need real access to your infrastructure.

---

Have ideas? [Open an issue](https://github.com/peg/rampart/issues) or reach out at rampartsec@pm.me.
