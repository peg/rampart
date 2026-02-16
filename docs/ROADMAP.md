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
