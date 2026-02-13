# Roadmap

What's coming next for Rampart. Priorities shift based on feedback — open an issue if something matters to you.

## Recently Shipped

- ✅ Native hooks for Claude Code and Cline
- ✅ MCP protocol proxy with auto-policy generation
- ✅ Shell wrapper and LD_PRELOAD interception
- ✅ Live TUI dashboard and HTML reports
- ✅ Webhook notifications and webhook actions
- ✅ SIEM integration (syslog + CEF)
- ✅ Semantic verification sidecar ([rampart-verify](https://github.com/peg/rampart-verify))

## Up Next

- Expanded integration guides
- Starter policy library for common stacks
- CI/CD integration
- Additional SIEM platform guides

## Non-Goals

Rampart is a policy engine for agents that operate in the real world. We don't chase full sandboxing — if an agent can be sandboxed, it doesn't need Rampart. We focus on the agents that *can't* be locked down because they need real access to your infrastructure.

---

Have ideas? [Open an issue](https://github.com/peg/rampart/issues) or reach out at rampartsec@pm.me.
