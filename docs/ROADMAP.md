# Roadmap

What's coming next for Rampart. Priorities shift based on feedback — open an issue if something matters to you.

## Recently Shipped (v0.1.x)

- ✅ Claude Code hook integration
- ✅ MCP protocol proxy
- ✅ Shell wrapper (`rampart wrap`)
- ✅ Live TUI dashboard (`rampart watch`)
- ✅ HTML audit reports (`rampart report`)
- ✅ Webhook notifications (Slack, Discord, Teams)
- ✅ Environment detection (`rampart init --detect`)

## Up Next

- **Smarter MCP enforcement** — transport improvements, tool schema analysis
- **CI integration** — GitHub Action for wrapping AI agents in pull requests
- **Policy intelligence** — detect credential exfiltration patterns in tool calls
- **Starter policy library** — curated policies for common stacks

## Future

- **MCP server isolation** — Deno-style per-server permissions
- **Community rules** — shareable policy patterns
- **Response evaluation** — inspect tool outputs, not just inputs

## Non-Goals

Rampart is a policy engine for agents that operate in the real world. We don't chase full sandboxing — if an agent can be sandboxed, it doesn't need Rampart. We focus on the agents that *can't* be locked down because they need access to your actual infrastructure.

---

Have ideas? [Open an issue](https://github.com/peg/rampart/issues) or reach out at rampartsec@pm.me.
