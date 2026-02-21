---
hide:
  - navigation
  - toc
---

<div class="hero-title" markdown>

# Rampart

</div>

<p class="hero-subtitle">Open-source guardrails for AI agents. A policy firewall for shell commands, file access, and MCP tools.</p>

---

## What is Rampart?

Rampart is a **policy engine** that sits between AI agents and the tools they use. Every command, file access, and network request gets evaluated against your YAML policies before it executes. Dangerous actions get blocked in microseconds. Everything gets logged to a tamper-evident audit trail where each entry is cryptographically linked to the previous one — if anyone tampers with a record, the chain breaks.

<div class="grid cards" markdown>

-   :material-shield-check:{ .lg .middle } **Policy Engine**

    ---

    YAML-based policies with glob matching. Deny, allow, log, or require human approval. Evaluates in **<10μs**.

    [:octicons-arrow-right-24: Learn more](features/policy-engine.md)

-   :material-lock:{ .lg .middle } **Audit Trail**

    ---

    Tamper-evident logs where every entry is linked to the last. Daily rotation, search, and verification built in.

    [:octicons-arrow-right-24: Learn more](features/audit-trail.md)

-   :material-bell-ring:{ .lg .middle } **Real-time Alerts**

    ---

    Webhook notifications to Discord, Slack, or Teams when something gets blocked. Export to security monitoring tools (Splunk, Wazuh, etc.) via syslog.

    [:octicons-arrow-right-24: Learn more](features/webhooks.md)

-   :material-connection:{ .lg .middle } **Universal Integration**

    ---

    Native hooks, shell wrapping, MCP proxy, system-level interception, HTTP API. Works with every major AI agent.

    [:octicons-arrow-right-24: Integration guides](integrations/index.md)

</div>

## Quick Start

```bash
# Install
brew tap peg/rampart && brew install rampart

# Protect Claude Code (one command)
rampart setup claude-code

# Use Claude Code normally — Rampart is transparent
claude
```

That's it. Every tool call now goes through Rampart's policy engine. [Full setup guide →](getting-started/quickstart.md)

## How It Works

```d2
direction: right

agents: {
  label: "AI Agents"
  claude: "Claude Code"
  cline: "Cline"
  openclaw: "OpenClaw"
  codex: "Codex CLI"
  other: "Any Agent"
}

intercept: {
  label: "Interception"
  hooks: "Native Hooks"
  shim: "Shell Shim"
  preload: "LD_PRELOAD"
  mcp: "MCP Proxy"
}

engine: "YAML Policy Engine\n<10μs" {
  style.fill: "#1d3320"
  style.stroke: "#2ea043"
  style.font-color: "#3fb950"
  style.border-radius: 8
}

verify: "rampart-verify\n(optional sidecar)" {
  style.stroke-dash: 4
  style.border-radius: 8
}

audit: "Audit Trail\nhash-chained" {
  style.border-radius: 8
}

outcomes: {
  label: "Outcomes"
  allow: "Execute" {
    style.fill: "#1d3320"
    style.stroke: "#2ea043"
    style.font-color: "#3fb950"
    style.border-radius: 6
  }
  deny: "Blocked" {
    style.fill: "#2d1b1b"
    style.stroke: "#da3633"
    style.font-color: "#f85149"
    style.border-radius: 6
  }
  approval: "Approval" {
    style.fill: "#2d2508"
    style.stroke: "#d29922"
    style.font-color: "#d29922"
    style.border-radius: 6
  }
}

agents.claude -> intercept.hooks
agents.cline -> intercept.hooks
agents.openclaw -> intercept.shim
agents.codex -> intercept.preload
agents.other -> intercept.mcp

intercept.hooks -> engine
intercept.shim -> engine
intercept.preload -> engine
intercept.mcp -> engine

engine -> outcomes.allow: "allow"
engine -> outcomes.deny: "deny"
engine -> verify: "ambiguous"
engine -> audit

verify -> outcomes.allow
verify -> outcomes.deny
verify -> outcomes.approval
```

## Works With Every Agent

| Agent | Integration | Setup |
|-------|------------|-------|
| **Claude Code** | Native hooks | `rampart setup claude-code` |
| **Cline** | Native hooks | `rampart setup cline` |
| **Cursor** | MCP proxy | `rampart mcp --` |
| **Claude Desktop** | MCP proxy | `rampart mcp --` |
| **Codex CLI** | LD_PRELOAD | `rampart preload --` |
| **OpenClaw** | Shim + service | `rampart setup openclaw` |
| **Any CLI agent** | Shell wrapper | `rampart wrap --` |
| **Python agents** | HTTP API / SDK | `localhost:9090` |

[:octicons-arrow-right-24: See all integration guides](integrations/index.md)
