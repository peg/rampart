---
hide:
  - navigation
  - toc
---

<div class="hero-title" markdown>

# Rampart

</div>

<p class="hero-subtitle">Open-source firewall for AI agents. See everything your AI does. Block the dangerous stuff.</p>

---

## What is Rampart?

Rampart is a **policy engine** that sits between AI agents and the tools they use. Every command, file access, and network request gets evaluated against your YAML policies before it executes. Dangerous actions get blocked in microseconds. Everything gets logged to a tamper-evident, hash-chained audit trail.

<div class="grid cards" markdown>

-   :shield:{ .lg .middle } **Policy Engine**

    ---

    YAML-based policies with glob matching. Deny, allow, log, or require human approval. Evaluates in **<10μs**.

    [:octicons-arrow-right-24: Learn more](features/policy-engine.md)

-   :lock:{ .lg .middle } **Audit Trail**

    ---

    Hash-chained JSONL logs. Tamper with any record and the chain breaks. Daily rotation, search, and verification.

    [:octicons-arrow-right-24: Learn more](features/audit-trail.md)

-   :bell:{ .lg .middle } **Real-time Alerts**

    ---

    Webhook notifications to Discord, Slack, or Teams when something gets blocked. SIEM export via syslog or CEF.

    [:octicons-arrow-right-24: Learn more](features/webhooks.md)

-   :plug:{ .lg .middle } **Universal Integration**

    ---

    Native hooks, shell wrapping, MCP proxy, LD_PRELOAD, HTTP API. Works with every major AI agent.

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

```mermaid
graph LR
    A[AI Agent] -->|tool call| R[Rampart]
    R -->|evaluate| P[Policy Engine<br/><10μs]
    P -->|allow| T[Tool executes]
    P -->|deny| B[Blocked + logged]
    P -->|log| L[Allowed + logged]
    R -->|always| AU[Audit Trail]
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
