---
title: Rampart
description: "Rampart is an open-source security policy engine for AI coding agents. Block dangerous commands, detect prompt injection, and audit every tool call."
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

## Frequently Asked Questions

**Is Claude Code safe to use in --dangerously-skip-permissions mode?**  
It can be — with guardrails. `--dangerously-skip-permissions` gives Claude Code full shell access, which is powerful but risky. Rampart provides those guardrails: every command is evaluated against your policy before it runs. [Full guide →](guides/securing-claude-code.md)

**What happens if my AI agent runs a destructive command?**  
Without Rampart: it runs. With Rampart: the command is evaluated against your policy in under 10μs. If it matches a deny rule, it's blocked before execution and logged. Claude Code receives the denial reason and explains it to you.

**Can AI agents be manipulated by prompt injection?**  
Yes — a webpage or MCP tool response can contain instructions that try to override an agent's behavior. Rampart's `watch-prompt-injection` policy monitors tool responses for these patterns and logs them for review. [Learn more →](guides/prompt-injection.md)

**Does Rampart send my commands to any external server?**  
No. Rampart runs entirely on your machine. Policy evaluation, audit logging, and the dashboard are all local processes. No command data, file paths, or decisions are sent anywhere.

**Will Rampart slow down my agent?**  
Policy evaluation takes under 10 microseconds per tool call. In practice, you won't notice it.

**What if I need to allow a command that's blocked?**  
Add an allow rule to `~/.rampart/policies/standard.yaml`, or use `require_approval` so you decide per-instance rather than changing the policy.

## How It Works

![Rampart Architecture](assets/architecture.png)

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
