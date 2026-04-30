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

Rampart is a **policy engine** that sits between AI agents and the tools they use. Every command, file access, and network request gets evaluated against your YAML policies before it executes. Dangerous actions get blocked instantly. Everything gets logged to a tamper-evident audit trail where each entry is cryptographically linked to the previous one — if anyone tampers with a record, the chain breaks.

Rampart also scans tool **responses** — if your agent reads a file containing credentials, the response is blocked before those secrets enter the agent's context window. [Learn more →](reference/owasp-mapping.md#response-scanning-asi06)

<div class="grid cards" markdown>

-   :material-shield-check:{ .lg .middle } **Policy Engine**

    ---

    YAML-based policies with glob matching. Deny, allow, log, or require human approval. Zero noticeable overhead.

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

    Native hooks, native plugins, shell wrapping, MCP proxy, system-level interception, HTTP API. Works with every major AI agent.

    [:octicons-arrow-right-24: Integration guides](integrations/index.md)

-   :material-shield-alert:{ .lg .middle } **Response Scanning**

    ---

    Block credentials in tool responses before they reach the agent's context window. Prevents secrets from being exfiltrated in later turns.

    [:octicons-arrow-right-24: How it works](reference/owasp-mapping.md#response-scanning-asi06)

-   :material-certificate:{ .lg .middle } **OWASP Agentic Top 10**

    ---

    Mapped against the 2026 OWASP framework for autonomous AI agents. 1 fully covered, 8 partially mitigated, 1 not addressed, with honest assessment of gaps.

    [:octicons-arrow-right-24: Full mapping](reference/owasp-mapping.md)

</div>

## Quick Start

```bash
# Install
brew tap peg/rampart && brew install rampart

# Claude Code
rampart setup claude-code

# OpenClaw
rampart setup openclaw
```

That's it. Pick the integration that matches your agent. [Full setup guide →](getting-started/quickstart.md) · [Support matrix →](getting-started/support-matrix.md)

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
Policy checks are pure in-memory pattern matching — no network calls, no disk I/O, no measurable impact on your agent's workflow.

**What if I need to allow a command that's blocked?**  
Run `rampart allow "your command pattern"` and it's done — no YAML editing required. The rule takes effect immediately. For one-time exceptions, use `action: ask` in your policy so you can approve each instance. [Full guide →](guides/customizing-policy.md)

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
  plugin: "Native Plugin"
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
agents.openclaw -> intercept.plugin
agents.codex -> intercept.preload
agents.other -> intercept.mcp

intercept.hooks -> engine
intercept.plugin -> engine
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
| **OpenClaw** | Native plugin | `rampart setup openclaw` |
| **Codex CLI** | Wrapper + preload | `rampart setup codex` |
| **Cursor** | MCP proxy | `rampart mcp --` |
| **Claude Desktop** | MCP proxy | `rampart mcp --` |
| **Any CLI agent** | Shell wrapper | `rampart wrap --` |
| **Python agents** | HTTP API / SDK | `localhost:9090` |

[:octicons-arrow-right-24: See all integration guides](integrations/index.md)

## What's New in v0.9.19

- **Integration hardening runway** — Codex wrapper setup is idempotent, uninstall is safer, and source builds now fail clearly when the preload library is missing. [Details →](integrations/codex-cli.md)
- **OpenClaw degraded mode clarified** — Sensitive tools block when Rampart serve is unavailable; explicitly configured lower-risk tools can still fail open. [Details →](integrations/openclaw.md)
- **Claude Code hook errors cleaned up** — Invalid or stale policies fail closed through structured hook responses instead of noisy shell-hook stderr.

### v0.9.18

- **Policy explain ergonomics** — `rampart policy explain` shows winning rules, source files, durable overrides, and session/tool context.
- **OpenClaw readiness checks** — `rampart doctor` reports native plugin readiness and approval-path state more clearly.
- **Release hygiene** — Changelog and plugin metadata now track release state more explicitly.

### v0.9.17

- **OpenClaw approval trust** — Native Discord exec approvals are the supported path for Rampart's OpenClaw integration. OpenClaw owns approval UI/state, Rampart owns policy, audit, and allow-always persistence. [Details →](integrations/openclaw.md)
- **Durable Allow Always** — OpenClaw approvals can persist safe learned rules to `user-overrides.yaml`.
- **Sensitive degraded-mode behavior** — High-risk OpenClaw tools stop silently bypassing policy when the service is unavailable.

### v0.9.13

- **`plugins.allow` set automatically** — Setup now adds `rampart` to OpenClaw's `plugins.allow` config. Existing plugins are preserved — only appends, never overwrites. No more "plugins.allow is empty" warning in `openclaw doctor`.
- **Plugin version corrected** — Plugin now reports the actual Rampart version instead of `0.1.0`.
- **`rampart doctor` false positives fixed** — Dist-patch and ask-mode warnings are now suppressed when the native plugin is active (both are irrelevant with plugin integration).
- **Enforcement verified** — Confirmed `before_tool_call` is properly awaited and blocking in OpenClaw 2026.3.28+. Deny decisions are enforced end-to-end, not just logged.

### v0.9.12

- **Plugin bundled in binary** — The OpenClaw plugin is now embedded directly in the `rampart` binary. `rampart setup openclaw` works on any machine — no external checkout or npm install required. [Learn more →](integrations/openclaw.md)
- **Bridge hardened** — Errors during approval escalations now fail closed (deny) instead of silently allowing.
- **Learn endpoint secured** — `POST /v1/rules/learn` now rate-limited and restricted to `allow` decisions only.

### v0.9.11

- **`openclaw.yaml` security hardening** — Closed `bash *`/`sh *`/`curl *`/`wget *` exec bypass holes. Dedicated `block-force-push` policy. Tightened docker/kubectl/git subcommand allowlists.
- **`default_action: ask` in openclaw.yaml** — Novel or unlisted tool calls surface for human approval instead of silently failing.
- **`sessions_spawn` depth guard** — Subagents cannot spawn further agents.

### v0.9.10

- **Native OpenClaw plugin** — `rampart setup openclaw` auto-detects your OpenClaw version and installs a native `before_tool_call` hook. Intercepts every tool call (exec, read, write, web_fetch, browser, message) without fragile dist patching; degraded behavior still depends on tool class and configuration. Requires OpenClaw >= 2026.3.28. [Learn more →](integrations/openclaw.md)
- **Always Allow writeback** — Click "Always Allow" in the OpenClaw approval UI and Rampart writes a permanent smart-glob rule to `~/.rampart/policies/user-overrides.yaml`.
- **Approval store persistence** — Pending approvals survive `rampart serve` restarts via JSONL journal.
- **`rampart doctor` plugin check** — Shows `✓ OpenClaw plugin: installed` when the native hook is active.
