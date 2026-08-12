---
title: Rampart
description: "Rampart is an open-source security policy engine for hook-visible AI agent actions. Block matched dangerous commands, detect known prompt-injection patterns, and audit policy decisions."
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

Rampart is a **policy engine** for actions exposed by a supported agent
integration. Hook-visible commands, file operations, fetches, and related tool
calls are evaluated against YAML policies before the host executes them.
Observed decisions are logged to a hash-chained audit trail. Rampart is not a
network firewall or sandbox and does not see arbitrary behavior inside an
allowed process.

On supported post-tool boundaries, Rampart can scan tool **responses** and
replace matching string content before the next model turn. This is
pattern-based mitigation, not a guarantee that secrets never enter agent
context. [Learn more →](reference/owasp-mapping.md#response-scanning-asi06)

<div class="grid cards" markdown>

-   :material-shield-check:{ .lg .middle } **Policy Engine**

    ---

    YAML-based policies with glob matching. Deny, allow, log, or require human approval. Local matching is benchmarked in microseconds.

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

    Native hooks and plugins for named supported agents, plus shell wrapping,
    MCP proxy, process interposition, and an HTTP API for other integrations.

    [:octicons-arrow-right-24: Integration guides](integrations/index.md)

-   :material-shield-alert:{ .lg .middle } **Response Scanning**

    ---

    On supported post-tool hooks, replace response strings that match configured credential patterns before the next model turn.

    [:octicons-arrow-right-24: How it works](reference/owasp-mapping.md#response-scanning-asi06)

-   :material-certificate:{ .lg .middle } **OWASP Agentic Top 10**

    ---

    Mapped against the 2026 OWASP framework for autonomous AI agents. Nine risks are partially mitigated and one is not addressed; none are claimed as fully covered.

    [:octicons-arrow-right-24: Full mapping](reference/owasp-mapping.md)

</div>

## Quick Start

```bash
# Install
brew install peg/tap/rampart

# Detect, configure, and verify supported installed agents
rampart protect

# Re-check policy and every configured active-verifier integration
rampart verify --all
```

That's it. Rampart selects the strongest supported native boundary for each
detected agent. [Full setup guide →](getting-started/quickstart.md) · [Support matrix →](getting-started/support-matrix.md)

## Frequently Asked Questions

**Is Claude Code safe to use in --dangerously-skip-permissions mode?**  
It can be used with an additional policy boundary, but Rampart is not a
sandbox. `--dangerously-skip-permissions` gives Claude Code broad shell access;
Rampart evaluates Bash and PowerShell tool calls that Claude exposes to its
hooks. Commands executed inside an already allowed interpreter are outside
that metadata boundary. [Full guide →](guides/securing-claude-code.md)

**What happens if my AI agent runs a destructive command?**  
With a working native hook, the command is evaluated before execution. If it
matches a deny rule, Rampart returns a structured denial and records the
decision. Evaluation is normally measured in microseconds, but end-to-end hook
latency varies by machine and policy set.

**Can AI agents be manipulated by prompt injection?**  
Yes — a webpage or MCP tool response can contain instructions that try to override an agent's behavior. Rampart's `watch-prompt-injection` policy monitors tool responses for these patterns and logs them for review. [Learn more →](guides/prompt-injection.md)

**Does Rampart send my commands to any external server?**  
Core Rampart policy evaluation, audit logging, and the dashboard are local.
Optional semantic verification and notification/webhook features send the
configured request data to their configured providers. The agent itself may
also use remote model and tool services independently of Rampart.

**Will Rampart slow down my agent?**  
Core matching is local and benchmarked in microseconds. Hook startup and audit
I/O add environment-dependent overhead; optional semantic verification adds a
network model call.

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

engine: "YAML Policy Engine\\nlocal matching" {
  style.fill: "#1d3320"
  style.stroke: "#2ea043"
  style.font-color: "#3fb950"
  style.border-radius: 8
}

verify: "rampart-verify\\n(optional sidecar)" {
  style.stroke-dash: 4
  style.border-radius: 8
}

audit: "Audit Trail\\nhash-chained" {
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
agents.codex -> intercept.hooks
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

## Integration Paths

| Agent | Integration | Setup |
|-------|------------|-------|
| **Claude Code** | Native hooks | `rampart setup claude-code` |
| **Cline** | Native hooks | `rampart setup cline` |
| **OpenClaw** | Zero-config native guard | `rampart protect openclaw` |
| **Codex CLI, IDE, desktop** | Native lifecycle hooks | `rampart setup codex` |
| **GitHub Copilot CLI / VS Code** | Shared native hooks | `rampart setup copilot` |
| **Gemini CLI (enterprise/API key)** | Experimental native hooks | `rampart setup gemini` |
| **Antigravity CLI / IDE** | Shared native policy plugin | `rampart setup antigravity` |
| **Hermes Agent** | Experimental native plugin | `rampart setup hermes` |
| **Cursor** | MCP proxy | `rampart mcp --` |
| **Claude Desktop** | MCP proxy | `rampart mcp --` |
| **Any CLI agent** | Shell wrapper | `rampart wrap --` |
| **Python agents** | HTTP API / SDK | `localhost:9090` |

[:octicons-arrow-right-24: See all integration guides](integrations/index.md)

## Current release

Rampart v1.6.2 hardens audit secrecy, compound-command and self-protection
enforcement, and MCP/HTTP protocol boundaries. It also corrects plugin
freshness and Hermes status reporting while grounding public support claims in
reproducible, credential-free evidence. See the
[release notes](https://github.com/peg/rampart/releases/latest) for the concise
upgrade summary or the repository
[changelog](https://github.com/peg/rampart/blob/main/CHANGELOG.md) for history.
