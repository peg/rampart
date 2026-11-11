---
title: Documentation
description: "Rampart is an open-source security policy engine for hook-visible AI agent actions. Block matched dangerous commands, detect known prompt-injection patterns, and audit policy decisions."
hide:
  - navigation
  - toc
---

<p class="docs-eyebrow">Rampart documentation</p>

<div class="hero-title" markdown>

<span id="rampart"></span>

# Put your policy into practice

</div>

<p class="hero-subtitle">Install Rampart, connect a supported agent, and check the boundary before you rely on it.</p>

## Start here

<div class="grid cards" markdown>

-   :material-download:{ .lg .middle } **New to Rampart**

    Install the CLI, choose a supported integration, and run the first checks.

    [Installation](getting-started/installation.md) · [Quick start](getting-started/quickstart.md)

-   :material-arrow-up-circle:{ .lg .middle } **Upgrade an installation**

    Update the binary and owned hooks, then verify the resulting setup.

    [Upgrade guide](getting-started/upgrade.md) · [Release notes](https://github.com/peg/rampart/releases/latest)

-   :material-file-document-edit:{ .lg .middle } **Write and test policy**

    Express the actions you allow, deny, or send for human approval.

    [Customize policy](guides/customizing-policy.md) · [Test policies](guides/testing-policies.md)

-   :material-stethoscope:{ .lg .middle } **Check a problem**

    Follow a failed check, unexpected denial, or integration limitation.

    [Troubleshooting](getting-started/troubleshooting.md) · [Support matrix](getting-started/support-matrix.md)

</div>

## Quick Start

```bash
brew install peg/tap/rampart
rampart protect
rampart verify --all
```

`rampart protect` detects and configures supported installed agents.
`rampart verify --all` re-checks policy and configured integrations with an
active verifier. A setup check alone is not proof that a host ingests its
hooks. Review your agent's [support status and limits](getting-started/support-matrix.md).

For Linux, Windows, and other install methods, use the
[installation guide](getting-started/installation.md).

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

-   :material-connection:{ .lg .middle } **Integration Boundaries**

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
Yes — a webpage or MCP tool response can contain instructions that try to override an agent's behavior. Rampart's `watch-prompt-injection` policy checks tool responses for high-confidence patterns and blocks matching responses where the host's post-tool hook can block them. [Learn more →](guides/prompt-injection.md)

**Does Rampart send my commands to any external server?**  
Core Rampart policy evaluation, audit logging, and the dashboard are local.
Optional semantic verification and notification/webhook features send the
configured request data to their configured providers. The agent itself may
also use remote model and tool services independently of Rampart.
Optional [external witnessing](features/external-witness.md) publishes compact
audit checkpoints without commands, prompts or tool-request content.

**Will Rampart slow down my agent?**  
Core matching is local and benchmarked in microseconds. Hook startup and audit
I/O add environment-dependent overhead; optional semantic verification adds a
network model call.

**What if I need to allow a command that's blocked?**  
If an `ask` rule keeps prompting, run `rampart allow "your command pattern"` — no YAML editing required, and the rule applies from the next call. A command blocked by a deny rule stays blocked: `allow` does not override deny rules. [Full guide →](guides/customizing-policy.md)

## How It Works

1. A configured integration exposes an agent's tool request to Rampart.
2. YAML policy returns **allow/watch**, **deny**, or **ask**. Allow and watch
   let the host continue; deny blocks the represented action; ask requires
   human approval through the integration's supported path.
3. The local audit trail records the request and policy decision.

<div class="architecture-figure" markdown>

```d2 alt="An exposed agent action reaches a configured integration and YAML policy engine. Policy can directly allow or watch, deny, or ask for human approval. Decisions are recorded in a local audit trail."
--8<-- "docs/architecture.d2"
```

</div>

`action: ask` routes directly from policy to human approval; it does not
require a semantic verifier. The integration determines whether approval is
shown by the host or handled through Rampart. See the
[native ask guide](guides/native-ask.md) and your
[integration guide](integrations/index.md) for the actual boundary.

Only an explicitly matched `webhook` rule invokes an optional external
[decision service](features/semantic-verification.md). The diagram describes
policy decisions, not proof of execution or independent audit witnessing.

[Architecture](reference/architecture.md) · [Threat model](reference/threat-model.md) · [Policy schema](reference/policy-schema.md)

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
| **Cursor** | Native local Agent hook; optional MCP proxy | `rampart setup cursor` |
| **Claude Desktop** | MCP proxy | `rampart mcp --` |
| **Any CLI agent** | Shell wrapper | `rampart wrap --` |
| **Custom agents** | HTTP API | `localhost:9090` |

[:octicons-arrow-right-24: See all integration guides](integrations/index.md)

## Current release

Rampart v1.10.0 stops answering `allow` for Claude Code: when policy allows an
action, Rampart returns no decision, so Claude Code's own permission mode and
prompts apply again. Deny and ask rules work as before. New Claude Code
installations on 2.1.295 or later fail closed when the hook cannot run;
existing installations keep their current behavior until you opt in.
`rampart doctor` now warns, rather than fails, when another detected agent has
no Rampart hooks, and `rampart protect` ends with a harmless test to try. The
alpha Python SDK and `rampart quickstart` are removed. Existing installations
need no action. Read the [upgrade guidance](getting-started/upgrade.md) before
upgrading a custom background service, and see the [release
notes](https://github.com/peg/rampart/releases/latest) or the repository
[changelog](https://github.com/peg/rampart/blob/main/CHANGELOG.md) for history.
