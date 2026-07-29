---
title: Architecture
description: "Understand Rampart's architecture: hooks and proxies feed a local policy engine that evaluates AI agent tool calls, then writes tamper-evident audit logs."
---

# Architecture

## Overview

Rampart is a policy enforcement layer between AI agents and their tools.
Supported integrations send host-exposed tool calls through Rampart, which
evaluates them against YAML policies and returns allow, deny, watch, ask, or webhook. Calls
inside an allowed process or omitted by the host remain outside that boundary.

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

## Design Decisions

**Boundary-specific failure behavior.** Managed native integrations fail closed
when enforcement is unavailable. Optional compatibility boundaries such as the
shell wrapper and preload library expose configurable degraded behavior.

**Custom YAML over OPA/Rego.** The domain is narrow — "should this tool call
run?" The custom engine's hot path is benchmarked in this repository; results
vary by policy set and host.

**Local-first.** No data leaves the machine. No cloud dependency. No telemetry.

**Deny-wins evaluation.** Any policy says deny → denied. No ambiguity.

## Components

### Policy Engine (`internal/engine/`)

The hot path. Loads YAML policies, evaluates tool calls.

**Evaluation order:**

1. Collect matching policies by tool type
2. Within each policy, rules evaluate top-to-bottom (first match wins)
3. Across policies: any deny → denied
4. Nothing matches → default action

Hot-reloads via `fsnotify`.

### Audit Sink (`internal/audit/`)

Append-only JSONL with SHA-256 hash chaining.

- ULID event IDs (time-ordered)
- External anchor every 100 events
- Validated chain checkpoints for bounded native-hook startup
- `fsync` on long-running service writes; native hooks avoid per-call fsync latency
- Log rotation with chain continuity

### Proxy Server (`internal/proxy/`)

HTTP server for tool evaluation. Bearer token auth, localhost-only.

| Endpoint | Purpose |
|----------|---------|
| `POST /v1/tool/{name}` | Evaluate a host-owned tool call |
| `POST /v1/preflight/{name}` | Policy preview, or host-owned execution check with `enforce: true` |
| `GET /v1/policy/summary` | Auth required. Returns JSON with `default_action`, per-rule summaries, and a plain-English overall summary |
| `GET /v1/approvals` | Pending approvals |
| `POST /v1/approvals/{id}/resolve` | Approve/deny |
| `GET /healthz` | Health check |

### Approval Store (`internal/approval/`)

Thread-safe store for `ask` decisions. ULID-keyed, configurable timeouts.

### Wrap Command

Starts embedded proxy → generates shell shim → sets `$SHELL` → execs child. Transparent to the agent.

### Preload Library (`preload/`)

~500 lines of C. Intercepts `execve`, `execvp`, `system()`, `popen()`, `posix_spawn()`. HTTP client via libcurl. Fail-open on server unreachable.

This is an optional source-built component. Current release archives and the
Homebrew formula package the Go CLI only; they do not include a native preload
library.

## Project Layout

```
cmd/rampart/         CLI (cobra)
internal/
  engine/            Policy evaluation (the core)
  audit/             Hash-chained JSONL audit trail
  proxy/             HTTP proxy server
  approval/          Human approval flow
  bridge/            Legacy OpenClaw compatibility bridge
  watch/             Terminal dashboard (bubbletea)
  mcp/               MCP proxy components
  openclaw/          OpenClaw-specific integration
  signing/           HMAC signing for approval URLs
  notify/            Webhook/notification handling
  dashboard/         Web dashboard (static assets)
  report/            HTML report generation
  detect/            Agent detection utilities
  build/             Build-time metadata
pkg/sdk/             Public Go SDK
policies/            Built-in profiles
preload/             C library for LD_PRELOAD
```

## Integration Patterns

| Pattern | How | Best For |
|---------|-----|----------|
| **Native hooks** | Agent's hook system calls `rampart hook` | Claude Code, Cline, Codex, GitHub Copilot CLI / VS Code; Gemini CLI (experimental) |
| **Native plugin** | Agent plugin forwards tool calls to Rampart before execution | OpenClaw |
| **Wrap** | `$SHELL` shim intercepts commands | Aider, OpenCode |
| **MCP Proxy** | Transparent MCP protocol proxy | Claude Desktop, Cursor |
| **LD_PRELOAD** | Optional libc exec/spawn interposition | Compatible dynamically linked Unix processes |
| **HTTP API** | Direct REST calls | Python agents, custom |
| **Go SDK** | Embed engine in Go code | Go agents |
