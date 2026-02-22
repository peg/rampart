---
title: Architecture
description: "Understand Rampart's architecture: hooks and proxies feed a local policy engine that evaluates AI agent tool calls, then writes tamper-evident audit logs."
---

# Architecture

## Overview

Rampart is a policy enforcement layer between AI agents and their tools. Every tool call passes through Rampart, which evaluates it against YAML policies and returns allow, deny, or log.

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

## Design Decisions

**Fail-open by default.** If Rampart crashes, tool calls pass through. Fail-closed locks you out of your machine. Configurable for strict environments.

**Custom YAML over OPA/Rego.** The domain is narrow — "should this tool call run?" Custom engine evaluates in <10μs vs OPA's 0.1-1ms.

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

### Interceptors (`internal/intercept/`)

Per-tool normalization before the engine sees the call:

| Interceptor | What It Does |
|------------|-------------|
| **exec** | Command pattern matching, binary extraction |
| **read/write** | Path normalization, glob matching |
| **fetch** | URL parsing, domain extraction |

### Audit Sink (`internal/audit/`)

Append-only JSONL with SHA-256 hash chaining.

- ULID event IDs (time-ordered)
- External anchor every 100 events
- `fsync` on every write
- Log rotation with chain continuity

### Proxy Server (`internal/proxy/`)

HTTP server for tool evaluation. Bearer token auth, localhost-only.

| Endpoint | Purpose |
|----------|---------|
| `POST /v1/tool/{name}` | Evaluate and execute |
| `POST /v1/preflight/{name}` | Dry-run check |
| `GET /v1/policy/summary` | Auth required. Returns JSON with `default_action`, per-rule summaries, and a plain-English overall summary |
| `GET /v1/approvals` | Pending approvals |
| `POST /v1/approvals/{id}/resolve` | Approve/deny |
| `GET /healthz` | Health check |

### Approval Store (`internal/approval/`)

Thread-safe store for `require_approval` decisions. ULID-keyed, configurable timeouts.

### Wrap Command

Starts embedded proxy → generates shell shim → sets `$SHELL` → execs child. Transparent to the agent.

### Preload Library (`preload/`)

~500 lines of C. Intercepts `execve`, `execvp`, `system()`, `popen()`, `posix_spawn()`. HTTP client via libcurl. Fail-open on server unreachable.

## Project Layout

```
cmd/rampart/         CLI (cobra)
internal/
  engine/            Policy evaluation (the core)
  audit/             Hash-chained JSONL audit trail
  intercept/         Tool-specific interceptors
  proxy/             HTTP proxy server
  approval/          Human approval flow
  daemon/            OpenClaw WebSocket integration
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
| **Native hooks** | Agent's hook system calls `rampart hook` | Claude Code, Cline |
| **Wrap** | `$SHELL` shim intercepts commands | Aider, OpenCode |
| **MCP Proxy** | Transparent MCP protocol proxy | Claude Desktop, Cursor |
| **LD_PRELOAD** | Syscall interception | Codex CLI, any process |
| **HTTP API** | Direct REST calls | Python agents, custom |
| **Go SDK** | Embed engine in Go code | Go agents |
