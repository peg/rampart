---
title: Securing Any CLI Agent
description: "Secure any CLI AI agent that respects SHELL by wrapping it with Rampart. Apply policy checks to commands, block dangerous actions, and keep audit logs."
---

# Any CLI Agent

`rampart wrap` works with **any agent** that reads the `$SHELL` environment variable. This covers most CLI-based AI agents.

## Setup

```bash
rampart wrap -- <your-agent-command>
```

### Examples

```bash
rampart wrap -- aider
rampart wrap -- opencode
rampart wrap -- python my_agent.py
rampart wrap -- node agent.js
```

## How It Works

1. Rampart starts an embedded policy server
2. Generates a shell shim that checks every command against the policy
3. Sets `$SHELL` to point at the shim
4. Execs your agent as a child process

Every time the agent spawns a shell command, the shim intercepts it, checks the preflight API, and either allows or blocks execution.

```
Agent → spawns shell → $SHELL (rampart shim) → Policy Engine → Allow/Deny/Require Approval
```

**require_approval behavior**: The shell shim blocks execution and waits for human resolution via `rampart approve <id>` or the API. The agent sees the command as "hung" until resolved.

## Monitor Mode

Log everything, block nothing — useful for understanding what your agent does before writing policies:

```bash
rampart wrap --mode monitor -- your-agent
```

Review the log, then write policies:

```bash
rampart audit stats
rampart report
```

## Custom Policy

```bash
rampart wrap --config /path/to/policy.yaml -- your-agent
```

## Platform Support

`rampart wrap` requires Linux or macOS. For Windows, use the [HTTP API](python-agents.md) or [MCP proxy](../features/mcp-proxy.md).

## When Wrap Doesn't Work

If your agent doesn't respect `$SHELL`, use [LD_PRELOAD](codex-cli.md) instead:

```bash
rampart preload -- your-agent
```

This intercepts exec syscalls directly — works with any dynamically-linked process regardless of `$SHELL` support.
