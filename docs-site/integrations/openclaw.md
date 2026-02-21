---
title: Securing OpenClaw
description: "Protect OpenClaw agents with Rampart guardrails for shell commands and file access. Use --patch-tools for full coverage and audit every risky action."
---

# OpenClaw

For [OpenClaw](https://github.com/openclaw/openclaw) users, Rampart provides a shell shim, background service, and optional file tool patching.

!!! tip "Fastest path"
    If you want your OpenClaw agent to install and configure Rampart for you, just say:
    > "Install Rampart and protect this machine."

    The agent will run `rampart quickstart --yes` which handles everything automatically.
    See the [agent install guide](../guides/agent-install.md) for full details.

## Setup

```bash
# Fastest: auto-detect, install service, configure hooks, run health check
rampart quickstart --yes

# Manual: shell command protection only
rampart setup openclaw

# Manual: full protection (shell commands + file reads/writes/edits)
rampart setup openclaw --patch-tools
```

Or use the interactive wizard, which will ask about file tool patching:

```bash
rampart setup
```

## What Gets Protected

| Tool | Without `--patch-tools` | With `--patch-tools` |
|------|------------------------|---------------------|
| Shell commands (`exec`) | ✅ Protected | ✅ Protected |
| File reads | ❌ Not checked | ✅ Protected |
| File writes | ❌ Not checked | ✅ Protected |
| File edits | ❌ Not checked | ✅ Protected |
| Grep | ❌ Not checked | ✅ Protected |

We recommend `--patch-tools` for full coverage, especially if your policies include file access rules (e.g., blocking reads of `.env`, SSH keys, credentials).

## How It Works

```
OpenClaw
  └─ exec tool  → Shell Shim → rampart serve → Policy Engine → Audit
  └─ file tools → Patched JS → rampart serve → Policy Engine → Audit
```

**Shell shim**: A small bash script that intercepts every command OpenClaw runs, sends it to the Rampart policy server, and blocks if denied. Fail-open — if Rampart is unreachable, commands pass through.

**File tool patches**: Injects a policy check into OpenClaw's internal read/write/edit/grep tool implementations. Same fail-open behavior.

**require_approval behavior**: When a policy action is `require_approval`, the daemon creates a pending approval and sends webhook notifications (if configured) to alert humans. The shim blocks execution until the approval is resolved via `rampart approve <id>` or the API.

!!! warning "File patches require re-running after OpenClaw upgrades"
    `--patch-tools` modifies files in `node_modules`. After upgrading OpenClaw, run `rampart setup openclaw --patch-tools --force` to re-apply.

## Compatibility

Supports recent OpenClaw versions with pi-coding-agent.

## Monitor

```bash
rampart watch       # Live dashboard
rampart status      # Quick check
rampart log --deny  # Recent denies
```

## Uninstall

```bash
rampart setup openclaw --remove
```

This stops the background service, removes the shim, and restores any patched file tools from backups. Your policies and audit logs in `~/.rampart/` are preserved.
