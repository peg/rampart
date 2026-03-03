---
title: Securing OpenClaw
description: "Protect OpenClaw agents and their sub-agents (Codex, Claude Code) with Rampart. Full exec coverage via LD_PRELOAD, file tool patching, and audit logging."
---

# OpenClaw

For [OpenClaw](https://github.com/openclaw/openclaw) users, Rampart provides multiple layers of protection: a shell shim for OpenClaw's own exec tool, LD_PRELOAD interception for sub-agents, and optional file tool patching.

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

### Protecting Sub-Agents

OpenClaw can spawn sub-agents like Codex CLI and Claude Code. These run commands through their own shell — **not** through OpenClaw's exec tool — so the shell shim alone won't catch them.

For Codex CLI, install the Rampart wrapper:

```bash
rampart setup codex
```

This creates a wrapper at `~/.local/bin/codex` that uses LD_PRELOAD to intercept every exec syscall from Codex and all its child processes. See the [Codex CLI integration guide](codex-cli.md) for details.

For Claude Code, install native hooks:

```bash
rampart setup claude-code
```

See the [Claude Code integration guide](claude-code.md) for details.

## Coverage

| What | How it's protected | Setup |
|------|--------------------|-------|
| OpenClaw shell commands (`exec` tool) | Shell shim | `rampart setup openclaw` |
| File reads/writes/edits/grep | Tool patching | `rampart setup openclaw --patch-tools` |
| Codex CLI commands | LD_PRELOAD wrapper | `rampart setup codex` |
| Claude Code commands | Native hooks | `rampart setup claude-code` |
| Any other sub-agent | LD_PRELOAD | `rampart preload -- <agent>` |

!!! note "Sub-agent coverage is not automatic"
    `rampart setup openclaw` only protects OpenClaw's own exec tool. Each sub-agent needs its own setup. This is because sub-agents spawn their own shell processes directly, bypassing OpenClaw's tool layer.

## How It Works

```
OpenClaw Gateway
  ├─ exec tool      → Shell Shim → rampart serve → Policy Engine → Audit
  ├─ file tools     → Patched JS → rampart serve → Policy Engine → Audit
  ├─ Codex CLI      → LD_PRELOAD → rampart serve → Policy Engine → Audit
  └─ Claude Code    → Native Hook → Policy Engine → Audit
```

**Shell shim**: A bash script at `~/.local/bin/rampart-shim` that intercepts `$SHELL -c "command"` calls. OpenClaw is configured to use this as its shell. Sends each command to the Rampart policy server before execution. Fail-open — if Rampart is unreachable, commands pass through.

**File tool patches**: Injects a policy check into OpenClaw's internal read/write/edit/grep tool implementations. Same fail-open behavior.

**LD_PRELOAD (sub-agents)**: The `librampart.so` library hooks exec-family syscalls (`execve`, `execvp`, `system`, `popen`, `posix_spawn`) at the C library level. Every child process inherits the preload, so the entire process tree is covered. Cannot be bypassed by changing `$SHELL` or calling `/bin/bash` directly.

**require_approval behavior**: When a policy action is `require_approval`, the shim or preload library blocks execution and polls until the approval is resolved via `rampart approve <id>`, the dashboard, or the API.

!!! warning "File patches require re-running after OpenClaw upgrades"
    `--patch-tools` modifies files in `node_modules`. After upgrading OpenClaw, run `rampart setup openclaw --patch-tools --force` to re-apply.

## Configuration

After running `rampart setup openclaw`, configure OpenClaw to use the shim as its shell. In `~/.openclaw/openclaw.json`:

```json
{
  "env": {
    "vars": {
      "SHELL": "/home/YOUR_USER/.local/bin/rampart-shim"
    }
  }
}
```

Then restart the OpenClaw gateway.

## Monitor

```bash
rampart watch       # Live dashboard
rampart status      # Quick check
rampart log --deny  # Recent denies
```

## Uninstall

```bash
rampart setup openclaw --remove
rampart setup codex --remove          # If installed
```

This stops the background service, removes the shim and wrappers, and restores any patched file tools from backups. Your policies and audit logs in `~/.rampart/` are preserved.
