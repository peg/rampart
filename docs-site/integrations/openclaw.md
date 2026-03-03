---
title: Securing OpenClaw
description: "Protect OpenClaw agents and their sub-agents (Codex, Claude Code) with Rampart. Shell shim, LD_PRELOAD, and file tool patching for full coverage."
---

# OpenClaw

For [OpenClaw](https://github.com/openclaw/openclaw) users, Rampart provides multiple layers of protection: a shell shim for OpenClaw's exec tool, LD_PRELOAD interception for sub-agents, and optional file tool patching.

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

# Manual: full protection (shell commands + file tools)
rampart setup openclaw --patch-tools
```

Or use the interactive wizard:

```bash
rampart setup
```

## Protecting Sub-Agents

OpenClaw can spawn sub-agents like Codex CLI and Claude Code. These agents execute commands through their own shell processes, **not** through OpenClaw's exec tool — so the shell shim alone doesn't catch them.

Use `rampart setup codex` to install a wrapper that intercepts all Codex commands via LD_PRELOAD:

```bash
rampart setup codex
```

This creates a wrapper at `~/.local/bin/codex` that transparently routes every command through Rampart's policy engine. The wrapper inherits to all child processes — no configuration needed per sub-agent.

For Claude Code, use `rampart setup claude-code` which installs native hooks.

For any other CLI agent, use `rampart preload`:

```bash
rampart preload -- <agent-command>
```

## Coverage Matrix

| What | Protected by | Notes |
|------|-------------|-------|
| OpenClaw shell commands (`exec` tool) | ✅ Shell shim | Via `$SHELL` env var |
| File reads/writes/edits/grep | ✅ `--patch-tools` | Re-run after OpenClaw upgrades |
| Codex CLI commands | ✅ `rampart setup codex` | LD_PRELOAD — all child processes |
| Claude Code commands | ✅ `rampart setup claude-code` | Native hooks |
| Other sub-agent commands | ✅ `rampart preload --` | LD_PRELOAD — universal |
| HTTP fetch (`web_fetch` tool) | ⚠️ Not intercepted | Uses Node.js HTTP internals, not exec. Use `fetch` tool policies or OS-level firewall rules |
| Browser automation | ⚠️ Not intercepted | Runs in a separate browser process |

## How It Works

```
OpenClaw Gateway
  ├─ exec tool → Shell Shim → rampart serve → Policy Engine → allow/deny
  ├─ file tools → Patched JS → rampart serve → Policy Engine → allow/deny
  ├─ Codex CLI → librampart.so (LD_PRELOAD) → Policy Engine → allow/deny
  └─ Claude Code → Native hooks → Policy Engine → allow/deny
```

**Shell shim**: A bash script at `~/.local/bin/rampart-shim` that intercepts every `bash -c "command"` call, sends it to Rampart's policy server, and blocks if denied. Configured via `env.vars.SHELL` in OpenClaw's config.

**LD_PRELOAD**: `librampart.so` hooks `execve`, `execvp`, `system()`, `popen()`, and `posix_spawn()` at the C library level. Inherited by all child processes automatically. Cannot be bypassed by choosing a different shell.

**File tool patches**: Injects a policy check into OpenClaw's internal read/write/edit/grep tool implementations. Same fail-open behavior.

**Fail-open**: All interception layers fail open — if Rampart is unreachable, commands pass through. This is deliberate ([design philosophy](../reference/threat-model.md)).

**require_approval**: When a policy uses `action: require_approval`, the shim blocks execution and creates a pending approval. If webhooks are configured, Rampart sends notifications (Discord, Slack, etc.) to alert humans. The command stays blocked until resolved via `rampart approve <id>`, `rampart deny <id>`, or the HTTP API.

!!! warning "File patches require re-running after OpenClaw upgrades"
    `--patch-tools` modifies files in `node_modules`. After upgrading OpenClaw (`npm install -g openclaw`), run:
    ```bash
    rampart setup openclaw --patch-tools --force
    ```

## Configuration

After running `rampart setup openclaw`, add the shim to your OpenClaw config:

```json
{
  "env": {
    "vars": {
      "SHELL": "/home/you/.local/bin/rampart-shim"
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
rampart setup openclaw --remove   # Remove shim, service, restore patched tools
rampart setup codex --remove      # Remove Codex wrapper
```

Policies and audit logs in `~/.rampart/` are preserved.

## Compatibility

Requires OpenClaw 2026.2.x or later. The `--patch-tools` option targets specific internal file paths and is tested against each OpenClaw release — if an upgrade changes the target code, the patch script will exit with an error and file tools will revert to unprotected (fail-open).
