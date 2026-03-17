---
title: Securing OpenClaw
description: "Native Rampart integration for OpenClaw — policy enforcement, exec approval routing, and file tool protection in one command."
---

# OpenClaw

Rampart integrates natively with OpenClaw 2026.3.x. One command sets up full protection and connects Rampart's policy engine to OpenClaw's exec approval system.

!!! info "Version requirement"
    Requires OpenClaw 2026.3.x or later for native exec approval integration. Earlier versions work with shell shim only.

!!! tip "Fastest path"
    If you want your OpenClaw agent to install and configure Rampart for you, just say:
    > "Install Rampart and protect this machine."

    The agent will run `rampart quickstart --yes` which handles everything automatically.
    See the [agent install guide](../guides/agent-install.md) for full details.

## Setup

```bash
rampart quickstart
```

That's it. Rampart:

1. Installs `rampart serve` as a boot service
2. Configures the OpenClaw shell shim (exec protection)
3. Patches OpenClaw file tools (read/write/edit/grep protection)
4. Patches `web_fetch` (network exfiltration protection)
5. Auto-selects the `openclaw.yaml` policy profile
6. Connects to the OpenClaw gateway for native exec approval routing

## How it works after setup

When `rampart serve` starts, it automatically connects to the OpenClaw gateway WebSocket and subscribes to exec approval events. This is the native integration — Rampart becomes the policy engine inside OpenClaw's approval flow.

```
Agent wants to run a command
  └─ OpenClaw fires exec.approval.requested
       └─ Rampart evaluates policy
            ├─ Hard deny (rm -rf /, cat ~/.ssh/id_rsa, etc.)
            │    → resolved immediately, command never runs
            │    → user sees nothing (no prompt needed)
            │
            ├─ Safe command (npm test, git status, etc.)
            │    → resolved allow-once immediately
            │    → command runs, no prompt
            │
            └─ Needs human review (kubectl apply, sudo, etc.)
                 → Rampart creates approval, notifies via your
                   configured channel (Discord, Telegram, etc.)
                 → command waits until you approve or deny
```

You can verify the bridge is connected:

```bash
rampart status
# Shows: OpenClaw bridge: connected (ws://127.0.0.1:18789)
```

Or check the serve log:

```bash
rampart log
# bridge: connected to OpenClaw gateway, listening for approval requests
```

## Protecting Sub-Agents

OpenClaw can spawn sub-agents like Codex CLI and Claude Code. These agents execute commands through their own shell processes, not through OpenClaw's exec tool. The bridge doesn't cover sub-agents — they need their own interception.

```bash
rampart setup codex       # Wraps Codex CLI with LD_PRELOAD
rampart setup claude-code # Adds hooks to ~/.claude/settings.json
```

`rampart quickstart` handles this automatically if Codex or Claude Code are detected.

## Coverage Matrix

| What | Protected by | Notes |
|------|-------------|-------|
| OpenClaw exec commands | ✅ Native bridge | Policy engine inside approval flow |
| File reads/writes/edits | ✅ File tool patches | Re-run after OpenClaw upgrades |
| `web_fetch` requests | ✅ Dist patch | Exfiltration via URL blocked |
| Codex CLI commands | ✅ `rampart setup codex` | LD_PRELOAD — all child processes |
| Claude Code commands | ✅ `rampart setup claude-code` | Native hooks |
| Other sub-agent commands | ✅ `rampart preload --` | LD_PRELOAD — universal |
| Browser automation | ⚠️ Not intercepted | Separate browser process |
| `message` tool | ⚠️ Not intercepted | Issue [#221](https://github.com/peg/rampart/issues/221) |

## Rampart deny overrides OpenClaw approval

!!! important "Approving in OpenClaw does not override a Rampart deny"
    With the native bridge, Rampart evaluates the command **before** OpenClaw shows it to you. Hard deny rules (`action: deny`) are resolved immediately and the command never runs — you won't see an approval prompt at all.

    For commands that should be human-approvable, use `action: ask` in your policy. That creates an approval gate where Rampart notifies you and waits for your decision before resolving OpenClaw's approval.

## The `openclaw.yaml` profile

`rampart quickstart` auto-selects the `openclaw.yaml` policy profile when OpenClaw is detected. This profile includes everything in `standard.yaml` plus:

- **Session-aware rules**: main session (direct chat) has different permissions from subagents and cron jobs
- **Deployment gates**: `kubectl apply`, `terraform apply`, `docker push`, `helm install/upgrade` require approval
- **Tighter sub-agent restrictions**: subagents face more restrictions on sensitive file access and external actions

To install it manually:

```bash
rampart init --profile openclaw
```

## Disabling the bridge

To run Rampart without the native bridge (shim-only mode):

```bash
rampart serve --no-openclaw-bridge
```

## Uninstall

```bash
rampart uninstall --yes
```

Removes the service, shell shim, OpenClaw gateway drop-in, and restores patched tool files. Policies and audit logs in `~/.rampart/` are preserved.

!!! warning "File patches require re-running after OpenClaw upgrades"
    `--patch-tools` modifies files in `node_modules`. After upgrading OpenClaw, run:
    ```bash
    rampart setup openclaw --patch-tools --force
    ```
    Or restart the OpenClaw gateway — the `ExecStartPre` drop-in re-patches automatically on gateway restart.
