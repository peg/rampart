---
title: Securing Cline
description: "Add Rampart native hooks to Cline. Evaluate supported shell, file, and web hook payloads before execution and audit observed decisions."
---

# Cline

[Cline](https://github.com/cline/cline) is an AI coding assistant for VS Code.
Rampart integrates with Cline's documented hook payloads for shell, file, web,
and MCP actions. This adapter is regression-tested in isolation; there is no
rolling latest-Cline host job, so consult the support matrix for the current
evidence level.

The installed hook scripts currently require Bash, so Rampart claims this path
on Linux and macOS. A native Windows Cline boundary has not yet been proven.

## Setup

```bash
rampart setup cline
```

This installs scripts for Cline's documented pre- and post-tool hook events.

## What Gets Intercepted

| Tool Call | Example | Intercepted? |
|-----------|---------|:---:|
| Shell commands | `npm install`, `rm -rf` | ✅ |
| File reads | Reading `.env`, `id_rsa` | ✅ |
| File writes | Writing to `/etc/`, config files | ✅ |
| File edits | Modifying source code | ✅ |

## How It Works

When Cline wants to execute a tool:

1. Cline's hook system sends the tool call to `rampart hook --format cline` via stdin (JSON)
2. Rampart evaluates the call against your YAML policies
3. If **allowed**: Rampart returns `{"cancel":false}`, Cline proceeds
4. If **denied**: Rampart returns `{"cancel":true,"errorMessage":"Blocked by Rampart: reason"}`, Cline never executes the command
5. If **ask**: Rampart returns `{"cancel":true}` immediately (no waiting), blocking execution

**Ask behavior:** Unlike integrations with native approval UI, Cline gets an immediate `cancel:true` response for `ask` policies. This prevents Cline from hanging while waiting for approval.

After setup, you continue using Cline normally and can confirm observed calls
with `rampart watch`.

## Monitor in Real Time

Open a separate terminal to watch decisions as they happen:

```bash
rampart watch
```

## Start in Monitor Mode

Not sure about your policies yet? Set your policy's `default_action: allow` and
use `action: watch` rules instead of `deny`. Calls Cline emits to the installed
hooks are logged without being blocked. Check `rampart watch`, then switch rules
to `deny` when you're confident.

## Troubleshooting

**Hooks not intercepting anything?**

Check that Cline's settings have the Rampart hook entries. In VS Code, open Cline settings and look for hook configuration pointing to `rampart hook`.

**Getting false positives?**

Adjust your policies in `~/.rampart/policies/` or use `rampart watch` to see which rules are firing, then tune the patterns.

## Uninstall

```bash
rampart setup cline --remove
```

This removes the Rampart hook scripts. Your policies and audit logs in `~/.rampart/` are preserved.
