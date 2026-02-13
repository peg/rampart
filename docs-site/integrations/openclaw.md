# OpenClaw

For [OpenClaw](https://github.com/openclaw/openclaw) users, Rampart provides a shell shim, background service, and optional file tool patching.

## Setup

```bash
# Shell command protection only
rampart setup openclaw

# Full protection (shell commands + file reads/writes/edits)
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
| Grep/search | ❌ Not checked | ✅ Protected |

We recommend `--patch-tools` for full coverage, especially if your policies include file access rules (e.g., blocking reads of `.env`, SSH keys, credentials).

## How It Works

```
OpenClaw
  └─ exec tool  → Shell Shim → rampart serve → Policy Engine → Audit
  └─ file tools → Patched JS → rampart serve → Policy Engine → Audit
```

**Shell shim**: A small bash script that intercepts every command OpenClaw runs, sends it to the Rampart policy server, and blocks if denied. Fail-open — if Rampart is unreachable, commands pass through.

**File tool patches**: Injects a policy check into OpenClaw's internal read/write/edit/grep tool implementations. Same fail-open behavior.

!!! warning "File patches require re-running after OpenClaw upgrades"
    `--patch-tools` modifies files in `node_modules`. After upgrading OpenClaw, run `rampart setup openclaw --patch-tools --force` to re-apply.

## Compatibility

Supports OpenClaw `2026.1.30`+ with pi-coding-agent `0.50.7`+.

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
