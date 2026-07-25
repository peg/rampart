---
title: Securing Codex
description: "Secure Codex CLI, IDE, and desktop local tool calls with Rampart lifecycle hooks."
---

# Codex

Rampart's primary Codex integration is the host's native lifecycle-hook
boundary. It does not replace the `codex` executable and does not require the
preload library.

## Setup

```bash
rampart setup codex
```

This installs Rampart wildcard `PreToolUse` and `PostToolUse` handlers in the
user-level Codex `hooks.json`. Existing unrelated hooks are preserved. Review
and trust the definition in Codex with `/hooks` before first use.

The same user-level hook configuration applies to Codex CLI, the IDE extension,
and the desktop app when they use that `CODEX_HOME`.

## What Rampart evaluates

- shell and unified execution;
- direct reads, writes, edits, and multi-file patches;
- MCP calls exposed to lifecycle hooks;
- local web/browser-style actions;
- delegated-agent calls exposed by the host.

Unknown future `PreToolUse` tool names deny in enforce mode until Rampart knows
how to classify them. A hosted or specialized action that does not emit the
lifecycle event cannot be protected by this boundary.

Allowed calls retain Codex's native sandbox and permission policy. Denied calls
stop before execution. Approval-required calls use Rampart's external approval
queue and require `rampart serve`; if it is unavailable, Rampart denies.

## Verification

```bash
rampart verify codex
```

For an opt-in real-host compatibility check against a candidate build:

```bash
scripts/compat-codex-host.sh --yes --rampart-bin ./rampart
```

The host test uses harmless canaries and a disposable Codex home containing
only a temporary copy of `auth.json`. It does not load user configuration,
memories, rules, or persistent sessions.

`rampart verify codex` proves installed configuration and adapter behavior; it
does not itself launch a real Codex model/tool loop. The opt-in harness is the
separate host-boundary check. See
[Security Assurance](../getting-started/security-assurance.md) for the evidence
levels and current platform gaps.

## Uninstall

```bash
rampart setup codex --remove
```

Rampart removes only its hook entries and any recognized legacy Rampart
wrapper.

## Platform support

The lifecycle-hook integration supports Linux, macOS, and Windows. POSIX
preload remains optional defense in depth for other processes; it is not the
Codex integration and is unavailable on Windows.
