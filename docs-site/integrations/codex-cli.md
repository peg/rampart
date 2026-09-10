---
title: Securing Codex
description: Protect Codex CLI, IDE, and desktop local tool calls with native lifecycle hooks.
---

# Codex

Rampart uses [Codex lifecycle hooks](https://developers.openai.com/codex/hooks)
to evaluate local tool calls before they run. Codex CLI, the IDE extension, and
the desktop app can share this user-level setup when their local runtimes
support lifecycle hooks and use the same `CODEX_HOME`.

## Setup

```bash
rampart setup codex
```

Rampart adds wildcard `PreToolUse` and `PostToolUse` entries to
`$CODEX_HOME/hooks.json`, or `~/.codex/hooks.json` when `CODEX_HOME` is unset.
Existing unrelated hooks are preserved. If an older Rampart release installed
`~/.local/bin/codex`, setup removes that managed preload wrapper to avoid
evaluating shell commands twice.

Codex treats user hooks as executable configuration. Open `/hooks` in Codex,
review the exact Rampart command, and trust it. A changed hook definition must
be reviewed again.

## Coverage

Codex reports supported local tool calls through the same lifecycle protocol:

- shell and unified execution calls;
- reads, writes, edits, and `apply_patch`;
- MCP tool calls;
- web/browser-style local tools;
- delegated-agent calls when the host emits the lifecycle event.

Rampart evaluates every target in a multi-file `apply_patch`; the most
restrictive decision wins. Unfamiliar future tool names fail closed in enforce
mode until Rampart classifies them. Hosted tools and specialized paths that do
not emit lifecycle hooks remain outside this boundary.

### Execution context visibility

In Codex 0.153.2, the
[unified execution handler](https://github.com/openai/codex/blob/rust-v0.153.2/codex-rs/core/src/tools/handlers/unified_exec/exec_command.rs)
reports `exec_command` as `Bash` with only `command` in `tool_input`. It omits
the requested `workdir` and `shell`. The
[hook's `cwd`](https://developers.openai.com/codex/hooks#common-input-fields)
describes the session working directory, which can differ from the requested
execution directory.
Rampart policy and approval review are limited to the fields Codex supplies;
they cannot confirm the omitted execution directory or shell.

## Decisions and approvals

Allowed calls continue through Codex's own sandbox and permission checks.
Denied calls receive Codex's structured `PreToolUse` denial. Ordinary local
allow/deny evaluation does not require `rampart serve`.

Codex does not currently accept an `ask` decision from `PreToolUse`. Approval
policies use Rampart's blocking external approval queue:

```bash
rampart serve
rampart watch
```

If the approval service is unavailable, the call is denied.

## Verify

```bash
rampart verify codex
```

This checks the installed hook definition and exercises the live Rampart
adapter with safe, non-executing canaries. It proves installed configuration
and adapter behavior without launching a model. See
[Security Assurance](../getting-started/security-assurance.md) for the precise
claim boundary.

## Uninstall

```bash
rampart setup codex --remove
```

Only Rampart's lifecycle hooks and a recognized legacy Rampart wrapper are
removed. Other hooks remain untouched.

## Platforms

Native lifecycle-hook setup supports Linux, macOS, and Windows. Rampart writes
both POSIX and Windows hook command forms. Codex controls hook timeout behavior,
so Rampart does not claim a host timeout fails closed.
