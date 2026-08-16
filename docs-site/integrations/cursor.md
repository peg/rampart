---
title: Cursor
description: "Protect local Cursor Agent tool calls with Rampart's native pre-tool hook, with MCP proxying as an optional second boundary."
---

# Cursor

Rampart can protect local Cursor Agent and Cmd+K tool calls through Cursor's
native `preToolUse` hook. Shell, file, MCP, and delegated-agent calls are mapped
into the same Rampart policy engine used by other integrations.

```bash
rampart protect cursor
```

This installs Rampart's managed Guard policy, starts or verifies the local
service, writes one user-level entry to `~/.cursor/hooks.json`, and runs safe
configuration and adapter checks. Existing Cursor hooks are preserved.

## What the hook does

```text
Cursor local Agent tool call
  → preToolUse
  → Rampart policy and audit
  → deny, or return control to Cursor's own permission system
```

The managed entry sets `failClosed: true`, so a hook crash, timeout, or invalid
response blocks the matched action. When Rampart allows a call, it emits an
empty response rather than overriding Cursor's own permissions or sandbox.

Cursor currently accepts `ask` in the hook schema but does not enforce it for
`preToolUse`. Rampart therefore resolves approval-required calls through the
local `rampart serve` approval queue and denies if that exact call cannot be
resolved safely.

Verify without invoking a model:

```bash
rampart verify cursor
```

This proves the installed user configuration and directly exercises Rampart's
Cursor adapter with a destructive canary. It does not claim that an
authenticated Cursor process loaded or invoked the hook.

## Coverage boundaries

The user-level hook covers local Agent Chat and Cmd+K operations that emit
`preToolUse`. It does not cover everything Cursor can do:

- Cursor Tab uses separate `beforeTabFileRead` and `afterTabFileEdit` hooks.
- Cloud Agents do not load `~/.cursor/hooks.json`; they use project, team, or
  enterprise-managed hooks.
- Early read-only Cloud Agent turns currently run without hooks.
- Cloud Agents do not currently expose the specialized MCP hook events,
  although Cursor documents generic `preToolUse` after hooks begin loading.
- Higher-priority enterprise, team, and project hook responses remain part of
  Cursor's host-controlled merge boundary.

## Team and enterprise deployment

Rampart does not build or operate fleet-management infrastructure. Its hook is
deterministic and non-interactive so an organization can deploy the same
command through its existing controls. Cursor documents these system paths:

- macOS: `/Library/Application Support/Cursor/hooks.json`
- Linux/WSL: `/etc/cursor/hooks.json`
- Windows: `C:\ProgramData\Cursor\hooks.json`

Cursor also offers team hook distribution on Enterprise plans. Treat those as
separate deployment scopes: Rampart's current setup command modifies only the
local user's file and never writes a system, project, or cloud-managed hook.

## Optional MCP proxy

For an MCP server, Rampart can additionally sit between Cursor and that server:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "rampart",
      "args": ["mcp", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "."]
    }
  }
}
```

The native hook and MCP proxy are complementary. The hook governs Cursor's
host-visible tool call; the proxy governs the JSON-RPC exchange with that one
MCP server. Neither is an OS sandbox or a claim to intercept arbitrary syscalls
made inside an allowed process.

Remove only Rampart's user hook with:

```bash
rampart setup cursor --remove
```

The host behavior and deployment paths above follow Cursor's current
[hooks reference](https://cursor.com/docs/hooks). Rampart keeps the integration
adapter-tested until an exact current Cursor host invocation is reproduced.
