---
title: Quick Start
description: "Get Rampart protecting your AI coding agent in minutes. Install, connect Claude Code or Cline, and start blocking dangerous commands with policy checks."
---

# Quick Start

!!! tip "First time?"
    Check out the [5-minute tutorial](tutorial.md) — it walks you through install, your first blocked command, and approval flow hands-on.

Get Rampart protecting your AI agent in one command.

!!! tip "Zero risk to try"
    Rampart **fails open** — if the service is unreachable or the policy engine crashes, your tools keep working. You'll never get locked out of your own machine.

## Install

=== "Go install (recommended)"

    ```bash
    go install github.com/peg/rampart/cmd/rampart@latest
    ```

=== "Script"

    ```bash
    curl -fsSL https://rampart.sh/install.sh | sh
    ```

=== "Homebrew"

    ```bash
    brew tap peg/rampart && brew install rampart
    ```

## One-Command Setup

```bash
rampart quickstart
```

This detects your agent (Claude Code, Codex, Cline), installs the service, wires up hooks, and verifies everything is working. Done.

Then use your agent normally. Rampart is invisible until something needs to be blocked or approved.

## Other Agents

=== "Claude Code"

    ```bash
    rampart setup claude-code
    ```

=== "Cline"

    ```bash
    rampart setup cline
    ```

=== "Codex / Any CLI Agent"

    ```bash
    # LD_PRELOAD shim — works with any dynamically-linked process
    rampart preload -- codex
    rampart preload -- node agent.js
    ```

=== "MCP Servers"

    ```bash
    # Proxy an MCP server with policy enforcement
    rampart mcp -- npx @modelcontextprotocol/server-filesystem .
    ```

## Verify It's Working

```bash
rampart doctor
```

Green across the board means you're fully protected. If something's off, doctor tells you exactly what to fix.

## Test the Policy Engine

Test decisions without running an agent:

```bash
rampart test "rm -rf /"
# → deny (block-destructive)

rampart test "git push origin main"
# → allow (or require_approval if you've configured it)
```

Or pipe a raw hook payload:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | rampart hook
```

```json
{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"Rampart: Destructive command blocked"}}
```

## Approve Risky Commands

When a command hits a `require_approval` rule, Rampart pauses the agent and waits. Approve or deny it from the dashboard:

```bash
open http://localhost:9090/dashboard/
```

The dashboard shows pending approvals, audit history, and your loaded policy. For agent team runs (multiple sub-agents in one session), approvals are grouped — one click to approve the whole run.

## Built-in Profiles

Rampart ships with three starting policies:

| Profile | Default Action | What it does |
|---------|---------------|--------------|
| `standard` | allow | Block dangerous commands, watch suspicious ones, allow the rest |
| `paranoid` | deny | Explicit allowlist — everything blocked unless permitted |
| `yolo` | allow | Watch everything, block nothing — observation only |

```bash
rampart init --profile standard
```

## Customize Your Rules

When Rampart blocks something it shouldn't, unblock it in one command — no YAML editing required.

### Allow a blocked command

```bash
rampart allow "npm install *"
```

Adds an allow rule for `npm install <anything>` to your custom policy and hot-reloads the daemon immediately.

For file-based overrides, use `--tool`:

```bash
rampart allow "/tmp/**" --tool read
rampart allow "/tmp/**" --tool write
```

### Block an additional command

```bash
rampart block "curl * | bash"
rampart block "npm publish *"
```

### See your custom rules

```bash
rampart rules
```

```
  Custom Rules
  ──────────────────────────────────────────────────────────────

  Global  (~/.rampart/policies/custom.yaml)

  #     ACTION   TOOL      PATTERN                ADDED
     1  allow    exec      npm install *          just now
     2  deny     exec      curl * | bash          2 hours ago
```

### Remove a rule

```bash
rampart rules remove 2    # removes curl * | bash
```

### Reset all custom rules

```bash
rampart rules reset
```

!!! info "Denial hints"
    When Rampart blocks a command, the error message shows the exact `rampart allow` command to run. Copy-paste to unblock.

!!! warning "Self-modification protection"
    `rampart allow`, `rampart block`, and `rampart rules` are blocked when run **by an AI agent**. Run them yourself in a terminal. This prevents agents from bypassing their own constraints.

For a full guide on scoping rules per-project and advanced options, see [Customizing Policy →](../guides/customizing-policy.md).

## What's Next?

- [5-Minute Tutorial →](tutorial.md) — Hands-on walkthrough with real examples
- [Configuration →](configuration.md) — Write custom policies
- [Customizing Policy →](../guides/customizing-policy.md) — Full guide to allow/block/rules
- [Integration Guides →](../integrations/index.md) — Cline, Cursor, Codex, MCP
- [Policy Engine →](../features/policy-engine.md) — Conditions, rule priority, glob patterns
