---
title: Quick Start
description: "Get Rampart protecting Claude Code, Codex, Cline, or OpenClaw in minutes. Install, pick your integration path, and verify coverage clearly."
---

# Quick Start

!!! tip "First time?"
    Check out the [5-minute tutorial](tutorial.md) — it walks you through install, your first blocked command, and approval flow hands-on.

Get Rampart protecting your AI agent in one command.

Before you dive in, skim the [integration support matrix](support-matrix.md) if you want the exact truth about serve requirements, approval UX, and support tiers for each surface.

!!! tip "Zero risk to try"
    Protection behavior depends on the integration. Claude Code and Cline native hooks can evaluate policy locally without `rampart serve`. `rampart serve` is still useful for dashboard views, audit APIs, and external approval workflows. OpenClaw's native plugin depends on `rampart serve` for policy evaluation.

## Install

=== "Go install (recommended)"

    ```bash
    go install github.com/peg/rampart/cmd/rampart@latest
    ```

=== "Script"

    ```bash
    curl -fsSL https://rampart.sh/install | sh
    ```

=== "Homebrew"

    ```bash
    brew tap peg/rampart && brew install rampart
    ```

## One-Command Setup

```bash
rampart quickstart
```

This detects your agent (Claude Code, Codex, Cline, OpenClaw), installs the service, wires up the right integration path, and verifies everything is working. Done.

Then use your agent normally. Rampart is invisible until something needs to be blocked or approved.

If you want persistent local defaults instead of exporting env vars, add this:

```yaml
# ~/.rampart/config.yaml
url: http://127.0.0.1:9090
```

See [Configuration](configuration.md) for the full `url` / `serve_url` / `api` story.

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

=== "OpenClaw"

    ```bash
    rampart setup openclaw
    ```

    Native plugin path on current OpenClaw builds. `rampart serve` is required for policy evaluation here.

=== "MCP Servers"

    ```bash
    # Proxy an MCP server with policy enforcement
    rampart mcp -- npx @modelcontextprotocol/server-filesystem .
    ```

## Verify It's Working

```bash
rampart doctor
```

Doctor should tell you which integration path is active, whether `serve` is optional or required for that path, and what coverage gaps remain. If something's off, it should tell you exactly what to fix.

## Test the Policy Engine

Test decisions without running an agent:

```bash
rampart test "rm -rf /"
# → deny (block-destructive)

rampart test "git push origin main"
# → allow (or ask if you've configured it)
```

You can also write test suites to verify your policies in CI. See the [Testing Policies](../guides/testing-policies.md) guide.

Or pipe a raw hook payload:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | rampart hook
```

```json
{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"Rampart: Destructive command blocked"}}
```

## Approval UX by Integration

When a command hits an `ask` rule, the approval UX depends on the integration:

- **Claude Code native hooks**: Claude shows its native approval prompt
- **Cline hooks**: command is canceled with an approval-required message (no native ask UI)
- **OpenClaw plugin**: OpenClaw owns the visible approval UI
- **Headless / external approval flows**: use `rampart serve` + dashboard/watch

To use the dashboard-based approval flow, run:

```bash
open http://localhost:9090/dashboard/
```

The dashboard shows pending approvals, audit history, and your loaded policy. For agent team runs (multiple sub-agents in one session), approvals are grouped — one click to approve the whole run.

!!! info "Serve is not universal"
    For direct Claude Code hooks, `rampart serve` is optional for local protection. It becomes important when you want dashboard visibility, approval APIs, headless-only approval flows, or integrations like OpenClaw that delegate policy evaluation through the local service.

## Built-in Profiles

Rampart ships with three starting policies:

| Profile | Default Action | What it does |
|---------|---------------|--------------|
| `standard` | allow | Block dangerous commands, watch suspicious ones, allow the rest |
| `paranoid` | deny | Explicit allowlist — everything blocked unless permitted |
| `yolo` | allow | Watch everything, block nothing — observation only |
| `research-agent` | allow | Tuned for web-heavy research agents; restricts exfiltration, allows broad fetch |
| `mcp-server` | deny | Conservative default for MCP server deployments; explicit allows required |

```bash
rampart init --profile standard
```

!!! tip "See all profiles"
    Run `rampart policy list` to see every available built-in profile and any policy files you've added.

## Customize Your Rules

When Rampart blocks something it shouldn't, unblock it in one command — no YAML editing required.

### Allow a blocked command

```bash
rampart allow "npm install *"
```

Adds an allow rule for `npm install <anything>` to your overrides and hot-reloads the daemon immediately.

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

### See your override rules

```bash
rampart rules
```

```
  Override Rules
  ──────────────────────────────────────────────────────────────

  Global  (~/.rampart/policies/user-overrides.yaml)

  #     ACTION   TOOL      PATTERN                ADDED
     1  allow    exec      npm install *          just now
     2  deny     exec      curl * | bash          2 hours ago
```

### Remove a rule

```bash
rampart rules remove 2    # removes curl * | bash
```

### Reset all override rules

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
