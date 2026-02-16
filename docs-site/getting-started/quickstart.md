# Quick Start

!!! tip "New to Rampart?"
    Start with the [5-minute tutorial](tutorial.md) for a hands-on walkthrough from install to first blocked command.

Get Rampart protecting your AI agent in under a minute.

![Rampart Architecture](../assets/architecture.png)

!!! tip "Zero risk to try"
    Rampart **fails open** — if the policy engine crashes or is unreachable, your tools keep working normally. You'll never get locked out of your own machine. Use `default_action: allow` with `action: log` rules to observe without blocking anything.

## Claude Code (Recommended)

If you're using Claude Code, this is a one-liner:

```bash
rampart setup claude-code
```

This installs native hooks into Claude Code's hook system. Every Bash command, file read, and file write gets evaluated against Rampart's policy engine before execution.

Then just use Claude Code normally:

```bash
claude
```

Rampart is completely transparent — safe commands pass through in microseconds, dangerous commands get blocked before they execute.

### See It Working

Open a second terminal and watch decisions in real time:

```bash
rampart watch
```

```
╔══════════════════════════════════════════════════════════════╗
║  RAMPART — enforce — 4 policies                             ║
╠══════════════════════════════════════════════════════════════╣
║  ✅ 21:03:42 exec  "git push origin main"     [allow-git]   ║
║  ✅ 21:03:41 read  ~/project/src/main.go      [default]     ║
║  🔴 21:03:38 exec  "rm -rf /tmp/*"            [protect-sys] ║
║  👤 21:03:36 exec  "kubectl apply -f ..."     [approve-k8s] ║
║  ✅ 21:03:35 exec  "npm test"                 [allow-dev]   ║
║  🟡 21:03:33 exec  "curl https://api.io"      [log-http]    ║
╠══════════════════════════════════════════════════════════════╣
║  1,247 total │ 1,201 allow │ 12 deny │ 34 log │ 3 approval  ║
╚══════════════════════════════════════════════════════════════╝
```

## Other Agents

=== "Any CLI Agent"

    ```bash
    # Wrap any agent that reads $SHELL
    rampart wrap -- aider
    rampart wrap -- opencode
    rampart wrap -- python my_agent.py
    ```

=== "MCP Servers"

    ```bash
    # Proxy MCP with policy enforcement
    rampart mcp -- npx @modelcontextprotocol/server-fs .
    ```

=== "LD_PRELOAD"

    ```bash
    # Universal — works with any dynamically-linked process
    rampart preload -- codex
    rampart preload -- node agent.js
    ```

## Built-in Profiles

Rampart ships with three profiles to get you started:

| Profile | Default Action | Description |
|---------|---------------|-------------|
| `standard` | allow | Block dangerous commands, log suspicious ones, allow the rest |
| `paranoid` | deny | Explicit allowlist — everything is blocked unless you say otherwise |
| `yolo` | allow | Log everything, block nothing — for auditing only |

```bash
# Initialize with a specific profile
rampart init --profile standard
```

## Test the Policy Engine

You can test decisions without running an agent:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | rampart hook
```

```json
{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"Rampart: Destructive command blocked"}}
```

## What's Next?

- [Configuration →](configuration.md) — Write custom policies
- [Integration Guides →](../integrations/index.md) — Set up your specific agent
- [Policy Engine →](../features/policy-engine.md) — Deep dive into matching rules
