---
title: Cursor (MCP Only)
description: "Secure Cursor MCP integrations with Rampart's proxy layer. Note: This only protects MCP servers, not Cursor's native built-in tools."
---

# Cursor (Limited Protection)

!!! warning "Important Limitation"
    **Cursor's native built-in tools (file read/write, terminal, code editing) do not go through MCP and cannot be protected by Rampart.** This guide only covers MCP server protection, which is a small fraction of Cursor's tool usage.
    
    Claude Code exposes a broader native hook surface, but it is also a host
    tool boundary rather than complete process isolation. See the
    [Claude Code guide](claude-code.md).

Cursor uses MCP servers for *some* tool access. Rampart can sit between Cursor and MCP servers as a transparent proxy.

## Setup

In your Cursor MCP configuration, prefix each server command with `rampart mcp --`:

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

## How It Works

```
Cursor → MCP tool call → rampart mcp (proxy) → Policy Engine → MCP Server
                                               → Audit Trail
```

Rampart speaks the MCP protocol natively. It intercepts every `tools/call` request, evaluates it against your policies, and either forwards it to the real MCP server or returns a JSON-RPC error.

**Ask behavior**: The standalone stdio proxy has no safely reachable approval
resolver. A policy action of `ask` therefore fails closed immediately and
returns a JSON-RPC error to Cursor. Use explicit `allow` or `deny` rules until a
service-backed exact-call approval owner is configured.

Denied tool calls never reach the MCP server. Cursor handles the error gracefully.

## Choose a Static Policy

Create the bundled MCP starter policy from the directory where Cursor's proxy
command will load `rampart.yaml`:

```bash
rampart init --profile mcp-server
```

Review and customize the resulting static policy. It is not tailored to the
server's advertised tools.

## Monitor Mode

Start in audit-only mode to see what tools are being called before writing policies:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "rampart",
      "args": ["mcp", "--mode", "monitor", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "."]
    }
  }
}
```

## Monitor

```bash
rampart watch
```
