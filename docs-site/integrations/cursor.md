# Cursor

Cursor uses MCP servers for tool access. Rampart sits between Cursor and the MCP server as a transparent proxy.

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

**require_approval behavior**: When a policy action is `require_approval`, the MCP proxy blocks and waits for human resolution via `rampart approve <id>` or the API. If denied or expired, it returns a JSON-RPC error to Cursor.

Denied tool calls never reach the MCP server. Cursor handles the error gracefully.

## Auto-Generate Policies

Don't write policies from scratch — scan an MCP server's tool list:

```bash
rampart mcp scan -- npx @modelcontextprotocol/server-filesystem .
```

This generates a deny-by-default policy with an explicit rule for each tool. Review, customize, and deploy.

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
