---
title: MCP Proxy
description: "Secure MCP tools with Rampart's transparent proxy. Enforce policy on every tools/call request so AI agents can use MCP servers without unchecked access."
---

# MCP Proxy

## What is MCP?

[Model Context Protocol (MCP)](https://modelcontextprotocol.io) is an open standard that lets AI agents talk to external tools — file systems, databases, APIs, cloud providers — through a unified interface. Instead of each agent having bespoke integrations, MCP servers expose "tools" that any MCP-compatible client can call.

**The problem:** MCP servers often have broad access (your entire filesystem, your GitHub repos, your Slack workspace). When an AI agent calls an MCP tool, there's no built-in way to say "read files, but don't delete them" or "access the GitHub API, but never delete repos."

**Rampart's MCP proxy** sits between the MCP client (your AI agent) and the MCP server, evaluating every `tools/call` against your policies. The client and server don't know it's there.

## Usage

```bash
# Wrap any MCP server
rampart mcp -- npx @modelcontextprotocol/server-filesystem /path

# Monitor mode (log only)
rampart mcp --mode monitor -- npx @modelcontextprotocol/server-fs .
```

## MCP Client Configuration

In your agent's MCP config (Claude Desktop, Cursor, etc.):

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

```d2
direction: right

client: "MCP Client
(Claude Desktop, Cursor…)" {shape: oval}
rampart: "rampart mcp" {style.border-radius: 8}
engine: "Policy Engine" {
  style.fill: "#1d3320"; style.stroke: "#2ea043"; style.font-color: "#3fb950"; style.border-radius: 8
}
server: "MCP Server" {shape: oval}

error: "Error Response" {
  style.fill: "#2d1b1b"; style.stroke: "#da3633"; style.font-color: "#f85149"; style.border-radius: 6
}
pending: "Pending Approval" {
  style.fill: "#2d2508"; style.stroke: "#d29922"; style.font-color: "#d29922"; style.border-radius: 6
}

client -> rampart: "tools/call"
rampart -> engine: "evaluate"
engine -> server: "allow"
engine -> error: "deny"
engine -> pending: "require_approval"
pending -> server: "approved"
pending -> error: "denied / timeout"
server -> rampart: "response"
rampart -> client: "response"
```

Rampart speaks the MCP protocol natively. The client and server don't know it's there. Denied tool calls return a standard JSON-RPC error — the MCP server never sees them.

## Auto-Generate Policies

Scan an MCP server's tool list and generate a deny-by-default policy:

```bash
rampart mcp scan -- npx @modelcontextprotocol/server-filesystem .
```

This creates a policy with an explicit rule for each tool. Review, customize, and deploy.

## MCP Tool Auto-Categorization

Rampart automatically categorizes MCP tools based on keywords in their names:

| Category | Keywords | Default Action |
|----------|----------|---------------|
| `mcp-destructive` | delete, destroy, remove, drop | `deny` |
| `mcp-dangerous` | stop, restart, execute, modify | `log` |

## MCP Proxy vs Shell Hook

| | Shell Hook (`setup claude-code`) | MCP Proxy (`mcp --`) |
|---|---|---|
| **What it intercepts** | Shell commands, file reads/writes | MCP `tools/call` JSON-RPC messages |
| **Best for** | Agents with hook support (Claude Code, Cline) | Claude Desktop, Cursor, any MCP client |
| **Setup** | One-time `rampart setup` | Wrap each MCP server command |
| **Granularity** | Command-level (`rm -rf *`) | Tool-level (`delete_file`, `create_issue`) |
| **Works with** | Agents that support hooks or `$SHELL` | Any agent that uses MCP servers |

**Use both together** for defense in depth — hooks catch shell commands, MCP proxy catches tool calls.

## Common MCP Servers It Works With

Rampart's MCP proxy works with **any** MCP server that uses stdio transport. Some popular ones:

| Server | Package | What It Does |
|--------|---------|-------------|
| Filesystem | `@modelcontextprotocol/server-filesystem` | Read, write, delete files |
| GitHub | `@modelcontextprotocol/server-github` | Issues, PRs, repos |
| Slack | `@modelcontextprotocol/server-slack` | Messages, channels |
| PostgreSQL | `@modelcontextprotocol/server-postgres` | SQL queries |
| Brave Search | `@modelcontextprotocol/server-brave-search` | Web searches |
| Puppeteer | `@modelcontextprotocol/server-puppeteer` | Browser automation |

Just prefix the server command with `rampart mcp --`:

```bash
rampart mcp -- npx -y @modelcontextprotocol/server-github
rampart mcp -- npx -y @modelcontextprotocol/server-slack
rampart mcp -- npx -y @modelcontextprotocol/server-postgres postgres://localhost/mydb
```

## 5-Minute Setup

### 1. Install Rampart

```bash
brew tap peg/rampart && brew install rampart
```

### 2. Create a Policy

Create `~/.config/rampart/policies/mcp.yaml` (or copy from the [example template](https://github.com/peg/rampart/blob/main/configs/examples/mcp-server.yaml)):

```yaml
version: "1"
default_action: allow

policies:
  - name: block-destructive
    match:
      tool: ["mcp-destructive"]
    rules:
      - action: deny
        message: "Destructive MCP tool blocked"
```

### 3. Update Your MCP Config

In your agent's MCP config (Claude Desktop, Cursor, etc.), wrap each server:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "rampart",
      "args": ["mcp", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/you/projects"]
    }
  }
}
```

That's it. Restart your agent and every MCP tool call now goes through Rampart.

## Example Policy for MCP Tools

Rampart auto-categorizes MCP tools by name, so many tools are protected out of the box. For fine-grained control:

```yaml
version: "1"
default_action: allow

policies:
  - name: block-destructive-tools
    match:
      tool: ["mcp-destructive"]
    rules:
      - action: deny
        message: "Destructive MCP tool blocked"

  - name: approve-dangerous-tools
    match:
      tool: ["mcp-dangerous"]
    rules:
      - action: require_approval
        message: "Risky MCP operation — approve?"

  - name: block-file-deletion
    match:
      tool: ["write"]
    rules:
      - action: deny
        when:
          command_matches: ["delete_file*"]
        message: "File deletion blocked"

  - name: log-all-mcp
    match:
      tool: ["mcp"]
    rules:
      - action: log
        message: "MCP tool call logged"
```

See [`configs/examples/mcp-server.yaml`](https://github.com/peg/rampart/blob/main/configs/examples/mcp-server.yaml) for a ready-to-use template.

## Example: Proxmox MCP Policy

```yaml
version: "1"
default_action: allow

policies:
  - name: block-vm-destruction
    match:
      tool: ["mcp__proxmox__vm_delete", "mcp__proxmox__snapshot_delete"]
    rules:
      - action: deny
        message: "VM/snapshot deletion blocked by policy"

  - name: log-vm-power
    match:
      tool: ["mcp__proxmox__vm_stop", "mcp__proxmox__vm_shutdown"]
    rules:
      - action: log
        message: "VM power operation logged"

  - name: block-disk-resize
    match:
      tool: ["mcp__proxmox__vm_resize_disk"]
    rules:
      - action: deny
        message: "Disk resize blocked — irreversible operation"
```
