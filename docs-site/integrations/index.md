---
title: Integration Guides
description: "Find the right Rampart integration for Claude Code, Cline, Cursor, OpenClaw, Codex, and custom agents. Compare hooks, MCP proxy, wrapping, and preload."
---

# Integration Guides

Rampart works with every major AI agent through multiple integration methods. Choose the guide for your agent below.

## Integration Methods

| Method | How It Works | Best For |
|--------|-------------|----------|
| **Native Hooks** | Uses the agent's built-in hook system | Claude Code, Cline |
| **Shell Wrapper** | Sets `$SHELL` to a policy-checking shim | Aider, OpenCode, Continue |
| **MCP Proxy** | Transparent proxy for MCP tool calls | Claude Desktop, Cursor |
| **LD_PRELOAD** | Intercepts exec syscalls at the OS level | Codex CLI, any process |
| **HTTP API** | RESTful endpoint for custom integrations | Python agents, custom code |
| **Native Plugin** | Agent framework calls Rampart before each tool runs | OpenClaw |
| **Shim + Service** | Legacy shell shim + dist patching compatibility path | Older OpenClaw |
| **WebSocket Daemon** | WebSocket integration for real-time agents | OpenClaw (legacy / alternative) |

## Ask Behavior

When a policy action is `ask`, behavior varies by integration:

| Integration | Behavior |
|-------------|----------|
| **Claude Code** | Hook returns `"permissionDecision":"ask"` — Claude Code shows native prompt |
| **Cline** | Hook returns `{"cancel":true}` with approval message (no native ask) |
| **MCP (Claude Desktop/Cursor)** | Proxy blocks, returns JSON-RPC error on deny |
| **OpenClaw** | OpenClaw owns the visible approval UI; Rampart plugin supplies policy decisions |
| **Shell Wrapper** | Shim blocks, command appears "hung" until resolved |
| **LD_PRELOAD** | Library blocks exec call, process appears "hung" |
| **HTTP API** | Returns `"decision":"ask"` with approval metadata when interactive review is required |

## Agent Compatibility

| Agent | Method | Command | Platforms |
|-------|--------|---------|-----------|
| [Claude Code](claude-code.md) | Native hooks | `rampart setup claude-code` | All |
| [Cline](cline.md) | Native hooks | `rampart setup cline` | All |
| [Cursor](cursor.md) | MCP proxy | `rampart mcp --` | All |
| [Claude Desktop](claude-desktop.md) | MCP proxy | `rampart mcp --` | All |
| [Codex CLI](codex-cli.md) | Wrapper + preload | `rampart setup codex` | Linux, macOS* |
| [OpenClaw](openclaw.md) | Native plugin | `rampart setup openclaw` | Linux, macOS |
| [Python Agents](python-agents.md) | HTTP API | `rampart serve` | All |
| [Any CLI Agent](any-cli-agent.md) | Shell wrapper | `rampart wrap --` | Linux, macOS |

\* macOS preload coverage is best for Homebrew/user-installed binaries; SIP-protected system binaries cannot be interposed.

## Choosing an Integration

```d2
direction: right

start: "Your agent" {shape: oval}

q: "Integration method?" {shape: diamond}

hooks: "rampart setup claude-code\\nrampart setup cline" {
  style.fill: "#1d3320"; style.stroke: "#2ea043"; style.font-color: "#3fb950"; style.border-radius: 6
}
shim: "rampart setup openclaw\\nnative plugin on current builds" {
  style.fill: "#1d3320"; style.stroke: "#2ea043"; style.font-color: "#3fb950"; style.border-radius: 6
}
mcp: "rampart mcp --" {
  style.fill: "#1d3320"; style.stroke: "#2ea043"; style.font-color: "#3fb950"; style.border-radius: 6
}
wrap: "rampart wrap --" {
  style.fill: "#1d3320"; style.stroke: "#2ea043"; style.font-color: "#3fb950"; style.border-radius: 6
}
preload: "rampart preload --" {
  style.fill: "#1d3320"; style.stroke: "#2ea043"; style.font-color: "#3fb950"; style.border-radius: 6
}
api: "HTTP API / SDK\\nlocalhost:9090" {
  style.fill: "#1d3320"; style.stroke: "#2ea043"; style.font-color: "#3fb950"; style.border-radius: 6
}

start -> q

q -> hooks: "Claude Code or Cline\\n(native hooks, lowest overhead)"
q -> shim: "OpenClaw\\n(native plugin on supported builds)"
q -> mcp: "Cursor, Claude Desktop\\nor any MCP-compatible client"
q -> wrap: "Any CLI agent\\nwith \$SHELL support"
q -> preload: "Any CLI agent\\nwithout \$SHELL or native hooks"
q -> api: "Custom / Python agent\\nor CI pipeline"
```

!!! tip "Start with the simplest method"
    Preferred order is: native hooks/plugin > wrap > MCP proxy > preload > HTTP API. Use the first one your agent supports cleanly.
