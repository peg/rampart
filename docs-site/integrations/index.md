---
title: Integration Guides
description: "Find the right Rampart integration for Claude Code, Cline, Cursor, OpenClaw, Hermes Agent, Codex, Gemini CLI, GitHub Copilot, and custom agents."
---

# Integration Guides

Rampart supports several widely used AI agents through multiple integration
methods, with different assurance levels and boundaries. Choose the guide for
your agent below, then check the [support matrix](../getting-started/support-matrix.md)
for the evidence and known limitations of that path.

## Integration Methods

| Method | How It Works | Best For |
|--------|-------------|----------|
| **Native Hooks** | Uses the agent's built-in hook system | Claude Code, Cline, Codex, Gemini CLI, GitHub Copilot |
| **Shell Wrapper** | Sets `$SHELL` to a policy-checking shim | Aider, OpenCode, Continue |
| **MCP Proxy** | Transparent proxy for MCP tool calls | Claude Desktop, Cursor |
| **LD_PRELOAD** | Intercepts exec syscalls at the OS level | Optional Unix defense in depth |
| **HTTP API** | RESTful endpoint for custom integrations | Python agents, custom code |
| **Native Plugin** | Agent framework calls Rampart before each tool runs | OpenClaw, Hermes Agent (experimental) |
| **Shim + Service** | Legacy shell shim + dist patching compatibility path | Older OpenClaw |
| **WebSocket Daemon** | WebSocket integration for real-time agents | OpenClaw (legacy / alternative) |

## Ask Behavior

When a policy action is `ask`, behavior varies by integration:

| Integration | Behavior |
|-------------|----------|
| **Claude Code** | Hook returns `"permissionDecision":"ask"` — Claude Code shows native prompt |
| **Codex** | Rampart's external approval queue blocks; unavailable queue denies |
| **Gemini CLI** | External Rampart queue blocks; unavailable queue denies |
| **GitHub Copilot CLI / VS Code** | Native Copilot approval prompt |
| **Cline** | Hook returns `{"cancel":true}` with approval message (no native ask) |
| **MCP (Claude Desktop/Cursor)** | Proxy blocks, returns JSON-RPC error on deny |
| **OpenClaw** | OpenClaw owns the visible approval UI; Rampart plugin supplies policy decisions |
| **Hermes Agent** | Experimental plugin blocks `ask` with an approval-required message until Hermes owns a plugin approval/resume flow |
| **Shell Wrapper** | Shim blocks, command appears "hung" until resolved |
| **LD_PRELOAD** | Library blocks exec call, process appears "hung" |
| **HTTP API** | Returns `"decision":"ask"` with approval metadata when interactive review is required |

## Agent Compatibility

| Agent | Method | Command | Platforms |
|-------|--------|---------|-----------|
| [Claude Code](claude-code.md) | Native hooks | `rampart setup claude-code` | All |
| [Cline](cline.md) | Native hooks | `rampart setup cline` | Linux, macOS |
| [Cursor](cursor.md) | MCP proxy | `rampart mcp --` | All |
| [Claude Desktop](claude-desktop.md) | MCP proxy | `rampart mcp --` | All |
| [Codex CLI, IDE, desktop](codex-cli.md) | Native hooks | `rampart setup codex` | All |
| [Gemini CLI](gemini-cli.md) | Native hooks | `rampart setup gemini` | Linux, macOS |
| [GitHub Copilot CLI / VS Code](github-copilot.md) | Shared native hooks | `rampart setup copilot` | All |
| [OpenClaw](openclaw.md) | Native plugin | `rampart setup openclaw` | Linux, macOS |
| [Hermes Agent](hermes.md) | Experimental user plugin | `rampart setup hermes` | All |
| [Python Agents](python-agents.md) | HTTP API | `rampart serve` | All |
| [Any CLI Agent](any-cli-agent.md) | Shell wrapper | `rampart wrap --` | Linux, macOS |

## Choosing an Integration

```d2
direction: right

start: "Your agent" {shape: oval}

q: "Integration method?" {shape: diamond}

hooks: "rampart protect\\n(native hook auto-detection)" {
  style.fill: "#1d3320"; style.stroke: "#2ea043"; style.font-color: "#3fb950"; style.border-radius: 6
}
shim: "rampart setup openclaw\\nrampart setup hermes" {
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

q -> hooks: "Claude Code, Cline, Codex, Gemini, or Copilot\\n(native hooks, lowest overhead)"
q -> shim: "OpenClaw or Hermes Agent\\n(native plugin where supported)"
q -> mcp: "Cursor, Claude Desktop\\nor any MCP-compatible client"
q -> wrap: "Any CLI agent\\nwith \$SHELL support"
q -> preload: "Any CLI agent\\nwithout \$SHELL or native hooks"
q -> api: "Custom / Python agent\\nor CI pipeline"
```

!!! tip "Start with the simplest method"
    Preferred order is: native hooks/plugin > wrap > MCP proxy > preload > HTTP API. Use the first one your agent supports cleanly.
