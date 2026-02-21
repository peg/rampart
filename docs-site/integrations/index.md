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
| **Shim + Service** | Shell shim + background daemon | OpenClaw |
| **WebSocket Daemon** | WebSocket integration for real-time agents | OpenClaw (alternative) |

## require_approval Behavior

When a policy action is `require_approval`, behavior varies by integration:

| Integration | Behavior |
|-------------|----------|
| **Claude Code** | Hook returns `"permissionDecision":"ask"` — Claude Code shows native prompt |
| **Cline** | Hook returns `{"cancel":true}` with approval message (no native ask) |
| **MCP (Claude Desktop/Cursor)** | Proxy blocks, returns JSON-RPC error on deny |
| **OpenClaw** | Shim blocks, daemon sends webhook notifications |
| **Shell Wrapper** | Shim blocks, command appears "hung" until resolved |
| **LD_PRELOAD** | Library blocks exec call, process appears "hung" |
| **HTTP API** | Returns `"decision":"require_approval"` with `approval_id` |

## Agent Compatibility

| Agent | Method | Command | Platforms |
|-------|--------|---------|-----------|
| [Claude Code](claude-code.md) | Native hooks | `rampart setup claude-code` | All |
| [Cline](cline.md) | Native hooks | `rampart setup cline` | All |
| [Cursor](cursor.md) | MCP proxy | `rampart mcp --` | All |
| [Claude Desktop](claude-desktop.md) | MCP proxy | `rampart mcp --` | All |
| [Codex CLI](codex-cli.md) | LD_PRELOAD | `rampart preload --` | Linux, macOS |
| [OpenClaw](openclaw.md) | Shim + service | `rampart setup openclaw` | Linux, macOS |
| [Python Agents](python-agents.md) | HTTP API | `rampart serve` | All |
| [Any CLI Agent](any-cli-agent.md) | Shell wrapper | `rampart wrap --` | Linux, macOS |

## Choosing an Integration

```d2
direction: right

start: "Your agent" {shape: oval}

q: "Integration method?" {shape: diamond}

hooks: "rampart setup claude-code
rampart setup cline" {
  style.fill: "#1d3320"; style.stroke: "#2ea043"; style.font-color: "#3fb950"; style.border-radius: 6
}
shim: "rampart setup openclaw
--patch-tools for full coverage" {
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
api: "HTTP API / SDK
localhost:9090" {
  style.fill: "#1d3320"; style.stroke: "#2ea043"; style.font-color: "#3fb950"; style.border-radius: 6
}

start -> q

q -> hooks: "Claude Code or Cline
(native hooks, lowest overhead)"
q -> shim: "OpenClaw
(shell shim + file patching)"
q -> mcp: "Cursor, Claude Desktop
or any MCP-compatible client"
q -> wrap: "Any CLI agent
with \$SHELL support"
q -> preload: "Any CLI agent
without \$SHELL (e.g. Codex)"
q -> api: "Custom / Python agent
or CI pipeline"
```

!!! tip "Start with the simplest method"
    Native hooks > wrap > MCP proxy > preload > HTTP API. Use the first one that works for your agent.
