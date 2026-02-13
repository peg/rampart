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

## Agent Compatibility

| Agent | Method | Command | Platforms |
|-------|--------|---------|-----------|
| [Claude Code](claude-code.md) | Native hooks | `rampart setup claude-code` | All |
| [Cline](cline.md) | Native hooks | `rampart setup cline` | All |
| [Cursor](cursor.md) | MCP proxy | `rampart mcp --` | All |
| [Claude Desktop](claude-desktop.md) | MCP proxy | `rampart mcp --` | All |
| [Codex CLI](codex-cli.md) | LD_PRELOAD | `rampart preload --` | Linux, macOS |
| [OpenClaw](openclaw.md) | Shim + service | `rampart setup openclaw` | Linux, macOS |
| [Python Agents](python-agents.md) | HTTP API / SDK | `localhost:9090` | All |
| [Any CLI Agent](any-cli-agent.md) | Shell wrapper | `rampart wrap --` | Linux, macOS |

## Choosing an Integration

```mermaid
graph TD
    A[Which agent?] -->|Claude Code| B[rampart setup claude-code]
    A -->|Cline| C[rampart setup cline]
    A -->|Claude Desktop / Cursor| D[rampart mcp --]
    A -->|Has $SHELL support?| E{Yes / No}
    E -->|Yes| F[rampart wrap --]
    E -->|No| G[rampart preload --]
    A -->|Custom / Python| H[HTTP API]
```

!!! tip "Start with the simplest method"
    Native hooks > wrap > MCP proxy > preload > HTTP API. Use the first one that works for your agent.
