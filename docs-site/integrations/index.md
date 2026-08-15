---
title: Integration Guides
description: "Find the right Rampart integration for Claude Code, Cline, Cursor, OpenClaw, Hermes Agent, Codex, Antigravity, experimental Gemini CLI, GitHub Copilot, and custom agents."
---

# Integration Guides

Rampart supports several widely used AI agents through multiple integration
methods, with different assurance levels and boundaries. Choose the guide for
your agent below, then check the [support matrix](../getting-started/support-matrix.md)
for the evidence and known limitations of that path.

After setup, `rampart verify --all` safely checks the policy engine and every
configured integration with an active behavioral verifier without invoking a
model. Static-only integrations such as Hermes remain visible in
`rampart doctor` and require their isolated compatibility harness for runtime
evidence.

## Integration Methods

| Method | How It Works | Best For |
|--------|-------------|----------|
| **Native Hooks** | Uses the agent's built-in hook system | Claude Code, Cline, Codex, Cursor, GitHub Copilot; Gemini CLI (experimental enterprise/API-key path) |
| **Shell Wrapper** | Sets `$SHELL` to a policy-checking shim | Aider, OpenCode, Continue |
| **MCP Proxy** | Transparent proxy for individual MCP servers | Claude Desktop, Cursor (optional second boundary) |
| **LD_PRELOAD** | Interposes supported libc exec/spawn functions; native library is source-built | Optional defense in depth for compatible Unix processes |
| **HTTP API** | RESTful endpoint for custom integrations | Python agents, custom code |
| **Native Plugin** | Agent framework calls Rampart before each tool runs | OpenClaw, Antigravity, Hermes Agent (experimental) |
| **Shim + Service** | Legacy shell shim + dist patching compatibility path | Older OpenClaw |

## Ask Behavior

When a policy action is `ask`, behavior varies by integration:

| Integration | Behavior |
|-------------|----------|
| **Claude Code** | Hook returns `"permissionDecision":"ask"` — Claude Code shows native prompt |
| **Codex** | Rampart's external approval queue blocks; unavailable queue denies |
| **Gemini CLI (experimental)** | External Rampart queue blocks; unavailable queue denies |
| **Antigravity CLI / IDE** | Native `force_ask` prompt, ignoring cached Always Allow permissions |
| **GitHub Copilot CLI / VS Code** | Native Copilot approval prompt |
| **Cursor** | External Rampart approval queue; Cursor's generic pre-tool `ask` is not enforced |
| **Cline** | Hook returns `{"cancel":true}` with approval message (no native ask) |
| **Standalone MCP proxy** | Proxy blocks, returns JSON-RPC error on deny |
| **OpenClaw** | OpenClaw owns the visible approval UI; Rampart plugin supplies policy decisions |
| **Hermes Agent** | Compatible Hermes installations own the native approval prompt and resume the same call; older or incomplete installs block with upgrade guidance |
| **Shell Wrapper** | Shim blocks, command appears "hung" until resolved |
| **LD_PRELOAD** | Library blocks exec call, process appears "hung" |
| **HTTP API** | Returns `"decision":"ask"` with approval metadata when interactive review is required |

## Agent Compatibility

| Agent | Method | Command | Platforms |
|-------|--------|---------|-----------|
| [Claude Code](claude-code.md) | Native hooks | `rampart setup claude-code` | All |
| [Cline](cline.md) | Native hooks | `rampart setup cline` | Linux, macOS, Windows* |
| [Cursor](cursor.md) | Native local Agent hook; optional MCP proxy | `rampart setup cursor` | All |
| [Claude Desktop](claude-desktop.md) | MCP proxy | `rampart mcp --` | All |
| [Codex CLI, IDE, desktop](codex-cli.md) | Native hooks | `rampart setup codex` | All |
| [Gemini CLI](gemini-cli.md) | Experimental enterprise/API-key native hooks | `rampart setup gemini` | Linux, macOS |
| [Antigravity CLI / IDE](antigravity.md) | Shared plugin with installed-plugin and adapter checks | `rampart setup antigravity` | All |
| [GitHub Copilot CLI / VS Code](github-copilot.md) | CLI adapter-tested; shared VS Code Preview contract | `rampart setup copilot` | All |
| [OpenClaw](openclaw.md) | Managed native guard | `rampart protect openclaw` | Linux, macOS |
| [Hermes Agent](hermes.md) | Experimental user plugin | `rampart setup hermes` | Linux, macOS |
| [Python Agents](python-agents.md) | HTTP API | `rampart serve` | All |
| [Any CLI Agent](any-cli-agent.md) | Shell wrapper | `rampart wrap --` | Linux, macOS |

\* Cline's Windows `.ps1` contract is source-reviewed and cross-build tested;
physical Windows host E2E remains pending. See the Cline guide for activation
and legacy `--yolo` limitations.

## Choosing an Integration

```d2
direction: right

start: "Your agent" {shape: oval}

q: "Integration method?" {shape: diamond}

hooks: "rampart protect\\n(native hook auto-detection)" {
  style.fill: "#1d3320"; style.stroke: "#2ea043"; style.font-color: "#3fb950"; style.border-radius: 6
}
shim: "rampart protect openclaw\\nrampart setup hermes (experimental)" {
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

q -> hooks: "Claude Code, Cline, Codex, or Copilot\\n(native hooks, lowest overhead)"
q -> shim: "OpenClaw, Antigravity, or Hermes\\n(native plugin where supported)"
q -> mcp: "Cursor, Claude Desktop\\nor any MCP-compatible client"
q -> wrap: "Any CLI agent\\nwith \$SHELL support"
q -> preload: "Any CLI agent\\nwithout \$SHELL or native hooks"
q -> api: "Custom / Python agent\\nor CI pipeline"
```

!!! tip "Start with the simplest method"
    Preferred order is: native hooks/plugin > wrap > MCP proxy > preload > HTTP API. Use the first one your agent supports cleanly.
