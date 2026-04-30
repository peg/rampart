---
title: Integration Support Matrix
description: "Supported Rampart integration modes, coverage, approval UX, serve requirements, and legacy compatibility notes."
---

# Integration Support Matrix

Use this page as the canonical support contract for Rampart's main integration surfaces.

| Surface | Integration method | `rampart serve` required? | Approval UX | Coverage summary | Support tier |
|---------|--------------------|---------------------------|-------------|------------------|--------------|
| Claude Code | Native hooks (`rampart setup claude-code`) | No for local hook enforcement; yes for dashboard/headless approval flows | Claude native approval prompt | Direct tool calls protected through `PreToolUse`; local policy evaluation works without serve | **Recommended** |
| Cline | Native hooks (`rampart setup cline`) | No for local hook enforcement | No native ask UI; approval-required actions cancel with context | Native hook coverage for supported tool lifecycle events | **Supported** |
| Codex CLI | Wrapper + preload (`rampart setup codex`) | Typically yes for service-backed evaluation path | Wrapper/preload approval semantics | Strong CLI coverage; depends on preload/wrapper path | **Recommended** |
| OpenClaw >= 2026.4.11 | Native plugin (`rampart setup openclaw`) | Yes | OpenClaw native approval UI | All tool calls are intercepted by the plugin; degraded behavior depends on tool class and `failOpenTools` | **Recommended** |
| OpenClaw 2026.3.28 - 2026.4.10 | Native plugin (`rampart setup openclaw`) | Yes | Native tool enforcement; approval UX is less polished than current builds | All tool calls are intercepted on supported builds; degraded behavior still depends on tool class and config | **Supported** |
| OpenClaw < 2026.3.28 | Legacy shim + bridge + optional patching | Yes | Legacy bridge/shim approval behavior | Compatibility path only; more fragile and upgrade-sensitive | **Legacy compatibility** |
| Cursor / Claude Desktop | MCP proxy (`rampart mcp --`) | Yes | MCP error / proxy-mediated behavior | MCP tool coverage only | **Supported** |
| Custom / Python / CI | HTTP API | Yes | Caller-defined | Whatever the caller routes through Rampart | **Supported** |

## Degraded behavior notes

- **Claude Code / Cline native hooks**: local policy evaluation still works when `rampart serve` is down, but dashboard features, approval APIs, and external approval state do not.
- **OpenClaw native plugin**: depends on `rampart serve`; sensitive tools block when the service is unavailable, while configured lower-risk fail-open tools may still proceed.
- **Legacy OpenClaw patching**: compatibility-only path; requires re-patching after upgrades.
- **Wrapper / preload / API paths**: behavior depends on integration settings and fail-open/fail-closed configuration.

## Choosing the right path

- Use **native hooks** when the agent supports them.
- Use the **OpenClaw native plugin** on current OpenClaw builds.
- Use **wrapper / preload** when the CLI agent has no hook system.
- Use **MCP proxy** or **HTTP API** for clients that integrate through MCP or custom service calls.

## Related guides

- [Quick Start](quickstart.md)
- [How Rampart Works](how-it-works.md)
- [OpenClaw integration](../integrations/openclaw.md)
- [Integration guides](../integrations/index.md)
