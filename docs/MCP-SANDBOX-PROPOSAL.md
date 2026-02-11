# MCP Sandbox Proposal — Deno-Style Per-Server Permissions

*Status: Future work. Documented 2026-02-11.*

## Problem

Rampart's MCP proxy protects against agent misuse (blocking dangerous tool calls). It does NOT protect against a malicious/compromised MCP server process that tries to steal credentials, open reverse shells, or escalate privileges on the host.

## Proposed Solution

Add `--sandbox` flag to `rampart mcp` that spawns the MCP server in an isolated Linux namespace with restricted capabilities:

```yaml
mcp:
  server: npx @modelcontextprotocol/server-github
  sandbox:
    network: [api.github.com:443]        # only these endpoints reachable
    read: [~/.config/github/credentials]  # only these paths readable
    write: []                             # no filesystem writes
    exec: false                           # no child process spawning
```

## Architecture

```
Agent → Rampart Policy Proxy → MCP Server (sandboxed) → External API
         ↑ blocks bad tool calls    ↑ can't escape its box
         Threat: agent misuse       Threat: malicious server
```

## Implementation Notes

- Linux namespaces (unshare) for filesystem/network/PID isolation
- Seccomp-bpf for syscall restriction (no exec/fork when disabled)
- Network namespaces + iptables for endpoint allowlisting
- macOS: no kernel namespace support — would need lightweight container (Lima/colima)
- Windows: not feasible without WSL

## Threat Coverage

| Threat | Policy Proxy (current) | Sandbox (proposed) |
|--------|----------------------|-------------------|
| Agent misuse via prompt injection | ✅ | ❌ irrelevant |
| Data exfil via tool call args | ✅ partial | ❌ irrelevant |
| Malicious MCP server | ❌ | ✅ |
| Compromised MCP server (supply chain) | ❌ | ✅ |
| MCP server credential theft | ❌ | ✅ (restricted reads) |
| MCP server reverse shell | ❌ | ✅ (no exec + restricted net) |

## Estimated Effort

- 4-6 weeks for Linux namespace implementation
- Additional 1-2 weeks for macOS via Lima/colima
- Requires elevated permissions (CAP_SYS_ADMIN or root for unshare)

## Decision

Deferred. Focus on policy proxy improvements, webhook notifications, and audit reports first. Revisit when there's user demand for supply-chain protection of MCP servers.
