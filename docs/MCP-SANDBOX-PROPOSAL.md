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

---

# Exfiltration Detection (Roadmap — v0.2.0)

## Problem

An agent can read sensitive files legitimately, then exfiltrate the contents via network tools or MCP tool call arguments. Current credential rules block *reading* secrets but not *sending* them.

## Approach

Add a `detect-exfiltration` rule type that scans tool call arguments for high-entropy strings and known secret patterns:

- **AWS keys**: `AKIA[0-9A-Z]{16}`
- **GitHub tokens**: `ghp_[a-zA-Z0-9]{36}`, `gho_`, `ghs_`
- **Slack tokens/webhooks**: `xoxb-`, `xoxp-`, `hooks.slack.com/services/T`
- **Generic high-entropy**: Base64 blobs > 20 chars in curl/wget/nc arguments
- **Private keys**: `BEGIN.*PRIVATE KEY`

## When to flag

Only when a secret pattern appears in a *network-bound* context:
- `curl`, `wget`, `nc`, `ssh` command arguments
- MCP tool calls to external services
- `exec` commands with pipe chains ending in network tools

This avoids false positives on legitimate file reads or local processing.

## Tuning

- Start as `log` action (visibility, not enforcement)
- Let users promote to `deny` after validating no false positives
- Ship with conservative patterns (known prefixes only, not generic entropy)
