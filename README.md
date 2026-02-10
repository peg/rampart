<div align="center">

# Rampart

**Policy engine for AI agent tool calls.**

Secure your AI agents without changing their code.

[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/peg/rampart/actions/workflows/ci.yml/badge.svg)](https://github.com/peg/rampart/actions/workflows/ci.yml)

</div>

---

Agents call tools — `exec`, `read`, `write`, `fetch`, MCP. Rampart sits between the agent and those calls, evaluates them against your policies, and blocks what shouldn't run. Everything gets logged to a hash-chained audit trail.

```bash
rampart setup claude-code                                # one-command Claude Code integration
rampart wrap -- aider                                    # wrap any agent that reads $SHELL
rampart mcp -- npx @modelcontextprotocol/server-fs .     # protect MCP servers
rampart serve                                            # protect via HTTP API
```

```
rampart: blocked — Destructive command blocked
Rampart: 47 calls evaluated, 1 denied, 3 logged
```

## Contents

- [The Problem](#the-problem)
- [Claude Code Integration](#claude-code-integration)
- [Wrap Any Agent](#wrap-any-agent)
- [Protect MCP Servers](#protect-mcp-servers)
- [Quick Start](#quick-start)
- [Writing Policies](#writing-policies)
- [Approval Flow](#approval-flow)
- [Preflight API](#preflight-api)
- [Audit Trail](#audit-trail)
- [Live Dashboard](#live-dashboard)
- [Integration](#integration)
- [Performance](#performance)
- [Architecture](#architecture)
- [CLI Reference](#cli-reference)
- [Building from Source](#building-from-source)
- [Roadmap](#roadmap)
- [License](#license)

---

## The Problem

AI agents make tool calls you didn't anticipate. They hallucinate commands, follow injected instructions, and improvise in ways you'd rather they didn't. Traditional sandboxing is all-or-nothing: let the agent run, or don't.

That's not useful. You need *"yes to `git push`, no to `rm -rf /`, and log every `curl` for review"* — per tool, per pattern, with an audit trail.

```
Agent → Tool Call → Rampart → Allow / Deny / Log
                            → Audit (always)
```

---

## Claude Code Integration

Native integration through Claude Code's hook system. One command, no wrapper needed:

```bash
rampart setup claude-code
```

That's it. Every Bash command, file read, and file write goes through Rampart's policy engine before execution. Blocked commands never run.

Then just use Claude Code normally:
```bash
claude
```

Rampart evaluates every tool call in microseconds. Safe commands pass through transparently. Dangerous commands get blocked before the agent can execute them.

See what's happening in real time:
```bash
rampart watch
```

## Wrap Any Agent

For agents without a hook system, `wrap` sets `$SHELL` to a policy-checking shim. Works with any agent that reads the `$SHELL` environment variable (Aider, OpenCode, Continue, Cline, and more):

```bash
rampart wrap -- aider
rampart wrap -- opencode
rampart wrap -- python my_agent.py
```

## Protect MCP Servers

Drop-in proxy between your agent and any MCP server. Evaluates every `tools/call` against your policies:

```bash
# Instead of connecting directly to an MCP server:
rampart mcp -- npx @modelcontextprotocol/server-filesystem /path
```

In your MCP config (Claude Code, Cursor, etc.):
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "rampart",
      "args": ["mcp", "--", "npx", "@modelcontextprotocol/server-filesystem", "."]
    }
  }
}
```

Denied tool calls return a JSON-RPC error — the MCP server never sees them. Safe calls pass through transparently. Tools with destructive keywords (delete, destroy, remove) are blocked out of the box.

```bash
# Dry run — log everything, block nothing
rampart wrap --mode monitor -- your-agent

# Custom policy file
rampart wrap --config my-policy.yaml -- your-agent
```

---

## Quick Start

```bash
# Install (Go 1.24+)
go install github.com/peg/rampart/cmd/rampart@latest

# Or build from source
git clone https://github.com/peg/rampart.git && cd rampart
go build -o rampart ./cmd/rampart

# Set up Claude Code integration (one command)
rampart setup claude-code

# Or wrap any agent
rampart wrap -- aider

# Or start the HTTP proxy
rampart serve
```

Test the policy engine directly:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | rampart hook
# → {"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"Rampart: Destructive command blocked"}}
```

Three built-in profiles:

| Profile | Default | Use case |
|---------|---------|----------|
| `standard` | allow | Block dangerous, log suspicious, allow the rest |
| `paranoid` | deny | Explicit allowlist for everything |
| `yolo` | allow | Log-only, no blocking |

---

## Writing Policies

Policies are YAML. Glob matching, hot-reload on file change.

```yaml
version: "1"
default_action: allow

policies:
  - name: block-destructive
    match:
      tool: ["exec"]
    rules:
      - action: deny
        when:
          command_matches: ["rm -rf *", "mkfs.*", "dd if=*", ":(){ :|:& };:"]
        message: "Destructive command blocked"

  - name: block-credential-reads
    priority: 1
    match:
      tool: ["read"]
    rules:
      - action: deny
        when:
          path_matches: ["**/.ssh/id_*", "**/.aws/credentials", "**/.env"]
        message: "Credential access blocked"

  - name: block-exfil
    match:
      tool: ["fetch"]
    rules:
      - action: deny
        when:
          domain_matches: ["*.ngrok-free.app", "*.requestbin.com", "webhook.site"]
        message: "Exfiltration domain blocked"
```

**Evaluation:** Deny always wins. Lower priority number = evaluated first. Four actions: `deny`, `require_approval`, `log`, `allow`.

---

## Approval Flow

For the grey area — commands that need a human to decide:

```yaml
policies:
  - name: production-deploys
    match:
      tool: ["exec"]
    rules:
      - action: require_approval
        when:
          command_matches: ["kubectl apply *", "terraform apply *"]
        message: "Production deployment requires approval"
```

The proxy returns `202 Accepted` and blocks until resolved:

```bash
rampart pending                          # What's waiting
rampart approve abc123                   # Let it through
rampart deny abc123 --reason "not now"   # Block it
```

---

## Preflight API

Check if a call would be allowed without executing it:

```bash
curl -s localhost:9090/v1/preflight/exec \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"agent":"a","session":"s","params":{"command":"rm -rf /"}}'
# → {"allowed":false,"decision":"deny","matched_policies":["block-destructive"]}
```

No side effects. For agents that plan before acting.

---

## Audit Trail

Every tool call is logged to hash-chained JSONL. Each entry includes a SHA-256 hash of the previous entry — tamper with any record and the chain breaks.

```bash
rampart audit tail --follow     # Stream events
rampart audit verify            # Check chain integrity
rampart audit stats             # Decision breakdown
rampart audit search            # Query by tool, agent, decision, time range
```

Why hash-chained: in regulated environments, you need to prove what your agent did. A hash chain means no one can edit history without detection.

---

## Live Dashboard

```bash
rampart watch
```

```
╔══════════════════════════════════════════════════════════════╗
║  RAMPART — enforce — 3 policies                             ║
╠══════════════════════════════════════════════════════════════╣
║  ✅ 21:03:42 exec  "git push origin main"     [allow-git]   ║
║  ✅ 21:03:41 read  ~/project/src/main.go      [default]     ║
║  🔴 21:03:38 exec  "rm -rf /tmp/*"            [protect-sys] ║
║  ✅ 21:03:35 exec  "npm test"                 [allow-dev]   ║
║  🟡 21:03:33 exec  "curl https://api.io"      [log-http]    ║
╠══════════════════════════════════════════════════════════════╣
║  1,247 total │ 1,201 allow │ 12 deny │ 34 log               ║
╚══════════════════════════════════════════════════════════════╝
```

---

## Integration

### HTTP Proxy

Anything that can make HTTP requests works with Rampart. Point your agent's tool calls at the proxy:

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `POST` | `/v1/tool/{toolName}` | Evaluate and execute |
| `POST` | `/v1/preflight/{toolName}` | Dry-run check |
| `GET` | `/v1/approvals` | Pending approvals |
| `POST` | `/v1/approvals/{id}/resolve` | Approve or deny |
| `GET` | `/healthz` | Health check |

### Framework Examples

```python
# Python (LangChain, CrewAI, any framework)
response = requests.post("http://localhost:9090/v1/tool/exec",
    headers={"Authorization": f"Bearer {token}"},
    json={"agent": "my-agent", "session": "s1", "params": {"command": cmd}})

if response.json()["decision"] == "deny":
    return f"Blocked: {response.json()['message']}"
```

### OpenClaw

For [OpenClaw](https://github.com/openclaw/openclaw) users, Rampart includes a daemon mode that connects via WebSocket to evaluate exec approvals. See [integrations/openclaw](integrations/openclaw/) for setup.

---

## Performance

Policy evaluation in single-digit microseconds:

| Command | Decision | Time |
|---------|----------|------|
| `rm -rf /` | deny | 8µs |
| `sudo reboot` | log | 6µs |
| `.ssh/id_rsa` read | deny | 3µs |
| `git status` | allow | 4µs |
| `curl ngrok.io` | deny | 3µs |

The proxy adds negligible latency. Agents wait seconds for LLM responses — a few microseconds of policy evaluation is invisible.

---

## Architecture

```
┌──────────────────────────────────────────┐
│              Your Agent                   │
└───────────────┬──────────────────────────┘
                │ HTTP
                ▼
┌──────────────────────────────────────────┐
│           Rampart Proxy (:9090)          │
│                                          │
│  ┌────────────┐    ┌──────────────────┐  │
│  │   Engine    │    │   Audit Sink     │  │
│  │  (µs eval)  │    │ (hash-chained)  │  │
│  └────────────┘    └──────────────────┘  │
│                                          │
│  ┌────────────┐    ┌──────────────────┐  │
│  │ Interceptors│    │ Approval Store  │  │
│  │ exec/read/  │    │ (timeout, ULID) │  │
│  │ write/fetch │    │                  │  │
│  └────────────┘    └──────────────────┘  │
└──────────────────────────────────────────┘
```

**Engine** — Loads YAML policies, evaluates tool calls. Deny-wins, first-match-within-policy, priority ordering.

**Interceptors** — Per-tool logic. Path normalization for filesystem ops, URL parsing for fetch, pattern matching for exec.

**Audit Sink** — Hash-chained JSONL with rotation and verification.

**Approval Store** — Thread-safe, ULID-keyed, configurable timeouts.

---

## CLI Reference

```bash
# Claude Code (native hooks — recommended)
rampart setup claude-code                    # One-time setup
rampart hook                                 # Called automatically by Claude Code

# Wrap (any agent that reads $SHELL)
rampart wrap -- <command>                    # Wrap any agent
rampart wrap --mode monitor -- <command>     # Audit-only, no blocking

# MCP
rampart mcp -- <mcp-server-command>          # Proxy MCP with policy enforcement
rampart mcp --mode monitor -- <server>       # Audit-only MCP proxy

# Proxy
rampart init [--profile standard|paranoid|yolo]
rampart serve [--port 9090]
rampart watch

# Policy
rampart policy check                         # Validate YAML
rampart policy explain "rm -rf /"            # Trace evaluation

# Audit
rampart audit tail [--follow]
rampart audit verify
rampart audit stats
rampart audit search [--tool exec] [--decision deny]

# Approvals
rampart pending
rampart approve <id>
rampart deny <id> [--reason "..."]
```

---

## Building from Source

```bash
git clone https://github.com/peg/rampart.git
cd rampart
go build -o rampart ./cmd/rampart
go test ./...
```

Requires Go 1.24+.

---

## Roadmap

Current: **v0.1** — all tests passing.

What's here:
- Policy engine (deny-wins, priority ordering, glob matching)
- HTTP proxy with bearer auth
- `rampart setup claude-code` — one-command Claude Code integration
- `rampart hook` — native Claude Code/Cline hook handler
- `rampart wrap` — zero-config agent wrapping via `$SHELL`
- `rampart mcp` — MCP protocol proxy with policy enforcement
- Four interceptors (exec, read, write, fetch)
- Response-side evaluation (catch credential leaks in output)
- Hash-chained audit trail
- Human approval flow
- Live terminal dashboard
- OpenClaw daemon integration
- Three security profiles (standard, paranoid, yolo)

## Compatibility

| Agent | Method | Status |
|-------|--------|--------|
| Claude Code | `rampart setup claude-code` | Native hooks, all platforms |
| Aider | `rampart wrap` | Linux, macOS |
| OpenCode | `rampart wrap` | Linux, macOS |
| Continue | `rampart wrap` | Linux, macOS |
| Cline | `rampart wrap` or hooks | Linux, macOS |
| Cursor | `rampart wrap` | Linux, macOS |
| Windsurf | `rampart wrap` | Linux, macOS |
| Codex CLI | Not yet supported | Uses `getpwuid()`, bypasses `$SHELL` |
| Any MCP server | `rampart mcp` | All platforms |
| Custom agents | `rampart serve` | All platforms |

`rampart hook`, `rampart mcp`, and `rampart serve` work on Linux, macOS, and Windows.
`rampart wrap` requires a POSIX shell and works on Linux and macOS.

## What's next
- Behavioral fingerprinting from audit data
- Temporal sequence detection ("read .env then curl within 30s")
- MCP auto-policy generation from tool schemas
- Adversarial testing framework

---

## License

[Apache 2.0](LICENSE)
