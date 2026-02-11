<div align="center">

# 🛡️ Rampart

**See everything your AI agent does. Block the dangerous stuff.**

[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/peg/rampart/actions/workflows/ci.yml/badge.svg)](https://github.com/peg/rampart/actions/workflows/ci.yml)

</div>

---

Running Claude Code in yolo mode? Letting agents manage your infrastructure unsupervised? Rampart gives you visibility and control — every tool call gets evaluated against your policy before it executes. Dangerous commands get blocked in microseconds. Everything gets logged to a hash-chained audit trail.

```bash
# One command to protect Claude Code
rampart setup claude-code

# Or wrap any agent
rampart wrap -- aider

# Or protect anything via syscall interception (LD_PRELOAD)
rampart preload -- codex

# Or protect MCP servers
rampart mcp -- npx @modelcontextprotocol/server-fs .
```

<div align="center">
<img src="docs/watch.png" alt="rampart watch — live audit dashboard" width="700">
</div>

## Contents

- [Why Rampart](#why-rampart)
- [Claude Code Integration](#claude-code-integration)
- [Wrap Any Agent](#wrap-any-agent)
- [Protect Any Process (LD_PRELOAD)](#protect-any-process-ld_preload)
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

## Why Rampart

You gave your AI agent shell access because it's useful. But you have no idea what it's running — and sandboxing kills the usefulness.

Rampart sits between the agent and your system. You write a simple YAML policy that says what's allowed, what's blocked, and what gets flagged. The agent keeps working. You keep sleeping.

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

## Protect Any Process (LD_PRELOAD)

For agents with no hook system and no `$SHELL` support, `preload` intercepts exec-family syscalls at the OS level. This is the universal fallback — it works with **any** dynamically-linked process:

```bash
# Protect Codex CLI (no hooks, no $SHELL — preload is the only way)
rampart preload -- codex

# Protect any Python agent
rampart preload -- python my_agent.py

# Protect any Node.js agent
rampart preload -- node agent.js

# Monitor mode (log only, don't block)
rampart preload --mode monitor -- risky-tool
```

Preload intercepts `execve`, `execvp`, `system()`, `popen()`, and `posix_spawn()` — every way a process can spawn a command. Each call gets evaluated against your policy before executing. Denied calls return `EPERM`.

**Requires:** `librampart.so` (Linux) or `librampart.dylib` (macOS) installed to `~/.rampart/lib/`. Build from `preload/` or download from releases.

**Platform notes:**
- **Linux:** Works with all dynamically-linked binaries (~95% coverage)
- **macOS:** Works with Homebrew, nvm, pyenv, cargo binaries. Blocked by SIP for `/usr/bin/*` (but AI agents don't live there)

See [`preload/README.md`](preload/README.md) for build instructions and details.

---

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

# Make sure it's in your PATH (required for Claude Code hooks)
# Add to your shell profile (~/.zshrc or ~/.bashrc):
#   export PATH=$PATH:$(go env GOPATH)/bin
# Or symlink: sudo ln -sf $(go env GOPATH)/bin/rampart /usr/local/bin/rampart

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

# Preload (syscall interception — works with anything)
rampart preload -- <command>                 # LD_PRELOAD protection
rampart preload --mode monitor -- <command>  # Audit-only, no blocking
rampart preload --debug -- <command>         # Debug output to stderr

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
- `rampart setup cline` — one-command Cline integration
- `rampart hook` — native Claude Code/Cline hook handler
- `rampart wrap` — zero-config agent wrapping via `$SHELL`
- `rampart preload` — syscall-level interception via LD_PRELOAD (works with any agent)
- `rampart mcp` — MCP protocol proxy with policy enforcement
- Python SDK (`sdks/python/`) — decorators, async support
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
| Cline | `rampart setup cline` | Native hooks, all platforms |
| Codex CLI | `rampart preload` | LD_PRELOAD, Linux + macOS |
| Claude Desktop | `rampart mcp` | MCP server proxying, all platforms |
| Aider | `rampart wrap` | Linux, macOS |
| OpenCode | `rampart wrap` | Linux, macOS |
| Continue | `rampart wrap` | Linux, macOS |
| Cursor | `rampart wrap` + `rampart mcp` | Linux, macOS |
| Windsurf | `rampart wrap` | Linux, macOS |
| Python agents | `rampart preload` or HTTP API | Linux, macOS |
| Node.js agents | `rampart preload` or HTTP API | Linux, macOS |
| Any MCP server | `rampart mcp` | All platforms |
| Any process | `rampart preload` | Linux, macOS |
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
