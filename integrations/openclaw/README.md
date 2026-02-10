# Rampart + OpenClaw Integration

Rampart integrates with OpenClaw as an **automated exec approval engine**. When an agent attempts to run a command, OpenClaw asks Rampart for approval — and Rampart evaluates it against your policies in microseconds.

## How It Works

```
Agent → exec "rm -rf /" → OpenClaw Gateway (approval required)
                                │
                                ▼ exec.approval.requested
                          Rampart Daemon (WebSocket operator client)
                                │ evaluate against policies (µs)
                                ▼ exec.approval.resolve → deny
                          Gateway → Agent gets denial
                                │
                                ▼ audit event recorded
```

1. The agent requests a tool call (e.g., `exec` with `rm -rf /`)
2. OpenClaw's exec approval system triggers (command not in allowlist)
3. Gateway broadcasts `exec.approval.requested` to operator clients
4. Rampart daemon receives the request and evaluates against loaded policies
5. Rampart resolves: **allow**, **deny**, or **allow + log** — in microseconds
6. Every decision is recorded in the tamper-evident audit trail

## Quick Start

### 1. Configure OpenClaw for approval-gated exec

```json5
// ~/.openclaw/openclaw.json5
{
  tools: {
    exec: {
      host: "gateway",
      security: "allowlist",
      ask: "on-miss",
    }
  }
}
```

### 2. Start Rampart daemon

```bash
# Initialize with your preferred policy profile
rampart init --profile standard

# Start the daemon (connects to OpenClaw Gateway WebSocket)
rampart daemon --token YOUR_GATEWAY_TOKEN
```

The daemon connects to `ws://127.0.0.1:18789` by default and authenticates as an operator with approval permissions.

### 3. That's it

Every exec command the agent runs now goes through Rampart policy evaluation. Watch decisions in real-time:

```bash
rampart watch
```

## Configuration

### Rampart daemon flags

```
--gateway     Gateway WebSocket URL (default: ws://127.0.0.1:18789)
--token       Gateway auth token (or set OPENCLAW_GATEWAY_TOKEN)
--config      Rampart policy file (default: rampart.yaml)
--audit-dir   Audit log directory (default: ~/.rampart/audit)
--reconnect   Reconnect interval in seconds (default: 5)
```

### OpenClaw exec approval settings

| Setting | Value | Effect |
|---------|-------|--------|
| `tools.exec.host` | `"gateway"` | Exec runs on gateway host (not sandbox) |
| `tools.exec.security` | `"allowlist"` | Only allowlisted commands run without approval |
| `tools.exec.ask` | `"on-miss"` | Prompt for approval when command isn't allowlisted |

With these settings, any command not in the exec-approvals allowlist triggers an approval request that Rampart auto-resolves.

## Policy Decisions

| Rampart Decision | Approval Resolution | Effect |
|-----------------|-------------------|--------|
| **allow** | `allow-once` | Command executes, audit event recorded |
| **deny** | `deny` | Command blocked, agent gets rejection |
| **log** | `allow-once` | Command executes, flagged in audit trail |

## Additional Tools

### Policy sync

Generate OpenClaw-compatible config from Rampart policies:

```bash
rampart openclaw sync --config ~/.rampart/rampart.yaml
```

### Audit sidecar

Run Rampart in audit-only mode for visibility without enforcement:

```bash
rampart init --profile yolo
rampart serve
rampart watch
```

## Architecture

The daemon implements the OpenClaw Gateway WebSocket protocol:

- Connects as `role: operator` with `scopes: [operator.read, operator.approvals]`
- Handles protocol v3 handshake (challenge/response)
- Listens for `exec.approval.requested` events
- Resolves via `exec.approval.resolve` method
- Auto-reconnects on disconnect with configurable interval

Rampart evaluates policies in **microseconds** — the overhead is negligible compared to the agent's LLM inference time.
