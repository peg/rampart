# Architecture

## Overview

Rampart is a policy enforcement layer between AI agents and their tools. Every tool call passes through Rampart, which evaluates it against YAML policies and returns allow, deny, or log. Everything is audited to a hash-chained trail.

```
Agent → Tool Call → Rampart → Policy Engine → Allow / Deny / Log
                                            → Audit (always)
```

## Design Decisions

**Fail-closed.** If Rampart crashes, tool calls fail. The agent doesn't get unrestricted access. A security layer that fails open is a logging tool.

**Custom YAML over OPA/Rego.** The domain is narrow — "should this tool call run?" — and doesn't need a general-purpose policy language. Three lines of YAML beats fifteen lines of Rego. The custom engine also evaluates in <10µs vs OPA's 0.1-1ms.

**Local-first.** No data leaves the machine. No cloud dependency. No telemetry. You're adding a security layer, not another SaaS.

**Deny-wins evaluation.** If any policy says deny, the call is denied. No ambiguity, no override. Within a priority level, first match wins.

## Components

### Policy Engine (`internal/engine/`)

Loads YAML policies, evaluates tool calls. The hot path.

Evaluation order:
1. Collect all policies whose `match` clause fits the tool call
2. Within each policy, rules evaluate top-to-bottom (first match wins)
3. Across policies: any `deny` → denied. No deny + any `log` → logged. Only `allow` → allowed
4. Nothing matches → configurable default action

Policies hot-reload via fsnotify. Edit the YAML, Rampart picks it up.

### Interceptors (`internal/intercept/`)

Per-tool-type logic that normalizes parameters before they hit the engine:

- **exec** — command pattern matching, binary extraction
- **read/write** — path normalization, glob matching
- **fetch** — URL parsing, domain extraction

### Audit Sink (`internal/audit/`)

Append-only JSONL with hash chaining. Each event includes SHA-256 of the previous event's hash — tamper with any record and the chain breaks.

- ULID event IDs (time-ordered, sortable)
- External anchor every 100 events (prevents full-chain recomputation)
- fsync on every write
- Log rotation with chain continuity across files

### Proxy Server (`internal/proxy/`)

HTTP server that accepts tool calls, evaluates them, and returns decisions. Bearer token auth, localhost-only by default.

| Endpoint | Purpose |
|----------|---------|
| `POST /v1/tool/{name}` | Evaluate and execute |
| `POST /v1/preflight/{name}` | Dry-run check |
| `GET /v1/approvals` | Pending approvals |
| `POST /v1/approvals/{id}/resolve` | Approve/deny |
| `GET /healthz` | Health check |

### Approval Store (`internal/approval/`)

Thread-safe store for `require_approval` decisions. ULID-keyed, configurable timeouts. The proxy blocks the request until a human resolves it or it times out.

### Wrap Command (`cmd/rampart/cli/wrap.go`)

`rampart wrap -- <command>` starts an embedded proxy, generates a shell shim, sets `$SHELL` to the shim, and execs the child process. Every shell command the child spawns goes through the shim, which checks the preflight API before executing. The agent doesn't need modification.

### Daemon (`internal/daemon/`)

WebSocket client that connects to an OpenClaw gateway. Receives `exec.approval.requested` events, evaluates them against policies, and sends `allow-once` or `deny` resolutions. Useful when OpenClaw's approval system is the enforcement point.

## Integration Patterns

**`rampart wrap`** — Wrap any process. No code changes, no config beyond a policy file. The shell shim intercepts commands transparently. Best for: Claude Code, Codex, standalone scripts.

**HTTP Proxy** — Point your agent's tool calls at `localhost:9090`. Framework-agnostic. Best for: custom agents, Python scripts, anything that makes HTTP calls.

**OpenClaw Daemon** — Connects via WebSocket, auto-resolves exec approvals. Best for: OpenClaw deployments where the approval system is already in use.

**SDK** (`pkg/sdk/`) — Embed the engine directly in Go code. Zero network overhead, nanosecond evaluation. Best for: Go agents, performance-critical paths.

## Project Layout

```
cmd/rampart/         CLI (cobra)
internal/
  engine/            Policy evaluation (the core)
  audit/             Hash-chained JSONL audit trail
  intercept/         Tool-specific interceptors (exec, fs, http)
  proxy/             HTTP proxy server
  approval/          Human approval flow
  daemon/            OpenClaw WebSocket integration
  watch/             Terminal dashboard (bubbletea)
pkg/sdk/             Public Go SDK
policies/            Built-in profiles (standard, paranoid, yolo)
```

## Known Limitations

**Pattern matching is bypassable.** An agent can dodge `rm -rf *` detection with `find / -delete` or encoded payloads. Static patterns are a first layer, not the last. Future work: capability-based restrictions, behavioral profiling, content analysis.

**Proxy mode is voluntary.** A compromised agent could bypass `localhost:9090` by making direct calls. `rampart wrap` is harder to bypass (it controls `$SHELL`), but not impossible. For mandatory enforcement, pair with network-level controls (iptables, network namespaces).

**Response-side evaluation is pattern-based.** Rampart scans tool responses for credential patterns (AWS keys, private keys, API tokens) using regex matching. This catches accidental credential leaks but is not a full DLP solution.
