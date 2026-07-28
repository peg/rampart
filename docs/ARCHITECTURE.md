# Architecture

## Overview

Rampart is a policy enforcement layer between AI agents and their tools.
Supported integrations send host-exposed tool calls through Rampart, which
evaluates them against YAML policies and returns allow, deny, or log. Decisions
that reach Rampart are written to a hash-chained audit trail.

```
Agent → Tool Call → Rampart → Policy Engine → Allow / Deny / Watch
                                            → Audit (always)
```

## Design Decisions

**Boundary-specific failure behavior.** Managed native integrations fail closed
when enforcement is unavailable. Optional compatibility boundaries such as the
shell wrapper and preload library can be configured to fail open. See the
[threat model](THREAT-MODEL.md) for the trade-offs and exact boundary guarantees.

**Custom YAML over OPA/Rego.** The domain is narrow — "should this tool call
run?" — and doesn't need a general-purpose policy language. The custom engine's
hot path is benchmarked in this repository; results vary by policy set and host.

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

### Audit Sink (`internal/audit/`)

Append-only JSONL with hash chaining. Each event includes SHA-256 of the previous event's hash — tamper with any record and the chain breaks.

- ULID event IDs (time-ordered, sortable)
- External anchor every 100 events for independent integrity checkpoints
- Validated local chain state avoids full-history scans in one-shot native hooks
- fsync on long-running service writes; native hooks avoid per-call fsync latency
- Log rotation with chain continuity across files

### Proxy Server (`internal/proxy/`)

HTTP server that accepts tool calls, evaluates them, and returns decisions. Bearer token auth, localhost-only by default.

| Endpoint | Purpose |
|----------|---------|
| `POST /v1/tool/{name}` | Evaluate and execute |
| `POST /v1/preflight/{name}` | Policy preview, or host-owned execution check with `enforce: true` |
| `GET /v1/approvals` | Pending approvals |
| `POST /v1/approvals/{id}/resolve` | Approve/deny |
| `GET /healthz` | Health check |

### Approval Store (`internal/approval/`)

Thread-safe store for human approval decisions. ULID-keyed, configurable timeouts. The proxy blocks the request until a human resolves it or it times out.

### Wrap Command (`cmd/rampart/cli/wrap.go`)

`rampart wrap -- <command>` starts an embedded proxy, generates a shell shim, sets `$SHELL` to the shim, and execs the child process. Every shell command the child spawns goes through the shim, which checks the preflight API before executing. The agent doesn't need modification.

## Integration Patterns

**Codex lifecycle hooks** — `rampart setup codex` installs user-level
`PreToolUse` and `PostToolUse` hooks shared by Codex CLI, IDE, and desktop.
This is the preferred Codex path and preserves Codex's native sandbox.

**Claude Code lifecycle hooks** — `rampart setup claude-code` installs
user-level `PreToolUse`, `PostToolUse`, and `PostToolUseFailure` hooks.
Pre-tool policy controls execution; post-tool policy can replace denied
response content with shape-preserving redacted output before the next model
turn.

**GitHub Copilot lifecycle hooks** — `rampart setup copilot` installs one
PascalCase `PreToolUse`/`PostToolUse` hook file shared by Copilot CLI and VS
Code's agent host. The adapter emits both hosts' decision schemas. Copilot CLI
also supports an administrator-owned machine policy file; that policy directory
does not apply to VS Code.

**Antigravity policy plugin** — `rampart setup antigravity` installs one
global plugin shared by Antigravity CLI and IDE. Its `PreToolUse` handler maps
the documented camelCase tool payload to Rampart's local policy engine and
uses the host's native `force_ask` decision for approval rules. Antigravity's
current `PostToolUse` payload omits the tool call and result, so Rampart does
not install a misleading post-result scanner.

**`rampart wrap`** — Wrap any process. No code changes, no config beyond a policy file. The shell shim intercepts commands transparently. Best for: agents without a native hook or plugin, and standalone scripts.

**HTTP Proxy** — Point your agent's tool calls at `localhost:9090`. Framework-agnostic. Best for: custom agents, Python scripts, anything that makes HTTP calls.

**OpenClaw Plugin** — Rampart evaluates the tool call first. Allow decisions pass through, deny decisions are blocked immediately, and matched exec `ask` decisions are routed into OpenClaw's native approval flow without turning on prompts for every exec. Best for: OpenClaw deployments that want native approval UX with selective policy-driven exec approvals.

**OpenClaw compatibility bridge** — Older OpenClaw releases can use the
approval-event bridge hosted by `rampart serve`. Current releases should use the
native plugin installed by `rampart protect openclaw`.

**SDK** (`pkg/sdk/`) — Embed the engine directly in Go code. Zero network overhead, nanosecond evaluation. Best for: Go agents, performance-critical paths.

## Policy Profiles

Built-in profiles (`standard`, `paranoid`, `yolo`) provide ready-to-use policy sets for common use cases. Profiles include platform-specific policies where relevant — in v0.4.4, 17 macOS hardening policies were added covering Keychain access, Gatekeeper bypass, persistence mechanisms, user management, and osascript (AppleScript shell execution).

## Project Layout

```
cmd/rampart/         CLI (cobra)
internal/
  engine/            Policy evaluation (the core)
  audit/             Hash-chained JSONL audit trail
  proxy/             HTTP proxy server
  approval/          Human approval flow
  bridge/            Legacy OpenClaw compatibility bridge
  watch/             Terminal dashboard (bubbletea)
pkg/sdk/             Public Go SDK
policies/            Built-in profiles (standard, paranoid, yolo)
```

## Known Limitations

**Pattern matching has gaps.** Common evasion techniques (shell wrappers like `bash -c`, quoted binaries, escaped characters) are handled via normalization and `command_contains` substring matching. However, novel obfuscation (`find / -delete`, variable expansion, encoded payloads) can bypass static patterns. Combine with [semantic verification](https://github.com/peg/rampart-verify) for intent-based classification.

**Proxy mode is voluntary.** A compromised agent could bypass `localhost:9090` by making direct calls. `rampart wrap` is harder to bypass (it controls `$SHELL`), but not impossible. For mandatory enforcement, pair with network-level controls (iptables, network namespaces).

**Response-side evaluation is pattern-based.** Rampart scans tool responses for credential patterns (AWS keys, private keys, API tokens) using regex matching. This catches accidental credential leaks but is not a full DLP solution.
