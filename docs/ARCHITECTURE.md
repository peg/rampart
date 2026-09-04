# Architecture

## Overview

Rampart is a policy enforcement layer between AI agents and their tools.
Supported integrations send host-exposed tool calls through Rampart, which
evaluates them against YAML policies and returns allow, deny, watch, ask, or a
configured decision-webhook action. Decisions that reach Rampart are written
to a hash-chained audit trail.

```
Agent → Tool Call → Rampart → Policy Engine → Allow / Deny / Watch / Ask / Webhook
                                            → Audit (always)
```

## Design Decisions

**Boundary-specific failure behavior.** Managed native integrations fail closed
when enforcement is unavailable. Optional compatibility boundaries such as the
shell wrapper and preload library can be configured to fail open. See the
[threat model](https://docs.rampart.sh/reference/threat-model/) for the trade-offs and exact boundary guarantees.

**Custom YAML over OPA/Rego.** The domain is narrow — "should this tool call
run?" — and doesn't need a general-purpose policy language. The custom engine's
hot path is benchmarked in this repository; results vary by policy set and host.

**Local-first by default.** Rampart has no telemetry or mandatory cloud
dependency. Data leaves the machine only when the operator explicitly
configures a notification, decision webhook, semantic verifier, or remote SIEM
destination.

**Deny-wins evaluation.** If any policy says deny, the call is denied. No ambiguity, no override. Within a priority level, first match wins.

## Components

### Policy Engine (`internal/engine/`)

Loads YAML policies, evaluates tool calls. The hot path.

Evaluation order:
1. Collect all policies whose `match` clause fits the tool call
2. Within each policy, rules evaluate top-to-bottom (first match wins)
3. Across policies, the restrictive precedence is `deny`, `webhook`,
   `require_approval`, `ask`, `watch`, then `allow`
4. Nothing matches → configurable default action

Policies hot-reload via fsnotify. Edit the YAML, Rampart picks it up.

### Audit Sink (`internal/audit/`)

JSONL records are written in append mode and linked by SHA-256 hashes.
Verification detects inconsistent hashes and broken links in retained history;
the local files remain writable by their owner.

- ULID event IDs (time-ordered, sortable)
- Local `audit-anchor.json` checkpoint every 100 events by default; independent
  evidence requires retention outside the agent's write authority
- Validated local chain state avoids full-history scans in one-shot native hooks
- fsync on long-running service writes; native hooks avoid per-call fsync latency
- Log rotation with chain continuity across files

### Proxy Server (`internal/proxy/`)

HTTP server that accepts tool calls, evaluates them, and returns decisions. Bearer token auth, localhost-only by default.

| Endpoint | Purpose |
|----------|---------|
| `POST /v1/tool/{name}` | Evaluate a host-owned tool call |
| `POST /v1/preflight/{name}` | Policy preview, or host-owned execution check with `enforce: true` |
| `GET /v1/approvals` | Pending approvals |
| `POST /v1/approvals/{id}/resolve` | Approve/deny |
| `GET /healthz` | Health check |

### Approval Store (`internal/approval/`)

Thread-safe store for human approval decisions. ULID-keyed, configurable timeouts. The proxy blocks the request until a human resolves it or it times out.

### Wrap Command (`cmd/rampart/cli/wrap.go`)

`rampart wrap -- <command>` starts an embedded proxy, generates a shell shim, sets `$SHELL`, prepends PATH-resolved shell wrappers, and starts the child process. Commands that use that cooperative shell boundary are checked before execution. Absolute shell paths and direct process APIs do not pass through the shim.

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

**`rampart wrap`** — Add a cooperative shell boundary without agent code changes. Best for agents that honor `$SHELL` or resolve common shells through `PATH`; it is not subprocess interposition.

**HTTP Proxy** — Point your agent's tool calls at `localhost:9090`. Framework-agnostic. Best for: custom agents, Python scripts, anything that makes HTTP calls.

**OpenClaw Plugin** — Rampart evaluates the tool call first. Allow decisions pass through, deny decisions are blocked immediately, and matched exec `ask` decisions are routed into OpenClaw's native approval flow without turning on prompts for every exec. Best for: OpenClaw deployments that want native approval UX with selective policy-driven exec approvals.

**OpenClaw compatibility bridge** — Older OpenClaw releases can use the
approval-event bridge hosted by `rampart serve`. Current releases should use the
native plugin installed by `rampart protect openclaw`.

**SDK** (`pkg/sdk/`) — Embed the engine directly in Go code. This avoids network
overhead and keeps policy evaluation in-process. Best for: Go agents and
latency-sensitive paths.

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

**Compatibility boundaries are voluntary.** A compromised agent can bypass an
HTTP proxy by making direct calls, and it can bypass `rampart wrap` by ignoring
`$SHELL`, using an absolute shell path, or calling a process API directly. Use a
native hook/plugin where one is supported. For mandatory process or network
enforcement, pair Rampart with operating-system sandboxing or network controls.

**Response-side evaluation is pattern-based.** Rampart scans tool responses for credential patterns (AWS keys, private keys, API tokens) using regex matching. This catches accidental credential leaks but is not a full DLP solution.
