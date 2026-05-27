# Hermes Approval Ownership

Status: proposed

## Problem

Rampart's current Hermes integration is intentionally conservative. The bundled Hermes plugin runs a `pre_tool_call` hook, sends sanitized metadata to Rampart, blocks `deny`, and blocks `ask` / `require_approval` because Hermes plugins do not yet have a first-class way to create a native approval, wait for the operator, and resume the exact same tool call.

That is the right experimental boundary, but it is not the final product shape. A durable Hermes integration needs human approval without introducing a hidden Rampart approval queue or asking the operator to resolve the same action in two places.

The failure mode to avoid is split-brain approval ownership:

- Hermes has the active tool call and the user-facing chat / gateway approval surface.
- Rampart creates a separate pending approval object for the same tool call.
- The operator resolves one queue while the executing agent waits on another queue, or the tool call cannot be resumed exactly.

## Decision

For **Hermes-hosted workflows**, Hermes owns the operator-facing approval object and exact tool-call resume.

Rampart owns:

- policy evaluation
- absolute deny enforcement
- audit and diagnostics
- learning / persistent rule writeback for approved `allow-always` flows
- result-side policy and redaction decisions when configured

Hermes owns:

- native approval cards, prompts, Discord / gateway delivery, and CLI approval UI
- exact approval IDs exposed to the operator
- pausing and resuming the exact tool call that triggered the approval
- approval timeouts and user-visible cancellation
- session-level approval affordances, where allowed by policy

Rampart must not create a second human-facing pending approval object for the same Hermes-hosted tool call.

For **Rampart-hosted workflows**, Rampart's native approval store remains canonical. Examples include standalone dashboard/API approval workflows, direct `/v1/approvals` users, and integrations that do not provide their own approval/resume surface.

## Hard invariant

**Exactly one system may own the operator-facing pending approval object for a given tool call.**

Supporting metadata, audit events, learned-rule writeback, and post-resolution callbacks are allowed. A second human-facing pending approval object is not.

## Current boundary

The current Hermes plugin uses `POST /v1/preflight/{tool}` by default. That is deliberate because preflight avoids creating Rampart-native pending approvals that Hermes cannot resume from a plugin hook.

Current behavior remains:

- `allow`, `watch`, `log` -> Hermes continues the tool call.
- `deny` -> Hermes blocks the tool call with the Rampart policy reason.
- `ask`, `require_approval` -> Hermes blocks with an approval-required message.
- Rampart unavailable -> mutating / high-risk tools fail closed unless explicitly configured otherwise.

This document defines the target contract for moving beyond that conservative boundary.

## Target Hermes-hosted flow

```text
LLM requests a Hermes tool call
  |
  v
Hermes pre_tool_call broker invokes Rampart plugin
  |
  v
Rampart evaluates policy for tool + params + host ownership metadata
  |
  +-- deny -> Hermes returns blocked tool result; tool never executes
  |
  +-- allow/watch/log -> Hermes may execute, subject to native Hermes guardrails
  |
  +-- ask/require_approval -> Hermes creates one native approval object
                              with the Rampart decision attached
        |
        v
Operator approves / denies / times out in Hermes
        |
        v
Hermes resumes or blocks the exact original tool call
        |
        v
Hermes reports the approval outcome and tool result back to Rampart
        |
        v
Rampart records audit, diagnostics, and learned-rule writeback if requested
```

## API contract shape

The exact wire format can evolve, but the contract should make approval ownership explicit.

### Evaluation request

Hermes-hosted calls to `POST /v1/tool/{toolName}` should include host ownership metadata:

```json
{
  "agent": "hermes",
  "session": "sess-abc123",
  "run_id": "run-xyz",
  "tool_call_id": "toolu_01j8k...",
  "params": {
    "command": "deploy-prod"
  },
  "approval_owner": {
    "host": "hermes",
    "mode": "hosted",
    "supports_exact_resume": true,
    "supports_allow_always": true,
    "supports_result_callback": true
  }
}
```

Required semantics:

- `approval_owner.host=hermes` identifies the user-facing approval host.
- `approval_owner.mode=hosted` means Rampart must not create a Rampart-native pending approval object for this tool call.
- `tool_call_id` must be stable enough for Hermes to resume the exact call after approval.
- `run_id` may group related calls, but it must not replace exact approval IDs.
- If `supports_exact_resume=false`, Rampart must not return a hosted approval requirement that assumes resumability.

### Evaluation response

For an approval-required decision in hosted mode, Rampart returns a decision object, not a Rampart pending approval:

```json
{
  "decision": "ask",
  "message": "deployment requires operator approval",
  "policy": "deploy-prod-approval",
  "audit_id": "aud_01j8k...",
  "approval_mode": "hosted",
  "approval_owner": {
    "host": "hermes",
    "mode": "hosted"
  },
  "approval": {
    "reason": "deployment requires operator approval",
    "scope_options": ["once", "session"],
    "allow_always_supported": true,
    "expires_at": "2026-05-27T19:00:00Z"
  }
}
```

Required semantics:

- The response may include `audit_id` for correlation.
- It must not include a Rampart-native `approval_id` that points to an operator-facing Rampart queue in hosted mode.
- Hermes turns this response into its native `require_approval` / approval-card primitive.
- `deny` remains absolute. A Hermes approval must not override a Rampart `deny`.

### Approval outcome callback

After the native Hermes approval is resolved, Hermes reports the outcome to Rampart:

```json
{
  "audit_id": "aud_01j8k...",
  "tool_call_id": "toolu_01j8k...",
  "host_approval_id": "hermes_apr_01j8k...",
  "outcome": "approved",
  "scope": "once",
  "resolved_by": "operator",
  "resolved_at": "2026-05-27T18:42:15Z",
  "message": "approved in Hermes gateway"
}
```

Required semantics:

- Outcomes include `approved`, `denied`, `timeout`, and `cancelled`.
- Rampart records the outcome against the original audit entry.
- `allow-always` / learned-rule writeback is explicit and auditable.
- A callback is diagnostic and persistence-oriented; it does not grant permission to execute a different tool call.

### Tool result callback

After execution, Hermes may report result metadata for audit and result-side policy:

```json
{
  "audit_id": "aud_01j8k...",
  "tool_call_id": "toolu_01j8k...",
  "status": "completed",
  "exit_code": 0,
  "result_summary": {
    "bytes": 1840,
    "lines": 42,
    "redacted": false
  }
}
```

Result callbacks should default to metadata, size, hashes, and redacted previews. Full tool output should require an explicit policy choice because outputs can contain secrets.

## Hermes requirements

Hermes needs a core/plugin primitive that can represent a Rampart `ask` without executing the tool call or creating a competing approval queue.

The primitive should support:

- a `pre_tool_call` return shape such as `require_approval`
- exact native approval IDs
- exact tool-call pause and resume by ID
- deny / timeout paths that do not execute the tool
- approval result metadata exposed to `post_approval_response` or an equivalent plugin hook
- tool result metadata exposed to `transform_tool_result` or a follow-up callback
- guardrails ensuring Rampart `deny` is not bypassed by approvals-off modes or broad session approvals

A session-level Hermes approval can reduce prompts only when Rampart explicitly permits that scope. It must not silently upgrade an `allow once` policy result into a broader approval.

## Rampart requirements

Rampart needs to distinguish native Rampart approvals from host-owned approvals.

Implementation direction:

1. Add explicit hosted ownership fields to evaluation requests and responses.
2. In hosted mode, return approval requirements without creating a Rampart pending approval object.
3. Record an audit entry for the policy decision and correlate it with the host approval ID later.
4. Add an approval outcome endpoint or equivalent callback for hosted approvals.
5. Add result callback support for execution metadata and result-side policy.
6. Preserve existing `/v1/approvals` behavior for Rampart-hosted workflows.
7. Make `rampart doctor hermes` verify whether the installed Hermes supports hosted approvals.

## Forbidden behaviors

For Hermes-hosted workflows, the integration must not:

- create a Rampart-native pending approval and a Hermes approval for the same tool call
- poll a hidden Rampart approval queue while Hermes has the only resumable tool call
- resume a different tool call than the one that produced the approval request
- allow Hermes `/yolo`, approvals-off settings, or broad session approvals to bypass Rampart `deny`
- write a persistent allow rule from an approval that was only scoped to `once`
- send full secret-bearing tool inputs or outputs to Rampart unless policy explicitly requires them

## Acceptance criteria

A complete Hermes-hosted approval implementation should prove:

- a Rampart `deny` prevents tool execution
- a Rampart `ask` creates exactly one Hermes-native approval object
- no Rampart-native pending approval object is created in hosted mode
- approving once resumes the exact original tool call
- denying, cancelling, or timing out does not execute the tool
- `allow-always` writes a persistent Rampart rule only when that scope was explicitly chosen
- a repeated matching call is silent / allowed after learned-rule writeback
- concurrent approvals resolve by exact ID, not FIFO order
- Rampart audit links policy decision, host approval ID, approval outcome, and tool result metadata
- Rampart unavailable fails closed for mutating / high-risk tools unless explicitly configured otherwise

## Rollout sequence

1. Document this contract and keep current Hermes integration labeled experimental.
2. Add Rampart hosted approval API fields and audit semantics behind compatibility-preserving behavior.
3. Add Hermes core support for plugin-driven native approval and exact resume.
4. Move the Rampart Hermes plugin from preflight-only mode to hosted `/v1/tool/{tool}` mode when supported.
5. Add end-to-end regression tests with temporary Hermes and Rampart homes.
6. Add doctor/status checks that detect unsupported Hermes versions, missing plugin state, unreachable Rampart, and dual-queue drift.

## Why this is the best UX

This preserves the operator's mental model:

- one approval card
- one approval ID
- one place to click
- one exact tool call resumed or blocked
- one audit chain explaining the policy decision and outcome

Rampart makes Hermes safer without owning Hermes' user interaction. Hermes remains the visible approval host, and Rampart remains the policy and audit authority.
