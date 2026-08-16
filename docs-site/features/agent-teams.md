---
title: Agent Team Oversight
description: "Rampart groups sub-agent approvals by shared run ID so you can supervise agent teams safely. Review and approve parallel Claude Code or Cline actions together."
---

# Agent Team Oversight

When you run Claude Code with multiple sub-agents — or any orchestrator spawning
parallel workers — every agent in the session shares the same **run ID**.
Rampart groups their pending approvals so you can decide the current calls
together and separately choose whether later calls receive a time-bounded
grant.

!!! info "Available since v0.4.0"

---

## How It Works

Claude Code assigns a `session_id` to every session. When you run an orchestrator that spawns sub-agents, all of them share that same `session_id`. Rampart reads it from the `PreToolUse` hook payload and uses it as the **run ID** for grouping.

Cline uses `taskId` instead — Rampart maps that automatically.

You don't configure anything. If you already use Rampart, agent team grouping just works.

---

## Dashboard View

When 2 or more pending approvals share the same agent, session, run ID, and
credential owner, the dashboard's **Active** tab groups them into a cluster
card:

```
┌─────────────────────────────────────────────────────────┐
│  Run: a1b2c3d4…  credential-3fa87c…  (3 pending)    ▼   │
├─────────────────────────────────────────────────────────┤
│  exec  kubectl apply -f deploy.yaml    claude-code      │
│  exec  kubectl delete pod old-pod      claude-code      │
│  exec  kubectl rollout restart app     claude-code      │
├─────────────────────────────────────────────────────────┤
│ [✓ Approve Pending] [Allow Future (2m)] [✗ Deny Pending]│
└─────────────────────────────────────────────────────────┘
```

**Approve Pending** resolves only the calls that are pending now. Later calls
from the same run still require approval.

**Allow Future** is a separate, explicit grant. It approves the pending calls
and authorizes later calls from the exact same agent/session/run and credential
owner for the duration shown on the button (default: 2 minutes). Calls that
are already pending for that owner must all appear in the reviewed request.
The window begins at Rampart's validation snapshot; resolving raced calls does
not restart or extend it.
Calls that arrive after Rampart's validation snapshot while it closes the
create-versus-grant race are covered by that future authority and reported
separately from the reviewed IDs. If one of those calls is denied, expires, is
deleted, or is approved by another resolver first, Rampart aborts the future
grant and requires a refresh rather than overriding the intervening decision.

**Deny Pending** blocks only the currently pending requests. The agents get a
denial response and can try a different approach.

Solo approvals (no run ID, or unique run ID) render exactly as before — no UI change for single-agent users.

---

## Explicit Run Grants

After you confirm **Allow Future**, Rampart caches the complete agent, session,
run, and credential-owner identity. New tool calls in that exact scope are
allowed immediately — the agent doesn't wait and no approval card is created.

The grant expires after the configured `--approval-timeout` (default: 2
minutes). The confirmation names the exact scope and duration before authority
is granted. This window begins when Rampart validates the reviewed snapshot,
not when the last raced call settles. After expiry, the next call from that run
queues for approval again.

Run grants currently expire by timeout or when the server restarts; the bulk
endpoint does not yet revoke a live grant early. A `deny` request affects
pending calls only.

Only one live `rampart serve` process may own approval state in a Rampart data
directory. A second process using the same directory fails at startup rather
than creating an independent in-memory grant view. Use one service endpoint per
data directory.

---

## API

### Bulk resolve a run

```http
POST /v1/approvals/bulk-resolve
Authorization: Bearer <admin-scoped-token>
Content-Type: application/json

{
  "agent": "claude-code",
  "session": "repo/main",
  "run_id": "SESSION_ID_HERE",
  "action": "approve",
  "scope": "pending",
  "ids": ["01KHT3...", "01KHT4...", "01KHT5..."],
  "resolved_by": "dashboard"
}
```

Response:

```json
{
  "resolved": 3,
  "ids": ["01KHT3...", "01KHT4...", "01KHT5..."],
  "reviewed_ids": ["01KHT3...", "01KHT4...", "01KHT5..."],
  "race_covered_ids": [],
  "scope": "pending",
  "future_calls_authorized": false
}
```

`agent`, `session`, and `run_id` are required. Missing or empty identity fields
return `400`; Rampart refuses to infer an authorization identity from a run ID.
`scope` and `ids` are also required. The IDs must be the exact pending
approvals the operator reviewed. IDs already stale during initial validation
return `409` before this request resolves a listed call. If another resolver or
expiry races after validation, Rampart returns `503`; exact resolutions already
committed are named in `ids`, unresolved reviewed calls are named in
`unresolved_reviewed_ids`, and no future-call grant is published. A `503` also
sets `refresh_required: true`; refresh and reconcile instead of replaying the
same request blindly. Use `scope: "run"` only when you intend to grant future-call
authority. All IDs in a run-scoped request must share one credential owner. A
run-scoped request must also include every approval already pending for that
owner at initial validation; omission returns `409` without resolving a listed
call. A successful response then includes `future_calls_authorized: true`,
`grant_ttl_ms`, and `grant_expires_at`.

### List approvals with run groups

```http
GET /v1/approvals
Authorization: Bearer <admin-scoped-token>
```

Response includes both the flat `approvals` array and a `run_groups` array:

```json
{
  "approvals": [...],
  "run_grant_ttl_ms": 120000,
  "run_groups": [
    {
      "agent": "claude-code",
      "session": "repo/main",
      "run_id": "abc123...",
      "credential_owner": "credential-3fa87c921e10",
      "count": 3,
      "earliest_created_at": "2026-02-19T04:30:00Z",
      "items": [...]
    }
  ]
}
```

`run_groups` only includes groups with 2+ pending items in the same exact
agent/session/run and credential-owner scope, sorted by
`earliest_created_at`. The credential-owner value is an opaque, shortened
store identifier; it is not a bearer credential.

---

## Override the Run ID

By default, Rampart derives the run ID from Claude Code's `session_id` (or Cline's `taskId`). You can override it with the `RAMPART_RUN` environment variable — useful for scripted orchestration or CI:

```bash
RAMPART_RUN=my-deploy-run claude
```

Priority order:

1. `RAMPART_RUN` env var (explicit override)
2. `session_id` from the Claude Code hook payload
3. `CLAUDE_CONVERSATION_ID` env var (fallback)
4. Empty string (no grouping)

---

## Audit Trail

Every audit event includes `run_id` when present:

```json
{
  "timestamp": "2026-02-19T04:30:00Z",
  "run_id": "abc123...",
  "tool": "exec",
  "command": "kubectl apply -f deploy.yaml",
  "agent": "claude-code",
  "decision": { "action": "approved" }
}
```

Each bulk-resolution audit event records `approval_scope`, the exact approval
ID, and `future_calls_requested`. A separate
`run_approval_publication_authorized` event is required immediately before a
run grant can become observable and distinguishes reviewed IDs from any
race-covered approvals, along with credential owner, millisecond TTL, and
candidate expiry. It records authorization intent, not successful publication,
so a sink failure cannot leave evidence that overclaims active authority. The
API response's `future_calls_authorized` field confirms that Rampart published
the future-call grant.

This means you can trace the full activity of an agent team run across the entire audit log — filter by `run_id` to see everything that run touched.

---

## Supported Agents

| Agent | Run ID source | Notes |
|-------|--------------|-------|
| Claude Code | `session_id` from PreToolUse hook | Shared across orchestrator + all sub-agents |
| Cline | `taskId` from hook payload | Per-task grouping |
| Any agent via `RAMPART_RUN` | Env var override | Set before launching your orchestrator |
| MCP proxy | `run_id` in tool call params | Pass explicitly from your MCP client |
