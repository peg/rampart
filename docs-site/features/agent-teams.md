---
title: Agent Team Oversight
description: "Rampart groups sub-agent approvals by shared run ID so you can supervise agent teams safely. Review and approve parallel Claude Code or Cline actions together."
---

# Agent Team Oversight

When you run Claude Code with multiple sub-agents — or any orchestrator spawning parallel workers — every agent in the session shares the same **run ID**. Rampart groups their pending approvals together so you can review and approve the whole team in one click.

!!! info "Available since v0.4.0"

---

## How It Works

Claude Code assigns a `session_id` to every session. When you run an orchestrator that spawns sub-agents, all of them share that same `session_id`. Rampart reads it from the `PreToolUse` hook payload and uses it as the **run ID** for grouping.

Cline uses `taskId` instead — Rampart maps that automatically.

You don't configure anything. If you already use Rampart, agent team grouping just works.

---

## Dashboard View

When 2 or more pending approvals share a run ID, the dashboard's **Active** tab groups them into a cluster card:

```
┌─────────────────────────────────────────────────────────┐
│  Run: a1b2c3d4…  (3 pending)                ▼           │
├─────────────────────────────────────────────────────────┤
│  exec  kubectl apply -f deploy.yaml    claude-code      │
│  exec  kubectl delete pod old-pod      claude-code      │
│  exec  kubectl rollout restart app     claude-code      │
├─────────────────────────────────────────────────────────┤
│              [✓ Approve All]  [✗ Deny All]              │
└─────────────────────────────────────────────────────────┘
```

**Approve All** resolves every pending approval in the run and caches the decision — subsequent tool calls from that run are auto-approved for the remainder of the approval timeout (default: 1 hour). No more approvals queue for that run.

**Deny All** blocks all pending requests. The agents get a denial response and can try a different approach.

Solo approvals (no run ID, or unique run ID) render exactly as before — no UI change for single-agent users.

---

## Auto-Approve Cache

After you click **Approve All**, Rampart caches the approval for that run ID. New tool calls from the same run are allowed immediately — the agent doesn't wait, no approval card is created.

The cache expires after the configured `--approval-timeout` (default 1 hour). After expiry, the next call from that run will queue for approval again.

To disable the cache for a specific run, use the API directly:

```bash
# Deny a run, preventing future auto-approvals
curl -X POST http://localhost:9090/v1/approvals/bulk-resolve \
  -H "Authorization: Bearer $RAMPART_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"run_id": "YOUR_RUN_ID", "action": "deny"}'
```

---

## API

### Bulk resolve a run

```http
POST /v1/approvals/bulk-resolve
Authorization: Bearer <token>
Content-Type: application/json

{
  "run_id": "SESSION_ID_HERE",
  "action": "approve",
  "resolved_by": "dashboard"
}
```

Response:

```json
{
  "resolved": 3,
  "ids": ["01KHT3...", "01KHT4...", "01KHT5..."]
}
```

`run_id` is required. Empty or missing `run_id` returns `400` — Rampart refuses to bulk-resolve without a run ID to prevent accidental mass-approval.

### List approvals with run groups

```http
GET /v1/approvals
Authorization: Bearer <token>
```

Response includes both the flat `approvals` array and a `run_groups` array:

```json
{
  "approvals": [...],
  "run_groups": [
    {
      "run_id": "abc123...",
      "count": 3,
      "earliest_created_at": "2026-02-19T04:30:00Z",
      "items": [...]
    }
  ]
}
```

`run_groups` only includes groups with 2+ pending items, sorted by `earliest_created_at`. Fully backwards compatible — existing consumers ignore the new field.

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

This means you can trace the full activity of an agent team run across the entire audit log — filter by `run_id` to see everything that run touched.

---

## Supported Agents

| Agent | Run ID source | Notes |
|-------|--------------|-------|
| Claude Code | `session_id` from PreToolUse hook | Shared across orchestrator + all sub-agents |
| Cline | `taskId` from hook payload | Per-task grouping |
| Any agent via `RAMPART_RUN` | Env var override | Set before launching your orchestrator |
| MCP proxy | `run_id` in tool call params | Pass explicitly from your MCP client |
