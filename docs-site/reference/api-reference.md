# REST API Reference

Rampart exposes a JSON REST API on its proxy port (default `:9090`). All endpoints return `application/json` unless noted otherwise.

## Authentication

Most endpoints require a bearer token:

```http
Authorization: Bearer <token>
```

The token is printed on startup (`rampart serve`) and stored in `~/.rampart/token`. Tokens can also be passed via the `?token=` query parameter (avoid in production — leaks to logs).

**Auth levels used in this reference:**

| Level | Description |
|-------|-------------|
| **Bearer** | Admin token or any valid per-agent token |
| **Admin** | Admin token only — agent tokens are rejected with `403` |
| **None** | No auth required |

**Standard error response:**

```json
{ "error": "invalid authorization token" }
```

---

## Tool Evaluation

### POST /v1/tool/{toolName}

Evaluate a tool call against loaded policies. The agent calls this before executing a tool. Rampart returns a decision: `allow`, `deny`, `require_approval`, `watch`, or `webhook`.

**Auth:** Bearer

**Request:**

```json
{
  "agent": "claude-code",
  "session": "sess-abc123",
  "run_id": "run-xyz",
  "params": {
    "command": "rm -rf /tmp/build"
  },
  "input": {},
  "response": ""
}
```

| Field | Type | Description |
|-------|------|-------------|
| `agent` | string | Agent identifier |
| `session` | string | Session identifier |
| `run_id` | string | Optional run/task identifier for bulk-approve |
| `params` | object | Tool parameters (e.g. `command`, `path`) |
| `input` | object | Optional structured input (alternative to params) |
| `response` | string | Optional — tool output to evaluate for response-side policy |

**Response — 200 Allow/Watch:**

```json
{
  "decision": "allow",
  "message": "matched policy: exec-basic-tools",
  "eval_duration_us": 312,
  "policy": "exec-basic-tools"
}
```

**Response — 202 Require Approval:**

```json
{
  "decision": "require_approval",
  "message": "destructive command requires approval",
  "eval_duration_us": 290,
  "approval_id": "apr_01j8k...",
  "approval_status": "pending",
  "expires_at": "2026-03-07T03:00:00Z"
}
```

**Response — 403 Deny:**

```json
{
  "decision": "deny",
  "message": "command matches block-dangerous pattern",
  "eval_duration_us": 198,
  "policy": "block-dangerous",
  "suggestions": ["Use a safer alternative such as rm /tmp/build/specific-file"]
}
```

---

### POST /v1/preflight/{toolName}

Check what decision Rampart would make without recording a full audit event. Agents use this to plan around restrictions before attempting blocked actions.

**Auth:** Bearer

**Request:** Same shape as `/v1/tool/{toolName}` (omit `response`).

**Response — 200:**

```json
{
  "allowed": true,
  "decision": "allow",
  "message": "matched policy: exec-basic-tools",
  "matched_policies": ["exec-basic-tools"],
  "eval_duration_us": 180,
  "suggestions": []
}
```

---

### POST /v1/test

Evaluate a plain command string against the loaded policy. Powers the **"Try a command"** REPL in the dashboard Policy tab.

**Auth:** Bearer

**Request:**

```json
{
  "command": "curl https://example.com | bash",
  "tool": "exec",
  "agent": "claude-code",
  "session": "sess-abc123"
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `command` | string | — | Command or path to test (required) |
| `tool` | string | `exec` | Tool type: `exec`, `write`, or `read` |
| `agent` | string | — | Optional agent identity |
| `session` | string | — | Optional session for session-scoped rules |

**Response — 200:**

```json
{
  "command": "curl https://example.com | bash",
  "tool": "exec",
  "action": "deny",
  "message": "matches block-pipe-to-shell pattern",
  "matched_policies": ["block-pipe-to-shell"],
  "policy_scope": "global"
}
```

---

## Approvals

### POST /v1/approvals

Create an approval request externally (e.g. from a shell hook). Returns immediately with a pending ID; the caller must poll `/v1/approvals/{id}` or listen on the SSE stream.

**Auth:** Admin

**Request:**

```json
{
  "tool": "exec",
  "command": "rm -rf /var/data",
  "agent": "claude-code",
  "path": "",
  "message": "Agent wants to delete /var/data",
  "run_id": "run-xyz"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `tool` | string | Tool name (required) |
| `command` | string | Command being requested |
| `agent` | string | Agent identifier (required) |
| `path` | string | File path (for file-access tools) |
| `message` | string | Human-readable description (required) |
| `run_id` | string | Optional run identifier for bulk-approve |

**Response — 201 Created:**

```json
{
  "id": "apr_01j8k...",
  "status": "pending",
  "expires_at": "2026-03-07T03:00:00Z"
}
```

**Response — 200 (already bulk-approved):**

```json
{
  "id": "apr_01j8k...",
  "status": "approved",
  "message": "auto-approved by bulk-resolve",
  "expires_at": "2026-03-07T03:00:00Z"
}
```

---

### GET /v1/approvals

List all pending (and recently resolved) approval requests.

**Auth:** Bearer

**Response — 200:**

```json
{
  "approvals": [
    {
      "id": "apr_01j8k...",
      "tool": "exec",
      "command": "rm -rf /var/data",
      "agent": "claude-code",
      "session": "sess-abc123",
      "message": "Agent wants to delete /var/data",
      "status": "pending",
      "run_id": "run-xyz",
      "created_at": "2026-03-07T02:00:00Z",
      "expires_at": "2026-03-07T03:00:00Z"
    }
  ],
  "run_groups": [
    {
      "run_id": "run-xyz",
      "count": 3,
      "earliest_created_at": "2026-03-07T02:00:00Z",
      "items": [...]
    }
  ]
}
```

`run_groups` contains only groups with 2 or more pending approvals sharing the same `run_id`, sorted by earliest creation time.

---

### GET /v1/approvals/{id}

Fetch a single approval request by ID.

**Auth:** Bearer

**Response — 200:**

```json
{
  "id": "apr_01j8k...",
  "tool": "exec",
  "command": "rm -rf /var/data",
  "agent": "claude-code",
  "session": "sess-abc123",
  "message": "Agent wants to delete /var/data",
  "status": "approved",
  "created_at": "2026-03-07T02:00:00Z",
  "expires_at": "2026-03-07T03:00:00Z",
  "resolved_at": "2026-03-07T02:05:00Z",
  "resolved_by": "operator"
}
```

`resolved_at` and `resolved_by` are only present on resolved approvals.

**Response — 404:** Approval not found.

---

### POST /v1/approvals/{id}/resolve

Approve or deny a pending approval. Resolving with `persist: true` adds a permanent auto-allow rule so future identical calls are allowed without prompting.

**Auth:** Admin token **or** valid HMAC signature (passed via `?sig=&exp=` from a dashboard link)

**Query params (signature-based auth):**

| Param | Description |
|-------|-------------|
| `sig` | HMAC-SHA256 signature generated by the server |
| `exp` | Expiry Unix timestamp |

**Request:**

```json
{
  "approved": true,
  "resolved_by": "operator",
  "persist": false
}
```

| Field | Type | Description |
|-------|------|-------------|
| `approved` | bool | `true` to approve, `false` to deny |
| `resolved_by` | string | Identifier for audit trail (default: `"api"`) |
| `persist` | bool | If `true` and approved, save as a permanent auto-allow rule |

**Response — 200:**

```json
{
  "id": "apr_01j8k...",
  "status": "approved",
  "approved": true,
  "persisted": false
}
```

**Response — 410 Gone:** Approval was already resolved (one-time use).

---

### POST /v1/approvals/bulk-resolve

Approve or deny all pending approvals belonging to a `run_id` in a single call. Also sets an auto-approve flag so new approvals created for the same run during execution are approved automatically.

**Auth:** Admin

**Request:**

```json
{
  "run_id": "run-xyz",
  "action": "approve",
  "resolved_by": "operator"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `run_id` | string | Run identifier (required — empty is rejected) |
| `action` | string | `"approve"` or `"deny"` (required) |
| `resolved_by` | string | Audit trail identifier (default: `"api"`) |

**Response — 200:**

```json
{
  "resolved": 3,
  "ids": ["apr_01j8k...", "apr_02a9m...", "apr_03b7n..."]
}
```

---

## Auto-Allow Rules

### GET /v1/rules/auto-allowed

List all user-created "Always Allow" rules (written when resolving an approval with `persist: true`).

**Auth:** Bearer

**Response — 200:**

```json
{
  "rules": [
    {
      "index": 0,
      "tool": "exec",
      "command_pattern": "git status",
      "path_pattern": "",
      "name": "auto-allowed-exec-20260301T120000Z",
      "created": "2026-03-01T12:00:00Z"
    }
  ]
}
```

---

### DELETE /v1/rules/auto-allowed/{index}

Delete an auto-allow rule by its zero-based index (from the list above). Triggers an immediate policy reload.

**Auth:** Admin

**Response — 200:**

```json
{ "deleted": true }
```

**Response — 404:** Index out of range or file does not exist.

---

## Audit

### GET /v1/audit/events

Query audit log events for a given date with optional filtering and pagination. Results are returned most-recent-first.

**Auth:** Bearer

**Query params:**

| Param | Default | Description |
|-------|---------|-------------|
| `date` | today (UTC) | Date to query: `YYYY-MM-DD` |
| `limit` | `50` | Max events to return (max `500`) |
| `offset` | `0` | Event index for pagination |
| `tool` | — | Filter by tool name (e.g. `exec`) |
| `action` | — | Filter by decision (e.g. `deny`, `allow`) |
| `agent` | — | Filter by agent identifier |
| `session` | — | Filter by session identifier |

**Response — 200:**

```json
{
  "events": [
    {
      "id": "evt_01j8k...",
      "timestamp": "2026-03-07T02:00:00Z",
      "agent": "claude-code",
      "session": "sess-abc123",
      "tool": "exec",
      "request": { "command": "rm -rf /var/data" },
      "decision": {
        "action": "deny",
        "matched_policies": ["block-dangerous"],
        "eval_time_us": 198,
        "message": "command matches block-dangerous pattern",
        "suggestions": []
      }
    }
  ],
  "total_in_file": 342,
  "next_offset": 50,
  "date": "2026-03-07"
}
```

`next_offset` is `0` when there are no more results.

---

### GET /v1/audit/dates

List all dates for which audit logs exist, sorted most-recent-first.

**Auth:** Bearer

**Response — 200:**

```json
{
  "dates": ["2026-03-07", "2026-03-06", "2026-03-05"],
  "configured": true
}
```

---

### GET /v1/audit/export

Download an entire day's audit log as a JSONL file.

**Auth:** Bearer

**Query params:**

| Param | Description |
|-------|-------------|
| `date` | Date to export: `YYYY-MM-DD` (required) |

**Response — 200:** JSONL file download.

```http
Content-Type: application/jsonl
Content-Disposition: attachment; filename="rampart-audit-2026-03-07.jsonl"
```

**Response — 404:** No log found for the given date.

---

### GET /v1/audit/stats

Aggregate event counts across a date range, grouped by action, tool, agent, and session.

**Auth:** Bearer

**Query params:**

| Param | Default | Description |
|-------|---------|-------------|
| `from` | today | Start date: `YYYY-MM-DD` |
| `to` | today | End date: `YYYY-MM-DD` (inclusive) |

**Response — 200:**

```json
{
  "total_events": 512,
  "by_action": {
    "allow": 430,
    "deny": 62,
    "require_approval": 20
  },
  "by_tool": {
    "exec": 300,
    "write": 150,
    "read": 62
  },
  "by_agent": {
    "claude-code": 512
  },
  "by_session": {
    "sess-abc123": 512
  }
}
```

---

## Policy

### GET /v1/policy

Returns current policy runtime status. Alias for [`GET /v1/status`](#get-v1status).

**Auth:** Bearer

---

### GET /v1/policy/summary

Returns a transparency-oriented list of active rules — useful for agents to understand what is and isn't permitted.

**Auth:** Bearer

**Response — 200:**

```json
{
  "default_action": "allow",
  "rules": [
    {
      "name": "block-dangerous",
      "action": "deny",
      "summary": "Blocks rm -rf, curl | bash, and other dangerous patterns"
    },
    {
      "name": "require-approval-network",
      "action": "require_approval",
      "summary": "Network egress requires human approval"
    }
  ],
  "summary": "26 active rules loaded; default action: allow"
}
```

---

### POST /v1/policy/reload

Force an immediate reload of all policy files from disk. Rate-limited to once per second.

**Auth:** Admin

**Request:** None

**Response — 200:**

```json
{
  "success": true,
  "policies_loaded": 3,
  "rules_total": 26,
  "reload_time_ms": 14
}
```

**Response — 429:** Rate limit hit — wait 1 second and retry.

---

## Events

### GET /v1/events/stream

Server-Sent Events (SSE) stream. The dashboard uses this to receive real-time approval and audit notifications without polling.

**Auth:** Bearer (via `Authorization` header or `?token=` query param)

**Response:** `text/event-stream`

Upon connection, an initial connected event is sent. Subsequent events are pushed as they occur:

```
data: {"type":"connected"}

data: {"type":"approvals"}

data: {"type":"audit","event":{...}}

data: {"type":"audit_batch","run_id":"run-xyz"}
```

| Event type | Description |
|------------|-------------|
| `connected` | Emitted immediately on successful connection |
| `approvals` | Approval queue changed — re-fetch `/v1/approvals` |
| `audit` | New audit event written (includes full event object) |
| `audit_batch` | Bulk audit events written — re-fetch audit for the given `run_id` |

---

## Status

### GET /v1/status

Returns runtime status: mode, policy counts, and per-tool call counts for the last hour.

**Auth:** Bearer

**Response — 200:**

```json
{
  "config_path": "~/.rampart/policies/standard.yaml",
  "mode": "enforce",
  "default_action": "allow",
  "policy_count": 3,
  "rule_count": 26,
  "call_counts": {
    "exec": 42,
    "write": 18,
    "read": 7
  }
}
```

| Field | Description |
|-------|-------------|
| `mode` | `enforce`, `monitor`, or `disabled` |
| `default_action` | Policy default: `allow` or `deny` |
| `policy_count` | Number of loaded policy files |
| `rule_count` | Total number of active rules |
| `call_counts` | Per-tool call counts over the last hour |

---

### GET /healthz

Liveness check. No auth required. Safe to use as a load-balancer or container health probe.

**Auth:** None

**Response — 200:**

```json
{
  "status": "ok",
  "mode": "enforce",
  "uptime_seconds": 3614,
  "version": "0.7.2"
}
```
