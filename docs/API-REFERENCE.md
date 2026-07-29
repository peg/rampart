# Rampart HTTP API Reference

## Overview
Rampart exposes a local HTTP API for policy evaluation, approval workflows, policy introspection, audit history, and operational monitoring.

- Default listen address: `http://127.0.0.1:9090` (configurable)
- Content type for JSON APIs: `application/json`
- Maximum request body size: 1 MiB (`1048576` bytes)
- All authenticated errors use:

```json
{
  "error": "..."
}
```

## Authentication
Most endpoints require a bearer token.

- Header format: `Authorization: Bearer <token>`
- Token source: `~/.rampart/token` (also available via `RAMPART_TOKEN` in many workflows)

Example:

```bash
TOKEN="$(cat ~/.rampart/token)"
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9090/v1/status
```

Notes:

- `GET /healthz` does not require authentication.
- `GET /v1/events/stream` accepts either bearer auth or `?token=<token>` query parameter.
- `POST /v1/approvals/{id}/resolve` may also be authorized by signed URL query params (`sig`, `exp`) when server-side signing is enabled.

## API Conventions

### Common Headers
For authenticated endpoints:

- `Authorization: Bearer <token>`
- `Content-Type: application/json` (for `POST` with JSON body)

### Error Schema

```json
{
  "error": "string"
}
```

### Decision Values
Common decision/action values across responses:

- `allow`
- `deny`
- `watch`
- `ask` (approval-required decision; `require_approval` was removed in v0.9.9)
- `approved` / `denied` / `always_allowed` (approval resolution audit context)

## Endpoints

## POST /v1/tool/{toolName}
Evaluates a tool call against active policy. In `enforce` mode, deny decisions are blocked; approval-required decisions are queued.

### Request Headers
- `Authorization: Bearer <token>` (admin or an evaluation-scoped agent token;
  an agent token overrides the request's `agent` identity)
- `Content-Type: application/json`

### Request Body Schema

```json
{
  "type": "object",
  "required": ["agent", "session", "params"],
  "properties": {
          "agent": { "type": "string" },
          "session": { "type": "string" },
    "run_id": { "type": "string" },
    "tool_call_id": { "type": "string" },
    "workdir": { "type": "string" },
    "cwd": { "type": "string" },
    "params": { "type": "object", "additionalProperties": true },
    "input": { "type": "object", "additionalProperties": true },
    "response": { "type": "string" }
  }
}
```

### Request Example

```json
{
  "agent": "claude-code",
  "session": "repo/main",
  "run_id": "run_01J...",
  "tool_call_id": "call_01J...",
  "cwd": "/home/user/project",
  "params": {
    "command": "git status"
  }
}
```

### Response Body Schema (200/202/403)

```json
{
  "type": "object",
  "required": ["allowed", "decision", "message", "eval_duration_us"],
  "properties": {
    "decision": { "type": "string" },
    "message": { "type": "string" },
    "eval_duration_us": { "type": "integer" },
    "policy": { "type": "string" },
    "suggestions": { "type": "array", "items": { "type": "string" } },
    "allowed": { "type": "boolean" },
    "enforced": { "type": "boolean" },
    "policy_decision": { "type": "string" },
    "policy_message": { "type": "string" },
    "response_policy_decision": { "type": "string" },
    "response_policy_message": { "type": "string" },
    "approval_id": { "type": "string" },
    "approval_status": { "type": "string" },
    "approval_scope": { "type": "string" },
    "approval_resolved_by": { "type": "string" },
    "approval_policy_audit_id": { "type": "string" },
    "expires_at": { "type": "string", "format": "date-time" },
    "response": { "type": "string" }
  }
}
```

Approved exact retry (when the original request supplied stable `run_id` and
`tool_call_id` values):

```json
{
  "allowed": true,
  "decision": "allow",
  "message": "approved once via Rampart approval",
  "approval_id": "01J...",
  "approval_status": "approved",
  "approval_scope": "once",
  "approval_resolved_by": "security-team",
  "approval_policy_audit_id": "evt_01J..."
}
```

Top-level `workdir` and `cwd` are convenience aliases. A structured
`params.workdir`, `params.cwd`, `input.workdir`, or `input.cwd` value takes
precedence, and the resulting working directory is used to resolve relative
paths.

The grant is short-lived and bound to the complete agent identity and depth,
session, run ID, tool-call ID, tool, effective working directory, params, and input
fingerprint. It can be consumed only once. A changed context or payload, or a
second retry, is evaluated normally and, if the ask policy still matches,
creates a new pending approval.

### Response Examples
Allowed:

```json
{
  "allowed": true,
  "decision": "allow",
  "message": "git allowed",
  "eval_duration_us": 9,
  "policy": "allow-git"
}
```

Denied:

```json
{
  "allowed": false,
  "decision": "deny",
  "message": "destructive command blocked",
  "eval_duration_us": 12,
  "policy": "block-destructive",
  "suggestions": [
    "rampart allow exec 'rm -rf /tmp/demo' --reason 'safe cleanup'"
  ]
}
```

Approval required (Rampart-native approval flow):

```json
{
  "allowed": false,
  "decision": "ask",
  "message": "needs approval",
  "eval_duration_us": 15,
  "policy": "require-human",
  "approval_id": "01J...",
  "approval_status": "pending",
  "expires_at": "2026-03-03T12:34:56Z"
}
```


In service `monitor` mode, `/v1/tool/*` is audit-only: `allowed` is `true`,
`decision` is the effective `allow`, and `enforced` is `false`. The observed
result remains available as `policy_decision` and `policy_message`. A
response-side deny is likewise recorded in `response_policy_decision` without
redacting the returned `response`. In `enforce` mode, a response-side deny sets
`allowed: false` and replaces the response with Rampart's redaction marker.

### Status Codes
- `200 OK` evaluated (allow/watch, monitor-mode deny, response-side deny with redaction)
- `202 Accepted` approval required; request queued in Rampart approval flow
- `400 Bad Request` invalid JSON body
- `401 Unauthorized` missing/invalid bearer token
- `403 Forbidden` denied in enforce mode
- `503 Service Unavailable` approval queue full or required audit storage unavailable

A non-empty `response` produces a separate response-phase audit event. The
event sets `request.rampart_phase` to `response`, links to the preceding event
with `request.request_audit_id`, records `response_bytes`, and does not store the
raw response. A monitor-mode response deny is recorded as observed rather than
redacted. In enforce mode, Rampart withholds the response if that audit event
cannot be persisted.

### curl
```bash
curl -X POST "http://127.0.0.1:9090/v1/tool/exec" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"agent":"claude-code","session":"repo/main","params":{"command":"git status"}}'
```

## POST /v1/preflight/{toolName}
Policy preview or host-owned pre-execution enforcement. By default this is a
non-mutating preview. Set `"enforce": true` only when the caller is at the
actual tool execution boundary; Rampart then records call-count state,
atomically consumes a matching `once: true` grant, and writes the audit record.
It still does not create/resolve approvals or execute the tool. When the
service itself is in `monitor` mode, an enforcement request remains audit-only:
`enforcement_requested` is true, `enforced` is false, and a restrictive policy
result is returned as an effective allow with the observed result in
`policy_decision`.

### Request Headers
- `Authorization: Bearer <token>`
- `Content-Type: application/json`

### Request Body Schema
Same schema as `POST /v1/tool/{toolName}`. Optional `enforce` defaults to
`false`. `verification: true` cannot be combined with `enforce: true`.

### Response Body Schema

```json
{
  "type": "object",
  "required": ["allowed", "decision", "message", "matched_policies", "eval_duration_us", "enforced"],
  "properties": {
    "allowed": { "type": "boolean" },
    "decision": { "type": "string" },
    "message": { "type": "string" },
    "matched_policies": { "type": "array", "items": { "type": "string" } },
    "eval_duration_us": { "type": "integer" },
    "enforced": { "type": "boolean" },
    "enforcement_requested": { "type": "boolean" },
    "policy_decision": { "type": "string" },
    "policy_message": { "type": "string" },
    "suggestions": { "type": "array", "items": { "type": "string" } }
  }
}
```

### Response Example

```json
{
  "allowed": false,
  "decision": "deny",
  "message": "destructive command blocked",
  "matched_policies": ["block-destructive"],
  "eval_duration_us": 8,
  "enforced": false,
  "enforcement_requested": false
}
```

### Status Codes
- `200 OK`
- `400 Bad Request`
- `401 Unauthorized`

### curl
```bash
curl -X POST "http://127.0.0.1:9090/v1/preflight/exec" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"agent":"claude-code","session":"repo/main","params":{"command":"rm -rf /"}}'
```

## POST /v1/approvals
Creates an external/manual approval request.

### Request Headers
- `Authorization: Bearer <admin-token>` (admin scope required; agent evaluation tokens are rejected)
- `Content-Type: application/json`

### Request Body Schema

```json
{
  "type": "object",
  "required": ["tool", "agent", "message"],
  "properties": {
    "tool": { "type": "string" },
    "command": { "type": "string" },
    "path": { "type": "string" },
    "agent": { "type": "string" },
    "message": { "type": "string" },
    "run_id": { "type": "string" }
  }
}
```

### Response Body Schema
Created (`201`):

```json
{
  "type": "object",
  "required": ["id", "status", "expires_at"],
  "properties": {
    "id": { "type": "string" },
    "status": { "type": "string" },
    "expires_at": { "type": "string", "format": "date-time" }
  }
}
```

Auto-approved (`200`, when run is bulk-approved):

```json
{
  "id": "01J...",
  "status": "approved",
  "message": "auto-approved by bulk-resolve",
  "expires_at": "2026-03-03T13:34:56Z"
}
```

### Status Codes
- `201 Created` approval created
- `200 OK` auto-approved by the exact agent/session/run cache
- `400 Bad Request` invalid JSON
- `401 Unauthorized`
- `503 Service Unavailable` approval queue full

### curl
```bash
curl -X POST "http://127.0.0.1:9090/v1/approvals" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tool":"exec","command":"kubectl delete pod foo","agent":"claude-code","message":"requires approval"}'
```

## GET /v1/approvals
Lists pending approvals plus groups keyed by the complete
`agent`/`session`/`run_id` scope. A caller-selected run ID is not assumed to be
globally unique.

### Request Headers
- `Authorization: Bearer <admin-token>` (admin scope required; agent evaluation tokens are rejected)

### Response Body Schema

```json
{
  "type": "object",
  "required": ["approvals", "run_groups"],
  "properties": {
    "approvals": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "id": { "type": "string" },
          "tool": { "type": "string" },
          "command": { "type": "string" },
          "agent": { "type": "string" },
          "session": { "type": "string" },
          "message": { "type": "string" },
          "status": { "type": "string" },
          "run_id": { "type": "string" },
          "created_at": { "type": "string", "format": "date-time" },
          "expires_at": { "type": "string", "format": "date-time" }
        }
      }
    },
    "run_groups": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "agent": { "type": "string" },
          "session": { "type": "string" },
          "run_id": { "type": "string" },
          "count": { "type": "integer" },
          "earliest_created_at": { "type": "string", "format": "date-time" },
          "items": { "type": "array" }
        }
      }
    }
  }
}
```

### Status Codes
- `200 OK`
- `401 Unauthorized`

### curl
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:9090/v1/approvals"
```

## GET /v1/approvals/{id}
Returns one approval by ID.

### Request Headers
- `Authorization: Bearer <admin-token>` (admin scope required; agent evaluation tokens are rejected)

### Response Body Schema

```json
{
  "type": "object",
  "required": ["id", "tool", "command", "agent", "session", "message", "status", "created_at", "expires_at"],
  "properties": {
    "id": { "type": "string" },
    "tool": { "type": "string" },
    "command": { "type": "string" },
    "agent": { "type": "string" },
    "session": { "type": "string" },
    "message": { "type": "string" },
    "status": { "type": "string" },
    "created_at": { "type": "string", "format": "date-time" },
    "expires_at": { "type": "string", "format": "date-time" },
    "resolved_at": { "type": "string", "format": "date-time" },
    "resolved_by": { "type": "string" }
  }
}
```

### Status Codes
- `200 OK`
- `401 Unauthorized`
- `404 Not Found`

### curl
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:9090/v1/approvals/01J..."
```

## POST /v1/approvals/{id}/resolve
Approves or denies a pending approval.

Approving a `/v1/tool/*` request that supplied both `run_id` and
`tool_call_id` creates a short-lived, one-shot grant for the exact original
request. Requests without both stable identifiers retain the existing polling
flow and are not given a reusable command-level grant.

`persist: true` stores an exact rule for `exec`, `read`, `write`, or `edit`.
Unsupported tool types return `400` and leave the approval pending so the
operator can approve once or author an explicit policy.

### Request Headers
- `Authorization: Bearer <admin-token>` (admin scope required), or a valid
  server-generated `sig` + `exp` query pair scoped to this approval ID
- `Content-Type: application/json`

Signed URLs may approve or deny this one request, but cannot use
`persist: true`; durable policy changes require admin-token authentication.

### Request Body Schema

```json
{
  "type": "object",
  "required": ["approved"],
  "properties": {
    "approved": { "type": "boolean" },
    "resolved_by": { "type": "string" },
    "persist": { "type": "boolean" }
  }
}
```

### Response Body Schema

```json
{
  "type": "object",
  "required": ["id", "status", "approved", "persisted"],
  "properties": {
    "id": { "type": "string" },
    "status": { "type": "string" },
    "approved": { "type": "boolean" },
    "persisted": { "type": "boolean" }
  }
}
```

### Status Codes
- `200 OK`
- `400 Bad Request` invalid JSON
- `401 Unauthorized` invalid token/signature
- `404 Not Found` unknown approval ID
- `410 Gone` approval already resolved (replay attempt)
- `503 Service Unavailable` durable exact-replay state could not be committed;
  the request remains pending and no execution grant is issued

### curl
```bash
curl -X POST "http://127.0.0.1:9090/v1/approvals/01J.../resolve" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"approved":true,"resolved_by":"security-team","persist":false}'
```

## POST /v1/approvals/bulk-resolve
Bulk approves or denies pending approvals for one exact
`agent`/`session`/`run_id` scope. An approved scope is cached for subsequent
calls in that same scope only.

### Request Headers
- `Authorization: Bearer <admin-token>` (admin scope required; agent evaluation tokens are rejected)
- `Content-Type: application/json`

### Request Body Schema

```json
{
  "type": "object",
  "required": ["agent", "session", "run_id", "action"],
  "properties": {
    "agent": { "type": "string" },
    "session": { "type": "string" },
    "run_id": { "type": "string" },
    "action": { "type": "string", "enum": ["approve", "deny"] },
    "resolved_by": { "type": "string" }
  }
}
```

### Response Body Schema

```json
{
  "type": "object",
  "required": ["resolved", "ids"],
  "properties": {
    "resolved": { "type": "integer" },
    "ids": { "type": "array", "items": { "type": "string" } }
  }
}
```

### Status Codes
- `200 OK`
- `400 Bad Request` missing/empty `agent`, `session`, or `run_id`, or invalid `action`
- `401 Unauthorized`

### curl
```bash
curl -X POST "http://127.0.0.1:9090/v1/approvals/bulk-resolve" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"agent":"claude-code","session":"repo/main","run_id":"run_01J...","action":"approve","resolved_by":"api"}'
```

## GET /v1/rules/auto-allowed
Returns user auto-allow rules persisted in `~/.rampart/policies/auto-allowed.yaml`.

### Request Headers
- `Authorization: Bearer <token>`

### Response Body Schema

```json
{
  "type": "object",
  "required": ["rules"],
  "properties": {
    "rules": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "index": { "type": "integer" },
          "tool": { "type": "string" },
          "command_pattern": { "type": "string" },
          "path_pattern": { "type": "string" },
          "name": { "type": "string" },
          "created": { "type": "string", "format": "date-time" }
        }
      }
    }
  }
}
```

### Status Codes
- `200 OK`
- `401 Unauthorized`
- `500 Internal Server Error`

### curl
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:9090/v1/rules/auto-allowed"
```

## POST /v1/rules/learn
Writes a permanent, exact allow rule to `~/.rampart/policies/user-overrides.yaml`. Used by the OpenClaw plugin for "Always Allow" writeback. Rampart preserves the full approved command or file path and escapes literal glob metacharacters rather than generalizing it. Automatic persistence supports `exec`, `read`, `write`, and `edit`; use an explicit policy for tools whose complete input cannot yet be represented exactly. Rate-limited to ~5 writes/sec.

### Request Headers
- `Authorization: Bearer <token>` (admin scope required)
- `Content-Type: application/json`

### Request Body Schema

```json
{
  "type": "object",
  "required": ["tool", "args", "decision"],
  "properties": {
    "tool":     { "type": "string", "enum": ["exec", "read", "write", "edit"], "example": "exec" },
    "args":     { "type": "string", "description": "Literal command or path to persist exactly", "example": "sudo apt-get install nmap" },
    "decision": { "type": "string", "enum": ["allow"], "description": "Only 'allow' is accepted — use policy YAML for deny rules" },
    "source":   { "type": "string", "description": "Optional origin label for audit trail", "example": "openclaw-approval" }
  }
}
```

### Response Body Schema

```json
{
  "type": "object",
  "properties": {
    "rule_name": { "type": "string", "example": "user-allow-a3f2b1c4" },
    "pattern":   { "type": "string", "example": "sudo apt-get install nmap" },
    "created":   { "type": "boolean" }
  }
}
```

### Status Codes
- `201 Created` — rule written and policy reloaded
- `409 Conflict` — rule already exists (returns existing pattern)
- `400 Bad Request` — invalid request body or decision value
- `401 Unauthorized`
- `429 Too Many Requests` — rate limited

### curl
```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tool":"exec","args":"sudo apt-get install nmap","decision":"allow","source":"manual"}' \
  "http://127.0.0.1:9090/v1/rules/learn"
```

## DELETE /v1/rules/auto-allowed/{index}
Deletes one auto-allowed rule by index and reloads policy engine.

### Request Headers
- `Authorization: Bearer <token>`

### Response Body Schema

```json
{
  "type": "object",
  "required": ["deleted"],
  "properties": {
    "deleted": { "type": "boolean" }
  }
}
```

### Status Codes
- `200 OK`
- `400 Bad Request` invalid index
- `401 Unauthorized`
- `404 Not Found` file missing or index out of range
- `500 Internal Server Error`

### curl
```bash
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:9090/v1/rules/auto-allowed/0"
```

## GET /v1/audit/events
Queries audit events for a date, with filtering and pagination.

### Request Headers
- `Authorization: Bearer <token>`

### Query Parameters
- `date` (`YYYY-MM-DD`, optional, default: current UTC date)
- `limit` (optional, default `50`, max `500`)
- `offset` (optional, event index offset for paged filtered results)
- `tool` (optional)
- `action` (optional)
- `agent` (optional)
- `session` (optional)

### Response Body Schema

```json
{
  "type": "object",
  "required": ["events", "total_in_file", "next_offset", "date"],
  "properties": {
    "events": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "id": { "type": "string" },
          "timestamp": { "type": "string", "format": "date-time" },
          "agent": { "type": "string" },
          "session": { "type": "string" },
          "run_id": { "type": "string" },
          "tool": { "type": "string" },
          "request": { "type": "object", "additionalProperties": true },
          "decision": {
            "type": "object",
            "properties": {
              "action": { "type": "string" },
              "matched_policies": { "type": "array", "items": { "type": "string" } },
              "evaluation_time_us": { "type": "integer" },
              "message": { "type": "string" },
              "suggestions": { "type": "array", "items": { "type": "string" } }
            }
          },
          "prev_hash": { "type": "string" },
          "hash": { "type": "string" }
        }
      }
    },
    "total_in_file": { "type": "integer" },
    "next_offset": { "type": "integer" },
    "date": { "type": "string" }
  }
}
```

### Status Codes
- `200 OK`
- `400 Bad Request` invalid date format
- `401 Unauthorized`
- `503 Service Unavailable` audit directory not configured

### curl
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:9090/v1/audit/events?date=2026-03-03&tool=exec&limit=100"
```

## GET /v1/audit/dates
Lists available audit dates.

### Request Headers
- `Authorization: Bearer <token>`

### Response Body Schema

```json
{
  "type": "object",
  "required": ["dates", "configured"],
  "properties": {
    "dates": { "type": "array", "items": { "type": "string" } },
    "configured": { "type": "boolean" }
  }
}
```

### Status Codes
- `200 OK`
- `401 Unauthorized`
- `500 Internal Server Error`
- `503 Service Unavailable` audit directory not configured

### curl
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:9090/v1/audit/dates"
```

## GET /v1/audit/export
Downloads a day of audit logs as JSONL.

### Request Headers
- `Authorization: Bearer <token>`

### Query Parameters
- `date` (required, `YYYY-MM-DD`)

### Response
- `Content-Type: application/jsonl`
- Body: raw JSONL stream

### Status Codes
- `200 OK`
- `400 Bad Request` missing/invalid `date`
- `401 Unauthorized`
- `404 Not Found` no log for requested date
- `503 Service Unavailable` audit directory not configured

### curl
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:9090/v1/audit/export?date=2026-03-03" \
  -o rampart-audit-2026-03-03.jsonl
```

## GET /v1/audit/stats
Aggregated audit statistics for a date range.

### Request Headers
- `Authorization: Bearer <token>`

### Query Parameters
- `from` (`YYYY-MM-DD`, optional, default current UTC date)
- `to` (`YYYY-MM-DD`, optional, default current UTC date)

### Response Body Schema

```json
{
  "type": "object",
  "required": ["total_events", "by_action", "by_tool", "by_agent", "by_session"],
  "properties": {
    "total_events": { "type": "integer" },
    "by_action": { "type": "object", "additionalProperties": { "type": "integer" } },
    "by_tool": { "type": "object", "additionalProperties": { "type": "integer" } },
    "by_agent": { "type": "object", "additionalProperties": { "type": "integer" } },
    "by_session": { "type": "object", "additionalProperties": { "type": "integer" } }
  }
}
```

### Status Codes
- `200 OK`
- `400 Bad Request` invalid dates or `to < from`
- `401 Unauthorized`
- `503 Service Unavailable` audit directory not configured

### curl
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:9090/v1/audit/stats?from=2026-03-01&to=2026-03-03"
```

## GET /v1/events/stream
Server-Sent Events stream for live updates.

Note: the route is `/v1/events/stream` (not `/v1/events`).

### Authentication
Either:
- `Authorization: Bearer <token>` header, or
- `?token=<token>` query parameter

### Response Headers
- `Content-Type: text/event-stream`
- `Cache-Control: no-cache`
- `X-Accel-Buffering: no`

### Event Format
Each message is sent as SSE `data:` JSON.

Initial connect event:

```text
data: {"type":"connected"}

```

Observed server-emitted event types:

- `{"type":"connected"}`
- `{"type":"approvals"}`
- `{"type":"audit","event":{...audit event...}}`
- `{"type":"audit_batch","run_id":"..."}`

### Status Codes
- `200 OK` stream established
- `401 Unauthorized`
- `500 Internal Server Error` streaming unsupported by writer

### curl
```bash
curl -N -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:9090/v1/events/stream"
```

Query-token variant:

```bash
curl -N "http://127.0.0.1:9090/v1/events/stream?token=$TOKEN"
```

## GET /v1/policy
Alias of `/v1/status`. Returns active runtime policy/config summary.

### Request Headers
- `Authorization: Bearer <token>`

### Response Body Schema

```json
{
  "type": "object",
  "required": ["config_path", "mode", "default_action", "policy_count", "rule_count", "call_counts"],
  "properties": {
    "config_path": { "type": "string" },
    "mode": { "type": "string" },
    "default_action": { "type": "string" },
    "policy_count": { "type": "integer" },
    "rule_count": { "type": "integer" },
    "call_counts": { "type": "object", "additionalProperties": { "type": "integer" } }
  }
}
```

### Status Codes
- `200 OK`
- `401 Unauthorized`

### curl
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:9090/v1/policy"
```

## GET /v1/status
Returns current runtime status and policy counts.

### Request Headers
- `Authorization: Bearer <token>`

### Response
Same schema as `GET /v1/policy`.

### Status Codes
- `200 OK`
- `401 Unauthorized`

### curl
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:9090/v1/status"
```

## GET /v1/policy/summary
Returns transparency-oriented rule summary.

### Request Headers
- `Authorization: Bearer <token>`

### Response Body Schema

```json
{
  "type": "object",
  "required": ["default_action", "rules", "summary"],
  "properties": {
    "default_action": { "type": "string" },
    "rules": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "name": { "type": "string" },
          "action": { "type": "string" },
          "summary": { "type": "string" }
        }
      }
    },
    "summary": { "type": "string" }
  }
}
```

### Status Codes
- `200 OK`
- `401 Unauthorized`

### curl
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:9090/v1/policy/summary"
```

## POST /v1/policy/reload
Forces immediate policy reload.

### Request Headers
- `Authorization: Bearer <token>`

### Request Body
- No body required.

### Response Body Schema
Success (`200`):

```json
{
  "type": "object",
  "required": ["success", "policies_loaded", "rules_total", "reload_time_ms"],
  "properties": {
    "success": { "type": "boolean" },
    "policies_loaded": { "type": "integer" },
    "rules_total": { "type": "integer" },
    "reload_time_ms": { "type": "integer" }
  }
}
```

Failure (`500`):

```json
{
  "success": false,
  "error": "..."
}
```

### Status Codes
- `200 OK`
- `401 Unauthorized`
- `429 Too Many Requests` rate-limited (<1s since previous reload)
- `500 Internal Server Error` reload failed
- `503 Service Unavailable` policy engine not initialized

### curl
```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:9090/v1/policy/reload"
```

## POST /v1/test
Policy REPL endpoint for evaluating a hypothetical command.

### Request Headers
- `Authorization: Bearer <token>`
- `Content-Type: application/json`

### Request Body Schema

```json
{
  "type": "object",
  "required": ["command"],
  "properties": {
    "command": { "type": "string" },
    "tool": { "type": "string", "default": "exec" },
    "agent": { "type": "string" },
    "session": { "type": "string" }
  }
}
```

### Response Body Schema

```json
{
  "type": "object",
  "required": ["command", "tool", "action", "message", "matched_policies", "policy_scope"],
  "properties": {
    "command": { "type": "string" },
    "tool": { "type": "string" },
    "action": { "type": "string" },
    "message": { "type": "string" },
    "matched_policies": { "type": "array", "items": { "type": "string" } },
    "policy_scope": { "type": "string" }
  }
}
```

### Status Codes
- `200 OK`
- `400 Bad Request` invalid JSON or missing `command`
- `401 Unauthorized`
- `503 Service Unavailable` policy engine not initialized

### curl
```bash
curl -X POST "http://127.0.0.1:9090/v1/test" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command":"git status","tool":"exec"}'
```

## GET /healthz
Unauthenticated health check.

### Request Headers
- None required

### Response Body Schema

```json
{
  "type": "object",
  "required": ["status", "mode", "uptime_seconds", "version"],
  "properties": {
    "status": { "type": "string" },
    "mode": { "type": "string" },
    "uptime_seconds": { "type": "integer" },
    "version": { "type": "string" }
  }
}
```

### Status Codes
- `200 OK`

### curl
```bash
curl "http://127.0.0.1:9090/healthz"
```

## GET /metrics
Prometheus metrics endpoint. Available only when server starts with metrics enabled.

### Request Headers
- `Authorization: Bearer <token>`

### Response
- `Content-Type`: Prometheus text exposition format
- Includes Rampart metrics and Go/process collectors

Primary Rampart metrics:

- `rampart_decisions_total{action="...",policy="..."}` (counter)
- `rampart_eval_duration_seconds` (histogram)
- `rampart_pending_approvals` (gauge)
- `rampart_policy_count` (gauge)
- `rampart_uptime_seconds` (gauge)

### Status Codes
- `200 OK`
- `401 Unauthorized`
- `404 Not Found` when metrics endpoint is disabled

### curl
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:9090/metrics"
```

## Dashboard and Other Routes

## GET /dashboard
Redirects to `/dashboard/`.

### Status Codes
- `301 Moved Permanently`

### curl
```bash
curl -i "http://127.0.0.1:9090/dashboard"
```

## GET /dashboard/
Serves Rampart dashboard UI assets.

### Status Codes
- `200 OK`

### curl
```bash
curl -i "http://127.0.0.1:9090/dashboard/"
```

## Any unmatched route
Returns JSON 404.

### Response

```json
{
  "error": "not found"
}
```

### Status Codes
- `404 Not Found`

## SSE Operational Notes
- Keep SSE clients long-lived (`curl -N`, EventSource, or equivalent).
- Treat events as notifications and re-query authoritative endpoints (`/v1/approvals`, `/v1/audit/events`) when needed.
- `audit_batch` indicates multiple audit updates (used after bulk approval resolve).

## Security Notes
- Keep `~/.rampart/token` permissions restrictive (owner read/write).
- Prefer header-based bearer auth over query parameters; use `?token=` only where header injection is not possible (for SSE clients).
- Signed resolve URLs (`sig`/`exp`) should be considered sensitive and short-lived.
