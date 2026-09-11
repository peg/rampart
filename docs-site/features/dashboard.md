---
title: Approval Dashboard
description: "Use Rampart's approval dashboard to review and decide risky AI agent actions in real time. Approve, deny, and audit every pending command from one view."
---

# Approval Dashboard

Rampart includes an embedded web dashboard for managing approval-gated decisions. View pending approvals, approve or deny them, and review decision history — all from your browser.

## Accessing the Dashboard

The dashboard is available when running `rampart serve`:

```bash
# Start the server
rampart serve --config ~/.rampart/policies/my-policy.yaml --port 9090

# Dashboard is at:
# http://localhost:9090/dashboard/
```

## Authentication

The dashboard HTML is served without authentication — it contains no secrets. All data is fetched from the `/v1/approvals` API, which requires a Bearer token.

An interactive `rampart serve` can display the bootstrap token. Background
and redirected service output omit the full token. Retrieve it in your own
terminal with `rampart token`, then enter it in the dashboard. Keep it out of
shared logs, screenshots, and agent prompts.

The browser stores it in `localStorage` for that origin and sends it to the
configured Rampart service to authenticate requests.

### Admin Scope vs. Eval Scope

Rampart credentials carry explicit scopes:

- **Bootstrap admin token** — persisted in `~/.rampart/token`. It carries
  admin scope and can access all dashboard APIs.
- **Named tokens** — created with `rampart token create <name>`. They can carry
  eval scope, admin scope, or both, plus optional policy profiles.

Only a credential carrying admin scope can read or resolve dashboard
approvals. Eval-only credentials are rejected by the approval and other admin
APIs; they cannot turn an agent's own request into operator authorization.

## Features

- **Pending approvals**: See all approval-gated decisions waiting for human input
- **Approve / Deny**: Resolve only the exact pending approvals shown in the confirmation
- **Explicit run grants**: Separately authorize future calls for the exact
  agent/session/run and credential-owner scope for the duration shown in the confirmation
- **History**: View past decisions with timestamps, agents, commands, and who resolved them
- **Auto-refresh**: Dashboard polls for new approvals automatically

## Security Model

| Component | Auth Required? | Notes |
|-----------|---------------|-------|
| Dashboard HTML/CSS/JS | No | Static files, no embedded secrets |
| `GET /v1/approvals` | Yes (admin-scoped Bearer) | Lists pending approvals and safe run groupings |
| `POST /v1/approvals/{id}/resolve` | Yes (admin-scoped Bearer or signed URL) | Resolves one pending approval |
| `POST /v1/approvals/bulk-resolve` | Yes (admin-scoped Bearer) | Requires exact reviewed IDs and an explicit scope; `scope: "run"` grants future-call authority |

**Signed URLs**: When webhooks fire for approval-gated decisions, the notification includes a self-authenticating signed URL. Recipients can approve/deny by clicking the link without needing the Bearer token.

## Network Access

By default, `rampart serve` binds to `127.0.0.1` (localhost only). Keep that
binding for local use. Non-loopback bindings require TLS or a trusted HTTPS
reverse proxy; an address alone does not establish a protected remote service.
See the [CLI reference](../reference/cli-commands.md) for `--tls-cert`,
`--tls-key`, and `--tls-auto`.

The dashboard token grants approval authority. Restrict access to the service
and its credentials. Signed approval links likewise carry authority for the
associated request and must stay private to intended reviewers.

## API Reference

For authenticated request and response formats, see the canonical
[approval API reference](../reference/api-reference.md).

## Integration with Hooks

The dashboard resolves requests owned by Rampart's external approval queue,
including Codex and Cursor hook requests. The waiting integration consumes the
result; the dashboard itself does not execute the tool.

Claude Code's ordinary `ask` returns `permissionDecision: "ask"` and Claude
owns the native prompt and resume. With `ask.audit: true`, the hook can mirror
pending review data to the service and correlate later host events on a
best-effort basis. Resolving that mirrored entry does not resume or cancel the
native prompt. Claude's explicit `ask.headless_only` path instead waits on the
external queue; see [Native Ask](../guides/native-ask.md).

OpenClaw native plugin approvals are owned by OpenClaw and do not create a
second Rampart pending request. Consult
[approval paths and limits](../getting-started/support-matrix.md#approval-paths-and-limits)
for other integrations.
