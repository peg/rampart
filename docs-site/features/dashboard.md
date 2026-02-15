# Approval Dashboard

Rampart includes an embedded web dashboard for managing `require_approval` decisions. View pending approvals, approve or deny them, and review decision history — all from your browser.

## Accessing the Dashboard

The dashboard is available on both `rampart serve` and `rampart daemon`:

```bash
# Start the server
rampart serve --config ~/.rampart/policies/my-policy.yaml --port 9090

# Dashboard is at:
# http://localhost:9090/dashboard/
```

## Authentication

The dashboard HTML is served without authentication — it contains no secrets. All data is fetched from the `/v1/approvals` API, which requires a Bearer token.

When `rampart serve` starts, it prints the token:

```
serve: full token: 22ae11b1b9b51c5c7c71dd4a74f44b2ea429cdebc31dda59ad7b8f2dc927b9b7
```

Enter this token in the dashboard's token field. It's stored in your browser's `localStorage` — never sent to any external service.

## Features

- **Pending approvals**: See all `require_approval` decisions waiting for human input
- **Approve / Deny**: Click to resolve approvals directly from the browser
- **History**: View past decisions with timestamps, agents, commands, and who resolved them
- **Auto-refresh**: Dashboard polls for new approvals automatically

## Security Model

| Component | Auth Required? | Notes |
|-----------|---------------|-------|
| Dashboard HTML/CSS/JS | No | Static files, no embedded secrets |
| `GET /v1/approvals` | Yes (Bearer token) | Lists pending and resolved approvals |
| `POST /v1/approvals/{id}/resolve` | Yes (Bearer OR signed URL) | Resolves a pending approval |

**Signed URLs**: When webhooks fire for `require_approval`, the notification includes a self-authenticating signed URL. Recipients can approve/deny by clicking the link without needing the Bearer token.

## Network Access

By default, `rampart serve` binds to `0.0.0.0` — accessible from your local network. For remote access:

- **Tailscale**: Bind to your Tailscale IP for secure access without exposing to the internet
- **Reverse proxy**: Put nginx/Caddy in front with your own auth
- **Localhost only**: Use `--port 127.0.0.1:9090` to restrict to local access

!!! warning
    The dashboard token grants full approval authority. Treat it like a password. Don't expose the port to the public internet without additional authentication.

## API Reference

The dashboard uses the same REST API available to any client:

```bash
# List approvals
curl http://localhost:9090/v1/approvals \
  -H "Authorization: Bearer $TOKEN"

# Approve
curl -X POST http://localhost:9090/v1/approvals/APPROVAL_ID/resolve \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"approved": true, "resolved_by": "trevor"}'

# Deny
curl -X POST http://localhost:9090/v1/approvals/APPROVAL_ID/resolve \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"approved": false, "resolved_by": "trevor", "reason": "not authorized"}'
```

## Integration with Hooks

When Claude Code triggers a `require_approval` policy, the flow is:

1. Hook returns `permissionDecision: "ask"` — Claude Code shows native approval prompt
2. Approval is also created in the server's approval store
3. Dashboard shows the pending approval
4. Webhooks fire (if configured) with signed approve/deny URLs

The first resolution wins — whether from Claude Code's prompt, the dashboard, a webhook link, or the API.
