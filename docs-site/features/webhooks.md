---
title: Webhook Notifications
description: "Send Rampart deny and approval events to Slack, Discord, Teams, or any webhook. Get immediate alerts when AI agents attempt risky commands or access."
---

# Webhook Notifications

Get real-time alerts when Rampart blocks something. Works with Discord, Slack, Teams, or any HTTP endpoint.

## Setup

Add a `notify` section to your policy file:

```yaml
version: "1"
default_action: allow

notify:
  url: "https://discord.com/api/webhooks/your/webhook"
  on: ["deny", "ask"]  # Notify on blocked and pending approval

policies:
  # ... your policies
```

### Notification Triggers

| Value | When |
|-------|------|
| `deny` | A tool call was blocked |
| `watch` | A tool call was flagged for review (`log` remains a legacy alias) |
| `ask` | A tool call needs human approval |

Long-running Rampart services deliver notifications asynchronously. Native
one-shot hooks wait for delivery with a one-second network timeout so the hook
process cannot exit before sending, while a slow webhook cannot consume the
agent host's full hook timeout.

Notification delivery is best-effort and is never an authorization dependency.
Long-running services bound concurrent deliveries and drop excess alerts with
a local warning rather than accumulating unbounded work. Rampart redacts common
credential shapes from the `command` field before delivery, but no redactor can
recognize every application-specific secret; treat the configured endpoint as
trusted for the event data you choose to send.

## Payload Format

Rampart sends a JSON POST to your webhook URL:

```json
{
  "timestamp": "2026-02-11T21:03:38Z",
  "action": "deny",
  "tool": "exec",
  "command": "rm -rf /tmp/*",
  "policy": "protect-sys",
  "message": "Destructive command blocked",
  "agent": "claude-code"
}
```

`command` is the redacted command, path or URL. For a call through
`rampart mcp`, `tool` is the policy tool type such as `mcp` or
`mcp-destructive`, and `command` starts with the MCP server's tool name, for
example `delete_repo — org/repo`. That name comes from the agent and MCP
server.

### Approval links

When `rampart serve` creates a pending approval, the notification also carries
`approval_id`, `expires_at`, and a signed `resolve_url`. Opening that link shows
a small confirmation page with the redacted request and **Approve** and
**Deny** buttons. Opening or previewing the link never decides the request;
only pressing a button does, once. The link expires with the approval and
cannot make a permanent allow rule.

The link points at `localhost` unless you set `--resolve-base-url`, so it works
only on the machine running `serve`. To approve from a phone or another
computer, expose `serve` over TLS or a trusted HTTPS reverse proxy and set
`--resolve-base-url` to that address. Anyone who has the link can decide that
request, so send approval notifications only to channels limited to reviewers.

`rampart mcp` in enforce mode leaves approval notifications to `serve`, so an
ask produces one notification with its link. `serve` notifies from the
`notify:` block of its own policy. If `serve` queues the approval without
notifying (for example, its policy has no `notify:` block), the proxy sends an
`ask` notification without a link from the `notify:` block of the policy
`rampart mcp` loaded, and the call still waits in the queue. If the approval
cannot reach `serve` (for example, `serve` is not running), the call is denied
and the proxy sends the same plain notification. The proxy sends `ask`
notifications only when its `on:` list includes `ask`.

## Platform Examples

=== "Discord"

    ```yaml
    notify:
      url: "https://discord.com/api/webhooks/1234567890/abcdef..."
      on: ["deny"]
    ```

=== "Slack"

    ```yaml
    notify:
      url: "https://hooks.slack.com/services/T00/B00/xxxx"
      on: ["deny"]
    ```

=== "Teams"

    ```yaml
    notify:
      url: "https://outlook.office.com/webhook/..."
      on: ["deny"]
    ```

=== "Custom"

    ```yaml
    notify:
      url: "https://your-api.example.com/rampart-events"
      on: ["deny", "watch"]
    ```

## Webhook Actions

For more advanced use cases, delegate allow/deny decisions to an external service:

```yaml
rules:
  - action: webhook
    when:
      command_matches: ['*production*']
    webhook:
      url: 'http://localhost:8090/verify'
      timeout: 5s
      fail_open: true
```

The webhook receives the full tool call context and returns:

```json
{"decision": "allow"}
// or
{"decision": "deny", "reason": "Production deployment not approved"}
```

Webhook actions **fail closed by default**: an unavailable, invalid, or timed-out
decision endpoint denies the tool call. Set `fail_open: true` explicitly only
when availability is more important than enforcing that rule.

See [Semantic Verification](semantic-verification.md) for an LLM-powered webhook implementation.
