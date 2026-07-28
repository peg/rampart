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
