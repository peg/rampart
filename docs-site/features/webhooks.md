# Webhook Notifications

Get real-time alerts when Rampart blocks something. Works with Discord, Slack, Teams, or any HTTP endpoint.

## Setup

Add a `notify` section to your policy file:

```yaml
version: "1"
default_action: allow

notify:
  url: "https://discord.com/api/webhooks/your/webhook"
  on: ["deny"]  # Only notify on denied commands

policies:
  # ... your policies
```

### Notification Triggers

| Value | When |
|-------|------|
| `deny` | A tool call was blocked |
| `log` | A tool call was flagged for review |

## Payload Format

Rampart sends a JSON POST to your webhook URL:

```json
{
  "timestamp": "2026-02-11T21:03:38Z",
  "decision": "deny",
  "tool": "exec",
  "command": "rm -rf /tmp/*",
  "policy": "protect-sys",
  "message": "Destructive command blocked",
  "agent": "claude-code",
  "session": "abc123"
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
      on: ["deny", "log"]
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

**Fail-open by default** — a down webhook doesn't break your agent.

See [Semantic Verification](semantic-verification.md) for an LLM-powered webhook implementation.
