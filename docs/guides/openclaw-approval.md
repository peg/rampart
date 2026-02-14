# OpenClaw Approval Flow

## Overview

Rampart and OpenClaw can work together to enforce human-in-the-loop control for risky agent actions.

- Rampart evaluates tool calls against policy.
- When a rule returns `require_approval`, Rampart returns `202 Accepted` plus an `approval_id`.
- Rampart sends a notification webhook to chat (Discord/Slack/OpenClaw webhook).
- A human approves or denies in chat through OpenClaw.
- OpenClaw resolves the pending Rampart approval via the resolve API, then the shim can continue.

## Architecture

```text
Agent → Rampart Shim → Rampart HTTP API → require_approval
                                        → 202 + approval_id
                                        → webhook fires to Discord/Slack
                                        → OpenClaw receives notification
                                        → User approves in chat
                                        → OpenClaw calls resolve API
                                        → Shim unblocks → command executes
```

## Configuration Example

```yaml
# rampart.yaml
notify:
  url: "https://discord.com/api/webhooks/..."
  platform: discord
  on: [deny, require_approval]

policies:
  - name: dangerous-commands
    tools: [exec]
    command_matches: ["^(rm|terraform|kubectl delete)"]
    action: require_approval
    message: "Requires human approval"
```

## OpenClaw Integration

OpenClaw can act as the chat-side resolver:

- Rampart webhook includes `approval_id`, `resolve_url`, and `expires_at`.
- OpenClaw surfaces the event to the operator in chat.
- When the operator approves/denies, OpenClaw calls Rampart's resolve API.
- Rampart marks the approval resolved, and the waiting shim/request can continue (approved) or fail (denied).

## Resolve API Examples

```bash
# Approve
curl -X POST http://localhost:9091/v1/approvals/{id}/resolve \
  -H "Content-Type: application/json" \
  -d '{"approved": true, "resolved_by": "trevor@discord"}'

# Deny
curl -X POST http://localhost:9091/v1/approvals/{id}/resolve \
  -H "Content-Type: application/json" \
  -d '{"approved": false, "resolved_by": "trevor@discord"}'
```
