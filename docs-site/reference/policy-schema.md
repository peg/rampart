# Policy Schema

Complete YAML reference for Rampart policy files.

## Top-Level Structure

```yaml
version: "1"              # Required. Always "1".
default_action: allow      # Required. "allow" or "deny".

notify:                    # Optional. Webhook notifications.
  url: "https://..."
  platform: "auto"         # Optional. "auto", "slack", "discord", "teams", "openclaw", "webhook".
  on: ["deny"]

policies:                  # Required. List of policy objects.
  - name: my-policy
    # ...
```

## Policy Object

```yaml
policies:
  - name: string           # Required. Unique identifier.
    priority: integer       # Optional. Lower = evaluated first. Default: 100.
    enabled: boolean        # Optional. Default: true. Set false to disable without removing.
    match:
      tool: string | list   # Required. Tool type(s) to match.
      agent: string          # Optional. Glob pattern for agent identity. Default: "*".
    rules:                  # Required. List of rule objects.
      - # ...
```

### `match.tool`

Which tool types this policy applies to:

| Value | Matches |
|-------|---------|
| `"exec"` | Shell commands |
| `"read"` | File read operations |
| `"write"` | File write/edit operations |
| `"fetch"` | HTTP/network requests |
| `"mcp-destructive"` | MCP tools with destructive keywords |
| `"mcp-dangerous"` | MCP tools with dangerous keywords |
| `"mcp__server__tool"` | Specific MCP tool by name |

Can be a string or a list:

```yaml
match:
  tool: "exec"           # Single tool
  tool: ["exec", "read"] # Multiple tools
```

## Rule Object

```yaml
rules:
  - action: string         # Required. deny | allow | log | require_approval | webhook
    when:                   # Optional. Conditions (omit for unconditional).
      command_matches: list
      command_not_matches: list
      path_matches: list
      path_not_matches: list
      url_matches: list
      domain_matches: list
      response_matches: list
      response_not_matches: list
      default: boolean          # Catch-all — matches when true
    message: string         # Optional. Reason shown on deny.
    webhook:                # Required when action is "webhook".
      url: string
      timeout: duration
      fail_open: boolean
```

### `action`

| Action | Effect |
|--------|--------|
| `deny` | Block the tool call. **Deny always wins.** |
| `allow` | Permit the tool call. |
| `log` | Permit but flag for review. |
| `require_approval` | Block until human approves/denies. |
| `webhook` | Delegate decision to external HTTP endpoint. |

### Conditions (`when`)

All conditions use **glob patterns**:

| Glob | Meaning |
|------|---------|
| `*` | Any characters (single segment) |
| `**` | Any characters (crosses `/`) |
| `?` | Any single character |

#### `command_matches`

Match against the command string for `exec` tools:

```yaml
when:
  command_matches:
    - "rm -rf *"
    - "sudo *"
    - "*curl*webhook.site*"
```

#### `path_matches` / `path_not_matches`

Match against file paths for `read`/`write` tools:

```yaml
when:
  path_matches:
    - "**/.ssh/id_*"
    - "**/.aws/credentials"
  path_not_matches:
    - "**/*.pub"        # Exclude public keys
```

#### `domain_matches`

Match against domains for `fetch` tools:

```yaml
when:
  domain_matches:
    - "*.ngrok-free.app"
    - "webhook.site"
```

#### `response_matches`

Match against tool output (regex patterns):

```yaml
when:
  response_matches:
    - "AKIA[0-9A-Z]{16}"                           # AWS key
    - "-----BEGIN (RSA |EC )?PRIVATE KEY-----"      # Private key
    - "ghp_[a-zA-Z0-9]{36}"                        # GitHub PAT
```

### Webhook Configuration

When `action: webhook`:

```yaml
webhook:
  url: "http://localhost:8090/verify"  # Required. Endpoint URL.
  timeout: "5s"                         # Optional. Default: 5s.
  fail_open: true                       # Optional. Default: true.
```

## Notify Object

```yaml
notify:
  url: "https://discord.com/api/webhooks/..."  # Required. Webhook URL.
  platform: "auto"                             # Optional. Platform-specific formatting.
  on: ["deny", "require_approval"]             # Required. Event types.
```

### Events

| Event | When |
|-------|------|
| `"deny"` | A tool call was blocked |
| `"log"` | A tool call was flagged |
| `"require_approval"` | A tool call requires human approval |

### Platforms

| Platform | Auto-detected for | Description |
|----------|-------------------|-------------|
| `"auto"` | Any URL | Auto-detect based on URL |
| `"slack"` | hooks.slack.com | Slack webhook format |
| `"discord"` | discord.com/api/webhooks | Discord webhook format |
| `"teams"` | webhook.office.com | Microsoft Teams format |
| `"openclaw"` | openclaw.dev/ai/io | OpenClaw notification format |
| `"webhook"` | Other URLs | Generic JSON webhook |

## Evaluation Rules

1. **Deny always wins** — if any policy denies, the call is denied
2. **First match within a policy** — rules evaluate top-to-bottom, first match wins
3. **Priority ordering** — lower priority number = evaluated first
4. **No match** → `default_action` applies

## Complete Example

```yaml
version: "1"
default_action: allow

notify:
  url: "https://discord.com/api/webhooks/your/webhook"
  on: ["deny"]

policies:
  - name: block-destructive
    priority: 1
    match:
      tool: ["exec"]
    rules:
      - action: deny
        when:
          command_matches:
            - "rm -rf /"
            - "rm -rf ~"
            - "mkfs*"
            - "dd if=*"
        message: "Destructive command blocked"

  - name: protect-credentials
    priority: 1
    match:
      tool: ["read"]
    rules:
      - action: deny
        when:
          path_matches: ["**/.ssh/id_*", "**/.aws/credentials", "**/.env"]
          path_not_matches: ["**/*.pub"]
        message: "Credential access blocked"

  - name: block-exfil
    priority: 2
    match:
      tool: ["fetch"]
    rules:
      - action: deny
        when:
          domain_matches: ["*.ngrok-free.app", "webhook.site"]
        message: "Exfiltration domain blocked"

  - name: log-network
    priority: 10
    match:
      tool: ["exec"]
    rules:
      - action: log
        when:
          command_matches: ["curl *", "wget *"]
        message: "Network command logged"

  - name: approve-deploys
    match:
      tool: ["exec"]
    rules:
      - action: require_approval
        when:
          command_matches: ["kubectl apply *"]
        message: "Deployment requires approval"
```
