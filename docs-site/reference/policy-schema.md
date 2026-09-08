---
title: Policy Schema
description: "Learn the Rampart YAML policy schema for exec, read, write, fetch, and notify rules. Build precise AI agent security guardrails with clear examples."
---

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
| `"mcp"` | MCP tools not otherwise classified |
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
  - action: string         # Required. deny | allow | log/watch | ask | webhook
    when:                   # Optional. Conditions (omit for unconditional).
      command_matches: list
      command_not_matches: list
      command_contains: list
      path_matches: list
      path_not_matches: list
      url_matches: list
      domain_matches: list
      session_matches: list
      session_not_matches: list
      agent_depth:
        gte: integer
        lte: integer
        eq: integer
      tool_param_matches: map[string]string
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
| `watch` | Permit but flag for review. `log` remains a deprecated alias. |
| `ask` | Request human approval through the active integration; unsupported approval paths fail closed. |
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

Restrictive rules (`deny` and `ask`) also recognize limited equivalent command
forms. A literal HTTP(S) download to a file followed by execution of that same
file in one represented POSIX command is matched as `curl URL | sh` or
`wget URL | sh`. This lets the standard supply-chain rule cover both piped and
file-backed execution. The original command remains the approval and audit
identity; this interpretation never grants an `allow` or `watch` rule.

The file correlation recognizes explicit curl `-o`/`--output`, wget
`-O`/`--output-document`, and stdout file redirects, including quoted paths and
attached option values. It covers sequential `;`, `&&`, `||` and newline
components, literal shell `-c` bodies, and the existing transparent executor
forms that do not change working directory or retokenize arguments. Execution
means a literal shell/source/script operand, interpreter stdin, or an explicit
executable path. Supported script interpreters are POSIX shells, `python`,
`python3`, `node`, `ruby` and `perl`; inline programs and module arguments are
not treated as script filenames.

This is not shell dataflow analysis. It does not infer filenames from URLs,
resolve variables or symlinks, inspect program contents, or correlate separate
tool calls. The file detector skips here documents, pipelines/background jobs,
unknown download options, and directory-changing `env` wrappers. Other policy
rules still evaluate those commands. Literal path comparison preserves `..`
because collapsing it could identify a different file through a symlink.
Grouping, function definitions, and conditional/loop grammar are also outside
this detector. Known shell truncations invalidate an earlier file correlation,
including redirections on shell wrappers or commands with opaque arguments.
Shared wget outputs and stdout streams retain each contributing HTTP(S) source.
Intervening effects inside programs remain unobserved.

Restrictive rules also recognize the explicitly supported infrastructure and
migration CLI forms described in [Production Guard](../guides/production-guard.md).
Those aliases consume known option operands and retain literal target identity;
they do not authorize commands or resolve an environment from configuration.

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

#### `agent_depth`

Match nested sub-agent depth (`0` = top-level agent, `1+` = sub-agents):

```yaml
when:
  agent_depth:
    gte: 1
    lte: 2
```

Exact match:

```yaml
when:
  agent_depth:
    eq: 0
```

#### `tool_param_matches`

Match MCP tool input parameters by case-insensitive glob pattern.
Keys are parameter names, values are glob patterns. Rule matches if any
parameter condition matches.

```yaml
when:
  tool_param_matches:
    path: "**/.env*"
    url: "*webhook.site*"
```

#### `call_count`

Sliding-window rate limiting for tool calls. Rampart increments the counter on every `PreToolUse` event.

```yaml
when:
  call_count:
    tool: fetch    # optional, omit for all tools
    gte: 100       # trigger threshold
    window: 1h     # sliding window (1h, 30m, 10m, 5m, 1m)
```

### Webhook Configuration

When `action: webhook`:

```yaml
webhook:
  url: "http://localhost:8090/verify"  # Required. Endpoint URL.
  timeout: "5s"                         # Optional. Default: 5s.
  fail_open: false                      # Optional. Default: false (fail closed).
```

## Notify Object

```yaml
notify:
  url: "https://discord.com/api/webhooks/..."  # Required. Webhook URL.
  platform: "auto"                             # Optional. Platform-specific formatting.
  on: ["deny", "ask"]                         # Optional. Event types.
```

### Events

| Event | When |
|-------|------|
| `"deny"` | A tool call was blocked |
| `"watch"` | A tool call was flagged (`"log"` is a legacy alias) |
| `"ask"` | A tool call requires human approval (`"require_approval"` remains a notification-filter alias) |

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
      - action: watch
        when:
          command_matches: ["curl *", "wget *"]
        message: "Network command logged"

  - name: ask-deploys
    match:
      tool: ["exec"]
    rules:
      - action: ask
        when:
          command_matches: ["kubectl apply *"]
        message: "Deployment requires approval"
```
