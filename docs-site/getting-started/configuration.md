---
title: Configuration
description: "Configure Rampart runtime defaults and YAML policies. Set service URLs cleanly, then tune what AI agents can execute, read, write, and fetch."
---

# Configuration

Rampart has **two kinds of configuration**:

1. **Runtime/client config** — where Rampart should find its local service
2. **Policy config** — what agents are allowed to do once Rampart evaluates a tool call

Most users only need one runtime setting:

```yaml
# ~/.rampart/config.yaml
url: http://127.0.0.1:9090
```

## Runtime Config (`~/.rampart/config.yaml`)

If you do not want to keep exporting environment variables, Rampart can load persistent local defaults from `~/.rampart/config.yaml`.

```yaml
url: http://127.0.0.1:9090
# serve_url: http://127.0.0.1:9090   # compatibility alias for url
# api: http://127.0.0.1:9091         # optional advanced override for daemon/split-topology API setups
```

| Setting | Use it for | Notes |
|--------|-------------|-------|
| `url` | Primary Rampart base URL | Canonical setting for hook, watch, plugin, and service-backed flows |
| `serve_url` | Backwards-compatible alias for `url` | Kept for compatibility; prefer `url` in new configs |
| `api` | Optional API base URL override for approval/control commands | Advanced only; usually unnecessary unless you split the API away from the main serve endpoint |

### Resolution order

Rampart resolves service addresses in this order:

**flag → environment → config file → auto-discovered state → default**

That means:

- `--api` or `--serve-url` wins when you pass it explicitly
- environment variables such as `RAMPART_URL`, `RAMPART_SERVE_URL`, and `RAMPART_API` override file values
- `~/.rampart/config.yaml` is the persistent local default
- if nothing is configured, Rampart falls back to discovered local state and then localhost defaults

### Which setting should I use?

Use **`url`** unless you have a specific reason not to.

- `url` is the normal setting for local Rampart service discovery
- `serve_url` exists for compatibility with older setups
- `api` is **not** the normal `rampart serve` setting — it is an advanced client-side override for approval/control flows

!!! info "Two different meanings of `--api`"
    Client-side `--api` flags expect an **API base URL** such as `http://127.0.0.1:9091`.

    Daemon/server `--api` flags refer to an **API listen address** such as `127.0.0.1:9091`.

## Policy File Location

Rampart policies are YAML files that define what your AI agent can and can't do. Policies are evaluated in microseconds and hot-reload when you edit them.

By default, Rampart looks for policies in `~/.rampart/policies/`. You can specify a custom location:

```bash
rampart serve --config /path/to/policy.yaml
rampart wrap --config /path/to/policy.yaml -- agent
```

## Basic Structure

```yaml
version: "1"
default_action: allow  # allow | deny | ask | watch

policies:
  - name: my-policy
    match:
      tool: ["exec"]  # Which tool types this applies to
    rules:
      - action: deny  # deny | allow | ask | watch | webhook
        when:
          command_matches: ["rm -rf *"]
        message: "Destructive command blocked"
```

## Actions

| Action | Effect |
|--------|--------|
| `deny` | Block the tool call. Agent receives an error. |
| `allow` | Permit the tool call. |
| `watch` | Permit but log with elevated visibility. (Previously called `log` — `log` still works as an alias.) |
| `ask` | Block until a human approves or denies. Also valid as `default_action: ask` to surface unmatched calls for review. |
| `webhook` | Delegate the decision to an external HTTP endpoint. |

**Deny always wins.** If any matching policy says `deny`, the call is denied regardless of other policies.

## Tool Types

Rampart recognizes four tool types:

| Tool | What It Matches |
|------|----------------|
| `exec` | Shell commands (Bash, terminal) |
| `read` | File read operations |
| `write` | File write/edit operations |
| `fetch` | HTTP requests, network operations |

For MCP tools, the tool name from the MCP `tools/call` is used directly (e.g., `mcp__filesystem__read_file`).

## Matching Rules

### Command Matching

```yaml
rules:
  - action: deny
    when:
      command_matches:
        - "rm -rf *"        # Glob pattern
        - "mkfs.*"           # Filesystem format
        - "dd if=*"          # Raw disk write
        - ":(){ :|:& };:"   # Fork bomb
```

### Path Matching

```yaml
rules:
  - action: deny
    when:
      path_matches:
        - "**/.ssh/id_*"         # SSH private keys
        - "**/.aws/credentials"  # AWS credentials
        - "**/.env"              # Environment files
      path_not_matches:
        - "**/*.pub"             # Exclude public keys
```

### URL Matching

Match the full request URL for `fetch` tool calls. Useful when you need more precision than domain matching — for example, to allow a domain but restrict specific paths:

```yaml
rules:
  - action: deny
    when:
      url_matches:
        - "https://api.example.com/admin/*"   # Block admin endpoints
        - "http://*/*"                          # Block non-HTTPS requests
        - "https://*/v1/secrets*"              # Block any host's secrets path
```

Use `domain_matches` when you only care about the hostname; use `url_matches` when path, scheme, or query matter.

### Session Matching

Filter rules by session identity — the repo path, branch, or project label Rampart associates with the current run. Useful for per-project policies without separate YAML files:

```yaml
rules:
  - action: deny
    when:
      session_matches:
        - "*/production"      # Any repo on the production branch
        - "infra-*"           # Sessions labelled infra-*
  - action: allow
    when:
      session_not_matches:
        - "*/main"            # Exclude main branch from this rule
```

Sessions are set by the agent integration (Claude Code sets them from the project path; MCP proxy uses the client-provided session ID).

### Tool Parameter Matching

Match arbitrary MCP tool input parameters by name and glob pattern. Each key is a parameter name; any matching parameter triggers the rule (OR logic across params):

```yaml
rules:
  - action: deny
    when:
      tool_param_matches:
        path: "**/.env*"           # deny if the "path" param targets .env files
        url: "*webhook.site*"      # deny if the "url" param points to webhook.site
```

This is particularly useful for MCP tools where the tool name alone doesn't give enough context — for example, a generic `file_read` MCP tool where you want to restrict specific path arguments.

### Domain Matching

```yaml
rules:
  - action: deny
    when:
      domain_matches:
        - "*.ngrok-free.app"
        - "*.requestbin.com"
        - "webhook.site"
```

### Response Matching

Scan tool output for sensitive patterns:

```yaml
rules:
  - action: deny
    when:
      response_matches:
        - "AKIA[0-9A-Z]{16}"                          # AWS access key
        - "-----BEGIN (RSA )?PRIVATE KEY-----"         # Private keys
        - "ghp_[a-zA-Z0-9]{36}"                       # GitHub PAT
```

## Rate Limiting

Use `call_count` to trigger a rule when a tool is invoked more than N times in a sliding time window. Useful for capping runaway agents or limiting expensive operations:

```yaml
rules:
  - action: ask
    when:
      call_count:
        gte: 50       # Threshold: 50 or more calls...
        window: 10m   # ...within the last 10 minutes
    message: "High fetch volume — pausing for review"

  - action: deny
    when:
      call_count:
        tool: fetch   # Optional: count only fetch calls (omit for all tools)
        gte: 200
        window: 1h
    message: "Fetch rate limit exceeded"
```

`window` accepts standard duration strings: `1h`, `30m`, `10m`, `5m`, `1m`. The counter increments on every `PreToolUse` event and resets as calls age out of the window.

## Priority

Lower priority number = evaluated first. Use priority to ensure critical rules run before general ones:

```yaml
policies:
  - name: critical-blocks
    priority: 1           # Evaluated first
    match:
      tool: ["exec"]
    rules:
      - action: deny
        when:
          command_matches: ["rm -rf /"]

  - name: general-logging
    priority: 10          # Evaluated later
    match:
      tool: ["exec"]
    rules:
      - action: log       # Renamed to action: watch in v0.9.x.
        when:
          command_matches: ["curl *"]
```

## Approval Flow

For commands that aren't dangerous enough to block outright, but risky enough for a human to decide:

```yaml
policies:
  - name: approve-deployments
    match:
      tool: ["exec"]
    rules:
      - action: ask
        when:
          command_matches:
            - "kubectl apply *"
            - "terraform apply *"
            - "docker push *"
            - "helm upgrade *"
        message: "Deployment — approve or deny?"

  - name: approve-installs
    match:
      tool: ["exec"]
    rules:
      - action: ask
        when:
          command_matches:
            - "pip install *"
            - "npm install *"
            - "brew install *"
        message: "Package install — approve or deny?"
```

How you'll see the approval prompt depends on your setup:

- **Claude Code** — native permission dialog (the same one Claude uses for `ask`)
- **MCP clients** — the proxy blocks until you approve via CLI or API
- **OpenClaw** — sends a chat message you can approve inline
- **Webhooks** — sends a notification with a signed approve/deny link

Manage pending approvals:

```bash
rampart pending                          # What's waiting
rampart approve abc123                   # Let it through
rampart deny abc123 --reason "not now"   # Block it
```

## Webhook Notifications

Get alerts when commands are blocked or need approval:

```yaml
version: "1"
default_action: allow

notify:
  url: "https://discord.com/api/webhooks/your/webhook"
  on: ["deny", "ask"]  # Options: deny, log, ask

policies:
  # ... your policies
```

## Example: Standard Policy

A sensible default that blocks destructive commands and credential access:

```yaml
version: "1"
default_action: allow

policies:
  - name: block-destructive
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
            - "chmod -R 777 /"
        message: "Destructive command blocked"

  - name: block-credential-access
    match:
      tool: ["read"]
    rules:
      - action: deny
        when:
          path_matches:
            - "**/.ssh/id_*"
            - "**/.aws/credentials"
            - "**/.env"
          path_not_matches:
            - "**/*.pub"
        message: "Credential file access blocked"

  - name: block-exfil
    match:
      tool: ["fetch"]
    rules:
      - action: deny
        when:
          domain_matches:
            - "*.ngrok-free.app"
            - "*.requestbin.com"
            - "webhook.site"
        message: "Exfiltration domain blocked"
```

## Example: Anti-Exfiltration Policy

Detect encoding, obfuscation, and data staging:

```yaml
version: "1"
default_action: allow

policies:
  - name: encoding-sensitive-files
    priority: 1
    match:
      tool: "exec"
    rules:
      - action: deny
        when:
          command_matches:
            - "base64 ~/.ssh/*"
            - "base64 ~/.aws/*"
            - "*cat*.ssh*|*base64*"
            - "*cat*.aws*|*base64*"
            - "*xxd*.ssh*"
        message: "Encoding of sensitive files blocked"

  - name: encoded-data-exfil
    priority: 1
    match:
      tool: "exec"
    rules:
      - action: deny
        when:
          command_matches:
            - "*base64*|*curl*"
            - "*base64*|*wget*"
            - "*base64*|*nc *"
        message: "Encoded data sent to network blocked"

  - name: reverse-shell
    priority: 1
    match:
      tool: "exec"
    rules:
      - action: deny
        when:
          command_matches:
            - "*bash -i >& /dev/tcp*"
            - "*python*socket*connect*"
            - "*nc -e /bin/*"
        message: "Reverse shell pattern blocked"
```

## Hot Reload

Rampart watches policy files for changes via `fsnotify`. Edit a YAML file and the policy engine picks it up immediately — no restart needed.

## Validation

Check your policy file for errors:

```bash
rampart policy check
```

Trace how a specific command would be evaluated:

```bash
rampart policy explain "rm -rf /"
```

## Next Steps

- [Policy Engine →](../features/policy-engine.md) — Full evaluation logic
- [Policy Schema →](../reference/policy-schema.md) — Complete YAML reference
- [Integration Guides →](../integrations/index.md) — Hook up your agent
