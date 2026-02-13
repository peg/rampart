# Configuration

Rampart policies are YAML files that define what your AI agent can and can't do. Policies are evaluated in microseconds and hot-reload when you edit them.

## Policy File Location

By default, Rampart looks for policies in `~/.rampart/policies/`. You can specify a custom location:

```bash
rampart serve --config /path/to/policy.yaml
rampart wrap --config /path/to/policy.yaml -- agent
```

## Basic Structure

```yaml
version: "1"
default_action: allow  # allow | deny

policies:
  - name: my-policy
    match:
      tool: ["exec"]  # Which tool types this applies to
    rules:
      - action: deny  # deny | allow | log | require_approval
        when:
          command_matches: ["rm -rf *"]
        message: "Destructive command blocked"
```

## Actions

| Action | Effect |
|--------|--------|
| `deny` | Block the tool call. Agent receives an error. |
| `allow` | Permit the tool call. |
| `log` | Permit but log with elevated visibility. |
| `require_approval` | Block until a human approves or denies. |
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
      - action: log
        when:
          command_matches: ["curl *"]
```

## Webhook Notifications

Get alerts when commands are blocked:

```yaml
version: "1"
default_action: allow

notify:
  url: "https://discord.com/api/webhooks/your/webhook"
  on: ["deny"]  # Options: deny, log

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
