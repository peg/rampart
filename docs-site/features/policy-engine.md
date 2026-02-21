---
title: Policy Engine
description: "Rampart's YAML policy engine checks every AI agent tool call in microseconds. Deny, allow, log, or require approval by command, path, URL, or pattern."
---

# Policy Engine

Rampart's policy engine evaluates every AI agent tool call against YAML rules in single-digit microseconds. No network calls, no external dependencies — just fast pattern matching.

## Evaluation Flow

```d2
direction: down

call: "Tool Call" {shape: oval}

match: "Match policies
by tool type" {shape: diamond}

rules: "Evaluate rules
top-to-bottom" {shape: diamond}

deny: "Denied" {
  style.fill: "#2d1b1b"
  style.stroke: "#da3633"
  style.font-color: "#f85149"
  style.border-radius: 6
}

webhook: "Webhook" {
  style.border-radius: 6
}

approval: "Approval" {
  style.fill: "#2d2508"
  style.stroke: "#d29922"
  style.font-color: "#d29922"
  style.border-radius: 6
}

watch: "Logged + Allowed" {
  style.fill: "#2d2508"
  style.stroke: "#d29922"
  style.font-color: "#d29922"
  style.border-radius: 6
}

allow: "Allowed" {
  style.fill: "#1d3320"
  style.stroke: "#2ea043"
  style.font-color: "#3fb950"
  style.border-radius: 6
}

default: "Default Action
(allow or deny)" {
  style.border-radius: 6
  style.stroke-dash: 4
}

audit: "Audit Trail" {shape: cylinder}

call -> match
match -> rules: "policies found"
match -> default: "no match"

rules -> deny: "deny rule"
rules -> webhook: "webhook rule"
rules -> approval: "require_approval"
rules -> watch: "watch rule"
rules -> allow: "allow rule"

deny -> audit
webhook -> audit
approval -> audit
watch -> audit
allow -> audit
default -> audit
```

### Evaluation Order

1. **Collect** all policies whose `match` clause fits the tool call
2. **Within each policy**, rules evaluate top-to-bottom (first match wins)
3. **Across policies**: any `deny` → denied. No deny + any `log` → logged. Only `allow` → allowed
4. **Nothing matches** → configurable default action (`allow` or `deny`)

**Deny always wins.** If any policy says deny, the call is denied. No override, no ambiguity.

## Pattern Matching

### Glob Syntax

Rampart uses glob patterns for matching:

| Pattern | Matches |
|---------|---------|
| `*` | Any sequence of characters (single path segment) |
| `**` | Any sequence of characters (crosses path separators) |
| `?` | Any single character |

### Examples

```yaml
command_matches:
  - "rm -rf *"      # rm -rf followed by anything
  - "kubectl * -n production"  # kubectl commands in production namespace

path_matches:
  - "**/.ssh/id_*"  # SSH keys anywhere in the filesystem
  - "*.env"         # .env files in current directory
  - "**/.env"       # .env files anywhere

domain_matches:
  - "*.ngrok-free.app"  # All ngrok subdomains
  - "webhook.site"      # Exact domain match
```

## Tool Types

| Tool | Trigger | Available Matchers |
|------|---------|-------------------|
| `exec` | Shell commands | `command_matches` |
| `read` | File reads | `path_matches`, `path_not_matches` |
| `write` | File writes | `path_matches`, `path_not_matches` |
| `fetch` | HTTP requests | `domain_matches` |
| MCP tools | MCP `tools/call` | Tool name matching + `command_matches` |

## Actions

### `deny`

Block the tool call. The agent receives an error with the policy's `message` field.

### `allow`

Permit the tool call. Logged at default level.

### `log`

Permit but flag for review. Shows with 🟡 in `rampart watch`.

### `require_approval`

Block until a human approves:

```yaml
rules:
  - action: require_approval
    when:
      command_matches: ["kubectl apply *", "terraform apply *"]
    message: "Production deployment requires approval"
```

```bash
rampart pending          # What's waiting
rampart approve abc123   # Let it through
rampart deny abc123      # Block it
```

### `webhook`

Delegate the decision to an external HTTP endpoint:

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

The webhook receives the full tool call context and returns `{"decision": "allow"}` or `{"decision": "deny", "reason": "..."}`.

## Response-Side Evaluation

Rampart can scan tool output (PostToolUse) for sensitive patterns, preventing credential leakage from reaching the AI agent. When a response matches, the output is blocked before the agent sees it.

### How it works

1. After a tool executes, the agent runtime sends a PostToolUse hook with the tool's output
2. Rampart evaluates the output against `response_matches` regex patterns
3. If a pattern matches, Rampart blocks the response — the agent never sees the sensitive data

### Configuration

```yaml
policies:
  - name: block-credential-leakage
    match:
      tool: ["exec", "read"]
    rules:
      - action: deny
        when:
          response_matches:
            - "AWS_SECRET_ACCESS_KEY\\s*="
            - "-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
            - "ghp_[A-Za-z0-9_]{36,}"           # GitHub PAT
            - "sk-[A-Za-z0-9]{20,}"              # OpenAI API key
            - "AKIA[0-9A-Z]{16}"                 # AWS access key ID
            - "xox[bpras]-[0-9a-zA-Z-]+"         # Slack token
          response_not_matches:
            - "example|placeholder|test"          # Exclude known safe patterns
        message: "Response contains potential credentials"
```

Patterns use **regex** (not glob). Response bodies larger than 1 MB are truncated before matching to prevent ReDoS.

### Claude Code setup

Add PostToolUse hooks alongside PreToolUse in `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [{ "type": "command", "command": "rampart hook" }] }
    ],
    "PostToolUse": [
      { "matcher": "Bash", "hooks": [{ "type": "command", "command": "rampart hook" }] }
    ]
  }
}
```

### Proxy API

The proxy API also supports response scanning. Include a `response` field in the request body:

```bash
curl -X POST http://localhost:9090/api/v1/tool \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"tool": "exec", "params": {"command": "env"}, "response": "AWS_SECRET_ACCESS_KEY=..."}'
```

### Default patterns

The `standard.yaml` policy ships with a `block-credential-leakage` policy that detects common credential patterns including AWS keys, private keys, GitHub PATs, OpenAI API keys, and Slack tokens.

## MCP Tool Matching

For MCP servers, Rampart auto-categorizes tools:

- Tools with destructive keywords (`delete`, `destroy`, `remove`, `drop`) → `mcp-destructive`
- Tools with dangerous keywords (`stop`, `restart`, `execute`, `modify`) → `mcp-dangerous`

```yaml
policies:
  - name: block-mcp-destructive
    match:
      tool: ["mcp-destructive"]
    rules:
      - action: deny
        message: "Destructive MCP operation blocked"
```

You can also match specific MCP tool names:

```yaml
policies:
  - name: block-vm-deletion
    match:
      tool: ["mcp__proxmox__vm_delete"]
    rules:
      - action: deny
        message: "VM deletion blocked"
```

## ⚠️ Glob Matching Limitations

!!! warning "Glob patterns operate on raw command strings"
    Rampart's glob matching compares patterns against the **literal command string** as received from the agent framework. It does **not** interpret shell semantics. This means commands can evade glob patterns using:

    - **Quoting:** `r"m" -rf /` or `'rm' -rf /` won't match `rm -rf *`
    - **Variable expansion:** `$CMD` where `CMD=rm` won't match `rm *`
    - **Backslash escaping:** `r\m -rf /` won't match `rm -rf *`
    - **Path variations:** `/bin/rm` vs `rm`
    - **Unicode/encoding tricks:** homoglyph characters

    **For high-security deployments**, use `default_action: deny` with explicit allowlists rather than relying solely on deny-list glob patterns. This inverts the model: only explicitly permitted commands can run, and evasion techniques are blocked by default.

    ```yaml
    default_action: deny
    policies:
      - name: allowed-commands
        match:
          tool: [exec]
        rules:
          - action: allow
            when:
              command_matches:
                - "git status"
                - "git diff *"
                - "ls *"
    ```

## Performance

| Command | Decision | Time |
|---------|----------|------|
| `rm -rf /` | deny | 8μs |
| `sudo reboot` | log | 6μs |
| `.ssh/id_rsa` read | deny | 3μs |
| `git status` | allow | 4μs |
| `curl ngrok.io` | deny | 3μs |

Policy evaluation is pure in-memory pattern matching. No disk I/O, no network calls, no external processes.

## Shell-Aware Command Matching

Rampart normalizes shell commands before policy matching to prevent evasion via shell metacharacters. Without normalization, an agent could bypass a `command_matches: ["rm -rf *"]` rule by using `'rm' -rf /`, `r\m -rf /`, or `"rm" -rf /`.

The normalizer handles:

- **Quote stripping**: `'rm' -rf /` → `rm -rf /`
- **Backslash escape removal**: `r\m -rf /` → `rm -rf /`
- **Env var prefix stripping**: `FOO=bar rm -rf /` → `rm -rf /`
- **Compound command splitting**: `rm -rf / && echo done` matches against each segment individually

Commands are matched against **both** the raw and normalized forms, so existing policies continue to work without changes.

## Hot Reload

Policies hot-reload via `fsnotify`. Edit the YAML file and changes take effect immediately — no restart required.
