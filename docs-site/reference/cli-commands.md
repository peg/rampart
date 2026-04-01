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

Install Rampart integration for OpenClaw. Auto-detects your OpenClaw version and uses the best available method.

```bash
rampart setup openclaw           # Auto-detect: native plugin (>= 2026.3.28) or legacy shim
rampart setup openclaw --plugin  # Force native plugin install (requires >= 2026.3.28)
rampart setup openclaw --migrate # Migrate from legacy shim/bridge to native plugin
rampart setup openclaw --force   # Overwrite existing config
rampart setup openclaw --remove  # Remove integration
```

**Native plugin (OpenClaw >= 2026.3.28):** Installs the bundled `before_tool_call` hook plugin. Covers all tool calls (exec, read, write, web_fetch, browser, message). Plugin is embedded in the `rampart` binary — no external download required.

**Legacy shim (OpenClaw < 2026.3.28):** Installs shell shim + optionally patches file tools via `--patch-tools`. Requires re-running after OpenClaw upgrades.

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

### `rampart upgrade`

Upgrade Rampart to the latest or a specified release. Downloads from GitHub releases, verifies SHA256, atomically replaces the binary, and optionally restarts `rampart serve` if it was running.

```bash
rampart upgrade              # Upgrade to latest release
rampart upgrade v0.8.0       # Upgrade to a specific version
rampart upgrade --yes        # Skip confirmation prompt
rampart upgrade --dry-run    # Preview without making changes
rampart upgrade --no-policy-update  # Skip refreshing built-in policy profiles
```

After upgrade, standard policy profiles (`standard.yaml`, `paranoid.yaml`, `yolo.yaml`) in `~/.rampart/policies/` are refreshed automatically. Custom policy files are never modified.

### `rampart uninstall`

Remove Rampart from the system. Removes agent hooks, stops and removes the service, cleans up PATH entries (Windows), and removes the shell shim.

```bash
rampart uninstall            # Interactive (prompts for confirmation)
rampart uninstall --yes      # Skip confirmation prompt
```

After running, delete `~/.rampart/` manually and remove any `rampart`-related lines from your shell profile.

## Core Commands

### `rampart hook`

Hook handler called by Claude Code/Cline. Reads tool call from stdin, writes decision to stdout.

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | rampart hook
```

### `rampart serve`

Start the HTTP policy proxy.

```bash
rampart serve                              # Default (port 9090, localhost only)
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

`--addr` takes a bare IP address (e.g. `127.0.0.1`, `0.0.0.0`, `::1`). Defaults to `127.0.0.1` (localhost only) — use `--addr 0.0.0.0` to listen on all interfaces. `--audit-dir` sets the directory for audit log output (defaults to `~/.rampart/audit/`).

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

## Service Management

### `rampart serve install`

Install `rampart serve` as a persistent system service. On macOS, creates a LaunchAgent plist. On Linux, creates a systemd user service (`rampart-serve.service`). Not supported on Windows.

```bash
rampart serve install                         # Install with defaults (port 9090)
rampart serve install --port 8080             # Custom port
rampart serve install --mode monitor          # Audit-only mode
rampart serve install --config-dir ~/.rampart/policies  # Custom policy directory
rampart serve install --audit-dir /var/log/rampart      # Custom audit directory
rampart serve install --approval-timeout 30m  # Custom approval timeout
rampart serve install --token mytoken         # Use a specific token
rampart serve install --force                 # Overwrite existing installation
```

The token is saved to `~/.rampart/token` and embedded in the service file (mode `0600`). Hooks read it automatically.

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `9090` | Proxy listen port |
| `--config-dir` | _(none)_ | Directory of additional policy YAML files |
| `--audit-dir` | `~/.rampart/audit` | Directory for audit logs |
| `--mode` | `enforce` | Enforcement mode: `enforce`, `monitor`, or `disabled` |
| `--approval-timeout` | `2m` | How long approvals stay pending before expiring |
| `--token` | _(auto-generated)_ | Override `RAMPART_TOKEN` for the service |
| `--force` | `false` | Overwrite an existing service installation |

### `rampart serve stop`

Stop a `rampart serve` process that was started with `--background`. Reads the PID from `~/.rampart/serve.pid` and sends `SIGTERM`.

```bash
rampart serve stop
```

### `rampart serve uninstall`

Remove the `rampart serve` system service. On macOS, unloads and removes the LaunchAgent plist. On Linux, disables and removes the systemd user service and runs `daemon-reload`.

```bash
rampart serve uninstall
```

## Diagnostics

### `rampart doctor`

Health check — verifies installation, policies, server, hooks, audit trail, and system info.

```bash
rampart doctor
```

When the OpenClaw native plugin is installed, doctor shows:
```
✓ OpenClaw plugin: installed (before_tool_call hook active)
```

If the plugin is missing or the OpenClaw version is too old:
```
✗ OpenClaw plugin: not installed
  → Run: rampart setup openclaw --plugin
```

### `rampart status`

Quick dashboard showing protected agents, enforcement mode, and today's event counts.

```bash
rampart status
```

### `rampart test`

Dry-run commands against your policies or run a declarative test suite.

**Single command:**

```bash
rampart test "rm -rf /"                  # Test an exec command
rampart test --tool read "/etc/passwd"   # Test a file read
rampart test --tool write "/etc/hosts"   # Test a file write
rampart test --config custom.yaml "cmd"  # Test with specific policy
```

**Test suite (YAML file):**

```bash
rampart test tests.yaml                  # Run all test cases
rampart test tests.yaml --verbose        # Show match details
rampart test tests.yaml --json           # Machine-readable output
rampart test tests.yaml --run "deny*"    # Filter by name glob
rampart test                             # Auto-discover rampart-tests.yaml
```

Test suite format:

```yaml
tests:
  - name: deny rm -rf
    tool: exec
    params:
      command: "rm -rf /"
    expect: deny
    expect_message: "Destructive*"    # optional glob match on message

  - name: allow git push
    tool: exec
    params:
      command: "git push origin main"
    expect: allow

  - name: deny SSH key read
    tool: read
    params:
      path: "~/.ssh/id_rsa"
    expect: deny
```

Tests can also be embedded directly in a policy file under a `tests:` key.
See `examples/policy-with-tests.yaml` for a self-verifying policy.

**Flags:**

| Flag | Description |
|------|-------------|
| `--tool` | Tool type: exec, read, write (default: exec) |
| `--config` | Path to policy file (overrides test suite `policy:` key) |
| `--verbose`, `-v` | Show match details for each test case |
| `--json` | Output results as JSON |
| `--run` | Run only tests matching a glob pattern |
| `--no-color` | Disable color output |

Exit code 0 if all tests pass, 1 if any fail. Designed for CI pipelines.

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

`--for` accepts Go duration strings (`1h`, `30m`, `24h`, `2h30m`). Expired rules are automatically skipped during evaluation and cleaned up periodically by `rampart serve`. `--once` creates a single-use rule: after its first match, Rampart removes it from the policy file and reloads. This works in both `rampart serve` (proxy) and `rampart hook` (Claude Code) modes.

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

## Policy Management

Commands for linting, discovering, and managing policy profiles from the Rampart registry.

### `rampart policy lint <file>`

Lint a policy YAML file for errors, warnings, and suggestions. Checks for invalid YAML syntax, unknown action/condition values (with typo suggestions), rules with no conditions, excessive glob depth, common field confusion, shadowed rules, and missing `default_action`.

```bash
rampart policy lint policy.yaml
rampart policy lint ~/.rampart/policies/custom.yaml
```

Exit code `1` if errors are found; `0` if only warnings or info.

### `rampart policy list`

List all available policy profiles — both built-in profiles and community policies from the Rampart registry. Uses a local cache (TTL: 1 hour) and falls back to embedded data when offline.

```bash
rampart policy list                    # List all profiles
rampart policy list --extended         # Show SOURCE and INSTALLED columns
rampart policy list --refresh          # Force refresh registry cache
rampart policy list --json             # JSON output
```

| Flag | Default | Description |
|------|---------|-------------|
| `--refresh` | `false` | Force refresh of registry cache |
| `--extended` | `false` | Show `SOURCE` and `INSTALLED` columns |
| `--json` | `false` | Output as JSON |

### `rampart policy search <query>`

Search community policies in the registry by name, description, or tag. Results are sorted by bench score (descending).

```bash
rampart policy search docker                     # Search for docker-related policies
rampart policy search "prompt injection"         # Multi-word search
rampart policy search ci --tag ci                # Filter by exact tag
rampart policy search security --min-score 80   # Minimum bench score
rampart policy search docker --json              # JSON output
```

| Flag | Default | Description |
|------|---------|-------------|
| `--tag` | _(none)_ | Filter by exact tag |
| `--min-score` | `0` | Minimum bench score (0–100) |
| `--json` | `false` | Output as JSON |

### `rampart policy show <name>`

Print the full YAML of a built-in profile or community policy without installing it.

```bash
rampart policy show standard
rampart policy show paranoid
rampart policy show docker-restricted
```

### `rampart policy fetch <name>`

Download and install a community policy profile to `~/.rampart/policies/<name>.yaml`. Verifies the SHA256 checksum before writing. Falls back to the embedded policy copy when the registry is unreachable.

```bash
rampart policy fetch docker-restricted          # Install a community policy
rampart policy fetch docker-restricted --force  # Overwrite if already installed
rampart policy fetch docker-restricted --dry-run  # Preview install path
```

| Flag | Default | Description |
|------|---------|-------------|
| `--force` | `false` | Overwrite an existing policy file |
| `--dry-run` | `false` | Preview download and install path without writing |

### `rampart policy install <name>`

Alias for `rampart policy fetch`. Downloads and installs a community policy profile.

```bash
rampart policy install docker-restricted
rampart policy install docker-restricted --force
rampart policy install docker-restricted --dry-run
```

### `rampart policy remove <name>`

Remove an installed community policy profile from `~/.rampart/policies/`. Built-in profiles (`standard`, `paranoid`, `yolo`, etc.) cannot be removed.

```bash
rampart policy remove docker-restricted
```

### `rampart policy sync <git-url>`

Sync a Rampart policy from a git repository. Requires `git` in `PATH` and an HTTPS URL pointing to a publicly accessible repo. Looks for `rampart.yaml`, `policy.yaml`, or `.rampart/policy.yaml` in the repo root. Writes the result to `~/.rampart/policies/org-sync.yaml` and persists state to `~/.rampart/sync-state.json`.

```bash
rampart policy sync https://github.com/myorg/policies   # One-shot sync
rampart policy sync https://github.com/myorg/policies --watch           # Poll for updates
rampart policy sync https://github.com/myorg/policies --watch --interval 10m  # Custom interval
rampart policy sync                                      # Re-use previously saved URL
```

| Flag | Default | Description |
|------|---------|-------------|
| `--watch` | `false` | Poll for policy updates in the foreground |
| `--interval` | `5m` | How often to poll when using `--watch` |

#### `rampart policy sync status`

Show the current sync configuration and last sync result.

```bash
rampart policy sync status
```

#### `rampart policy sync stop`

Remove the configured sync URL, stopping future syncs.

```bash
rampart policy sync stop
```

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

Top-level command for managing authentication tokens. Without a subcommand, shows help. Use `rampart token show` to print the current admin token.

### `rampart token show`

Print the current admin bearer token (read from `~/.rampart/token`).

```bash
rampart token show
```

### `rampart token rotate`

Generate and persist a new admin bearer token. Prompts for confirmation unless `--force` is given.

```bash
rampart token rotate
rampart token rotate --force
```

## Token Management

Per-agent tokens let you issue scoped tokens for individual agents with different policy enforcement levels. Agent tokens are `eval`-only by default — they can submit tool calls but cannot approve requests or modify policies.

### `rampart token create`

Create a new per-agent token. The full token is printed once at creation — save it, as it cannot be retrieved later.

```bash
rampart token create --agent codex
rampart token create --agent codex --policy paranoid --note "CI pipeline"
rampart token create --agent claude-code --expires 30d
rampart token create --agent admin-bot --scope eval --scope admin
rampart token create --agent codex --json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--agent` | _(required)_ | Agent name (e.g., `codex`, `claude-code`, `openclaw`) |
| `--policy` | _(global)_ | Policy profile to apply (e.g., `paranoid`, `standard`) |
| `--note` | _(none)_ | Human-readable note |
| `--scope` | `eval` | Token scopes: `eval`, `admin` (repeatable) |
| `--expires` | _(never)_ | Token expiry duration (e.g., `24h`, `7d`, `30d`) |
| `--json` | `false` | Output as JSON |

### `rampart token list`

List all per-agent tokens. Token values are masked — only the ID prefix is shown.

```bash
rampart token list
rampart token list --json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | `false` | Output as JSON |

### `rampart token revoke <token-id-or-prefix>`

Revoke a per-agent token by its ID or ID prefix. Revoked tokens are rejected immediately by the proxy.

```bash
rampart token revoke abc123
rampart token revoke abc                  # Revoke by prefix (must be unambiguous)
```

### `rampart token info <token-id-or-prefix>`

Show full details for a per-agent token.

```bash
rampart token info abc123
```
