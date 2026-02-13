# CLI Commands

Complete reference for all `rampart` commands.

## Agent Setup

### `rampart setup claude-code`

Install native hooks into Claude Code.

```bash
rampart setup claude-code           # Install hooks
# rampart setup claude-code --remove  # Not yet implemented
```

### `rampart setup cline`

Install native hooks into Cline.

```bash
rampart setup cline           # Install hooks
# rampart setup cline --remove  # Not yet implemented
```

### `rampart setup openclaw`

Install shell shim and background service for OpenClaw.

```bash
rampart setup openclaw                # Exec shim only
# rampart setup openclaw --patch-tools  # Not yet implemented
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
rampart serve                          # Default (port 9090)
rampart serve --port 8080              # Custom port
rampart serve --config policy.yaml     # Custom policy
rampart serve --syslog localhost:514   # With syslog output
rampart serve --cef                    # With CEF file output
rampart serve --syslog localhost:514 --cef  # CEF to syslog
```

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

## Monitoring

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
rampart audit search --tool exec --decision deny
rampart audit search --agent claude-code
```

## Policy

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
rampart deny <id> --reason "Not approved"
```
