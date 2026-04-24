# How Rampart Works

Rampart has four main pieces. Here's what each one does and how they fit together.

## The daemon (`rampart serve`)

This is the core. It loads your policies, evaluates every tool call against them, and writes audit events. It runs as an HTTP server on `localhost:9090` (by default).

```
rampart serve
```

You don't usually run this directly. `rampart quickstart` and `rampart setup` handle it for you by installing a system service (systemd on Linux, launchd on macOS).

**What happens if it's not running?** Behavior depends on the integration. Shell/preload integrations are fail-open by default so they do not lock you out of your own machine. The OpenClaw native plugin is stricter: sensitive tools such as `exec` and `write` block when `rampart serve` is unavailable, while explicitly configured lower-risk `failOpenTools` can still proceed.

## Agent setup (`rampart setup`)

This wires an agent to use the daemon. What it does depends on the agent:

| Agent | What `setup` does |
|-------|-------------------|
| **Claude Code** | Writes `PreToolUse` hook in `~/.claude/settings.json` |
| **Codex** | Installs `~/.local/bin/codex` wrapper that runs the real Codex binary through `rampart preload` |
| **Cline** | Writes hook config in `~/.cline/settings.json` |
| **OpenClaw** | Installs native `before_tool_call` plugin (all tools) on >= 2026.3.28; legacy shim on older versions |
| **MCP servers** | Use `rampart mcp --` prefix instead of setup |

After setup, every tool call the agent makes goes through the daemon for policy evaluation before execution.

```
rampart setup claude-code   # one-time, survives agent updates
rampart setup openclaw      # auto-detects version; native plugin on >= 2026.3.28
```

## Live monitoring (`rampart watch`)

A terminal dashboard that shows tool calls in real time. Useful for demos, debugging policies, and interactive approval workflows.

```
rampart watch              # all events
rampart watch -q           # quiet mode (hides system noise)
rampart watch --tool exec  # only exec events
```

Watch reads from the audit log (`~/.rampart/audit/`). It doesn't need the daemon to be running, but you won't see new events without it.

## Audit log

Every policy decision is written to `~/.rampart/audit/` as JSONL files (one per day). These are append-only, hash-chained for tamper evidence.

```
rampart report             # HTML summary of recent activity
rampart report --days 7    # last 7 days
```

## The flow

```
Agent (Claude Code, Codex, etc.)
  │
  ├─ exec "npm install foo"
  │
  ▼
Rampart daemon (localhost:9090)
  │
  ├─ Load policies from ~/.rampart/policies/
  ├─ Evaluate: allow / deny / ask
  ├─ Write audit event to ~/.rampart/audit/
  │
  ▼
Allow → command runs
Deny  → agent gets error message
Ask   → held until human approves/denies
```

## Common questions

**Do I need to run `rampart serve` manually?**
No. `rampart quickstart` installs it as a system service that starts on boot.

**What if I installed with `nohup rampart serve &`?**
That works but won't survive reboots. Run `rampart serve install` to create a persistent service, or use `rampart quickstart` which handles this.

**Can I run on a different port?**
Yes: `rampart serve --port 19090`. Set `RAMPART_URL=http://localhost:19090` so other commands find it.

**Does watch need the daemon?**
No. Watch reads audit files directly. But without the daemon, there are no new events to watch.
