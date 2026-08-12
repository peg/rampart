# How Rampart Works

Rampart has four main pieces. Here's what each one does and how they fit together.

## The daemon (`rampart serve`)

This is the shared local policy service. It loads your policies, evaluates tool calls for service-backed integrations, and writes audit events. It runs as an HTTP server on `localhost:9090` (by default).

```
rampart serve
```

You don't usually run this directly. `rampart protect` and the service-backed
setup flows start or verify it for you. They install a system service through
systemd on Linux or launchd on macOS; Windows uses a login-scoped background
process.

**What happens if it's not running?** Behavior depends on the integration:

- **Claude Code / Cline / Codex / GitHub Copilot native hooks**, plus the experimental Gemini CLI adapter, can still evaluate policy locally for direct hook decisions.
- **OpenClaw native plugin** depends on `rampart serve`; sensitive tools such as `exec` and `write` block when the service is unavailable, while explicitly configured lower-risk `failOpenTools` can still proceed.
- **Wrapper / preload / API integrations** typically need the service path and may fail open or fail closed depending on configuration.

## Agent setup (`rampart setup`)

This wires an agent to use the daemon. What it does depends on the agent:

| Agent | What `setup` does |
|-------|-------------------|
| **Claude Code** | Writes native hooks in `~/.claude/settings.json` |
| **Codex** | Installs native lifecycle hooks in `$CODEX_HOME/hooks.json` for CLI, IDE, and desktop |
| **Cline** | Installs direct platform-native hook files under `~/Documents/Cline/Hooks/` |
| **OpenClaw** | `rampart protect openclaw` installs the native plugin, managed policies, fail-closed degraded behavior, and behavioral verification on current builds |
| **MCP servers** | Use `rampart mcp --` prefix instead of setup |

After setup, every tool call exposed by the host goes through the integration's
enforcement path before execution. Some paths call into `rampart serve`;
Claude/Cline/Codex native hooks can also evaluate allow/deny policy locally.

```
rampart protect claude-code # managed native hooks + active verification
rampart protect codex       # native lifecycle hooks; no wrapper replacement
rampart protect openclaw    # managed fail-closed guard + behavioral verification
```

`rampart setup openclaw` remains available for advanced/manual integration
management and legacy compatibility.

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

## The flows

### Claude Code / Cline native hooks

```
Agent tool call
  │
  ▼
Rampart hook (`rampart hook`)
  │
  ├─ local policy evaluation
  ├─ optional serve-backed audit / external approval state
  │
  └─ allow / deny / ask returned to the agent's native hook UX
```

### Service-backed integrations (OpenClaw plugin, preload/wrapper, API)

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
Ask   → native agent prompt or external approval flow, depending on integration
```

## Common questions

**Do I need to run `rampart serve` manually?**
Not usually. `rampart protect` installs a persistent service on Linux and macOS;
Windows uses a login-scoped background process. Direct Claude Code and Cline
hook protection can still evaluate ordinary allow/deny policy locally if the
service later becomes unavailable.

**What if I installed with `nohup rampart serve &`?**
That works but won't survive reboots. On Linux or macOS, run
`rampart serve install` or `rampart protect` to create a persistent service.
On Windows, Rampart currently uses a login-scoped background process.

**Can I run on a different port?**
Yes: `rampart serve --port 19090`. Set `RAMPART_URL=http://localhost:19090` so other commands find it.

**Does watch need the daemon?**
No. Watch reads audit files directly. But without the daemon, there are no new events to watch.
