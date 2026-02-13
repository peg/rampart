# Cline

[Cline](https://github.com/cline/cline) is an AI coding assistant for VS Code. Rampart integrates via Cline's native hook system — every command, file read, and file write gets evaluated before execution.

## Setup

```bash
rampart setup cline
```

This installs hooks into Cline's settings that route tool calls through `rampart hook` for policy evaluation.

## What Gets Intercepted

| Tool Call | Example | Intercepted? |
|-----------|---------|:---:|
| Shell commands | `npm install`, `rm -rf` | ✅ |
| File reads | Reading `.env`, `id_rsa` | ✅ |
| File writes | Writing to `/etc/`, config files | ✅ |
| File edits | Modifying source code | ✅ |

## How It Works

When Cline wants to execute a tool:

1. Cline's hook system sends the tool call to `rampart hook` via stdin (JSON)
2. Rampart evaluates the call against your YAML policies (<10μs)
3. If **allowed**: Rampart returns success, Cline proceeds
4. If **denied**: Rampart returns an error message, Cline never executes the command

This happens transparently — you use Cline exactly as before.

## Monitor in Real Time

Open a separate terminal to watch decisions as they happen:

```bash
rampart watch
```

## Start in Monitor Mode

Not sure about your policies yet? Set your policy's `default_action: allow` and use `action: log` rules instead of `deny` — everything gets logged but nothing gets blocked. Check `rampart watch` to see what would be caught, then switch rules to `deny` when you're confident.

## Troubleshooting

**Hooks not intercepting anything?**

Check that Cline's settings have the Rampart hook entries. In VS Code, open Cline settings and look for hook configuration pointing to `rampart hook`.

**Getting false positives?**

Adjust your policies in `~/.rampart/policies/` or use `rampart watch` to see which rules are firing, then tune the patterns.

## Uninstall

```bash
rampart setup cline --remove
```

This removes the Rampart hook scripts. Your policies and audit logs in `~/.rampart/` are preserved.
