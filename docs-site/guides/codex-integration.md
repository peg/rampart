---
title: Codex CLI Integration
description: Protect OpenAI Codex CLI with Rampart using a shell wrapper. Every command Codex runs passes through your policy before execution.
---

# Securing Codex CLI with Rampart

Protect OpenAI Codex CLI tool calls using Rampart's shell wrapper. Every shell command Codex makes passes through your policy before execution.

## How it works

Unlike Claude Code and Cline — which expose hook APIs — Codex CLI v0.4.5+ uses a shell wrapper for integration. Rampart installs a `codex` wrapper script that transparently routes all Codex commands through policy evaluation.

```
Codex CLI → shell wrapper → Rampart policy check → allow / deny
```

For older Codex versions (< 0.4.5), Rampart falls back to LD_PRELOAD interception.

## Setup (one command)

```bash
rampart setup codex
```

This creates `~/.local/bin/codex` — a wrapper script that runs the real Codex binary through Rampart. From that point on, just use `codex` normally.

```
✓ Wrapper installed at /home/user/.local/bin/codex
  Wraps: /usr/local/bin/codex
  Via:   /usr/local/bin/rampart

✓ Run 'codex' normally — all tool calls are now enforced by Rampart.
  Uninstall: rampart setup codex --remove
```

### PATH order matters

The wrapper lives in `~/.local/bin`. Make sure that directory appears **before** the real Codex binary in your PATH:

```bash
# ~/.bashrc or ~/.zshrc
export PATH="$HOME/.local/bin:$PATH"
```

Verify the right `codex` is active:

```bash
which codex
# Should print: /home/user/.local/bin/codex
```

### Alternative: run inline

If you don't want the wrapper, you can invoke Rampart inline for any command:

```bash
rampart wrap -- codex exec --full-auto 'fix the bug in auth.py'
```

## Interactive setup wizard

If you run `rampart setup` without arguments, the wizard detects installed agents automatically:

```
Detected agents:
  ✓ Codex (found)        → rampart setup codex
  ✗ Claude Code          → not found
  ✗ OpenClaw             → not found

Which agents would you like to protect? [all detected/select/skip]
```

Codex is set up automatically when detected.

## Verify it's working

Start the Rampart server, then run Codex:

```bash
# Terminal 1
rampart serve

# Terminal 2 — Rampart watch shows live decisions
rampart watch

# Terminal 3 — run Codex normally
codex exec --full-auto 'check disk usage'
```

You should see `df -h` appear in `rampart watch` as allowed. Try something blocked:

```bash
codex exec --full-auto 'show me the SSH private key'
# → Operation not permitted (blocked by block-credential-access)
```

## Policy

Rampart's standard policy covers the most common Codex threat scenarios out of the box:

| Scenario | Policy | Action |
|---|---|---|
| `cat ~/.ssh/id_rsa` | `block-credential-access` | deny |
| `curl ... \| bash` | `block-destructive` | deny |
| `base64 -d \| sh` | `block-destructive` | deny |
| `sudo rm -rf /` | `require-privileged-approval` | ask |
| `cat /etc/shadow` | `block-credential-access` | deny |
| `/dev/tcp/` shell redirect | `block-network-exfil` | deny |

## Uninstall

```bash
rampart setup codex --remove
```

Rampart verifies the file is its own wrapper before removing it. The real Codex binary is restored automatically (it was never moved).

## Platform Notes

- **Linux:** Full support via shell wrapper. Older Codex versions (< 0.4.5) use LD_PRELOAD fallback.
- **macOS:** Shell wrapper works for all versions. LD_PRELOAD fallback also available.
- **Windows:** Not supported — use the HTTP API instead.

Run `rampart setup --help` for alternatives on unsupported platforms.
