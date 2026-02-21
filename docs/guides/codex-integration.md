# Securing Codex CLI with Rampart

Protect OpenAI Codex CLI tool calls using Rampart's LD_PRELOAD syscall interception. Every shell command, file read, and network request Codex makes passes through your policy before execution.

## How it works

Unlike Claude Code and Cline — which expose hook APIs — Codex CLI doesn't have a native hook system. Rampart uses `LD_PRELOAD` to intercept system calls (`execve`, `execvp`, `system`, `popen`, `posix_spawn`) at the OS level. This means every command Codex spawns is evaluated against your policy regardless of how Codex invokes it.

```
Codex CLI → tool call → librampart.so intercept → Rampart policy → allow / deny
```

## Setup (one command)

```bash
rampart setup codex
```

This creates `~/.local/bin/codex` — a wrapper script that runs the real Codex binary through `rampart preload`. From that point on, just use `codex` normally.

```
✓ Wrapper installed at /home/user/.local/bin/codex
  Wraps: /usr/local/bin/codex
  Via:   /usr/local/bin/rampart preload

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
rampart preload -- codex exec --full-auto 'fix the bug in auth.py'
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
| `sudo rm -rf /` | `require-privileged-approval` | require approval |
| `cat /etc/shadow` | `block-credential-access` | deny |
| `/dev/tcp/` shell redirect | `block-network-exfil` | deny |

## Uninstall

```bash
rampart setup codex --remove
```

Rampart verifies the file is its own wrapper before removing it. The real Codex binary is restored automatically (it was never moved).

## Linux only

`rampart setup codex` requires Linux — LD_PRELOAD syscall interception is not available on macOS or Windows. On macOS, use `rampart wrap -- codex` (shell-level wrapping) or the MCP proxy mode instead. Run `rampart setup --help` for alternatives.
