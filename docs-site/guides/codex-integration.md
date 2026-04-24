---
title: Codex CLI Integration
description: Protect OpenAI Codex CLI with Rampart using a shell wrapper. Every command Codex runs passes through your policy before execution.
---

# Securing Codex CLI with Rampart

Protect OpenAI Codex CLI subprocesses using Rampart's shell wrapper plus preload enforcement. Every shell command Codex spawns through libc exec-family calls passes through your policy before execution.

## How it works

Unlike Claude Code and Cline — which expose hook APIs — Codex CLI does not expose a native hook system. Rampart installs a `codex` wrapper script that transparently runs the real Codex binary through `rampart preload`.

```
Codex CLI → shell wrapper → librampart preload → Rampart policy check → allow / deny
```

## Setup

`rampart setup codex` requires the preload library (`librampart.so` on Linux, `librampart.dylib` on macOS). If your install does not include it — common for source builds — build and place it first:

```bash
mkdir -p ~/.rampart/lib
# Linux
cc -shared -fPIC -o ~/.rampart/lib/librampart.so preload/librampart.c -ldl -lcurl -lpthread
# macOS
cc -dynamiclib -fPIC -o ~/.rampart/lib/librampart.dylib preload/librampart.c -lcurl
```

Then install the persistent wrapper:

```bash
rampart setup codex
```

This creates `~/.local/bin/codex` — a wrapper script that runs the real Codex binary through Rampart. From that point on, just use `codex` normally.

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
| `sudo rm -rf /` | `require-privileged-approval` | ask |
| `cat /etc/shadow` | `block-credential-access` | deny |
| `/dev/tcp/` shell redirect | `block-network-exfil` | deny |

## Uninstall

```bash
rampart setup codex --remove
```

Rampart verifies the file is its own wrapper before removing it. The real Codex binary is restored automatically (it was never moved).

## Platform Notes

- **Linux:** Wrapper + `LD_PRELOAD` coverage for dynamically linked binaries.
- **macOS:** Wrapper + `DYLD_INSERT_LIBRARIES` coverage for Homebrew/user-installed binaries; SIP-protected system binaries cannot be interposed.
- **Windows:** `rampart setup codex` is not supported. Use the HTTP API or MCP proxy mode instead.

Run `rampart setup --help` for alternatives on unsupported platforms.
