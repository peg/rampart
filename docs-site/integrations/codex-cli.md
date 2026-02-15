# Codex CLI

Codex CLI doesn't have a hook system or `$SHELL` support. Rampart uses **LD_PRELOAD** to intercept exec syscalls at the OS level — the universal fallback.

## Setup

```bash
rampart preload -- codex
```

That's it. Every command Codex tries to execute goes through Rampart first.

## How It Works

```
Codex CLI
  └─ calls execve("rm", ["-rf", "/"], env)
       └─ librampart.so intercepts (LD_PRELOAD)
            └─ HTTP POST to rampart /v1/preflight/exec
                 ├─ allow → real execve() runs
                 ├─ deny  → returns EPERM
                 └─ require_approval → blocks until resolved, then allow/deny
```

**require_approval behavior**: The preload library blocks the exec call and polls the approval API until resolved by a human via `rampart approve <id>`. The process appears "hung" until approved or denied.

The preload library intercepts:

- `execve` — primary exec syscall
- `execvp` / `execvpe` — PATH-resolved variants
- `system()` — libc shell wrapper
- `popen()` — pipe to shell command
- `posix_spawn()` — modern spawn API

## Monitor Mode

Log everything without blocking:

```bash
rampart preload --mode monitor -- codex
```

## Platform Support

| Platform | Coverage |
|----------|----------|
| **Linux** | ~95% of dynamically-linked binaries |
| **macOS** | ~70-85% — works with Homebrew, nvm, pyenv. Blocked by SIP for `/usr/bin/*` |
| **Windows** | Not supported — use HTTP API instead |

## Requirements

The preload library (`librampart.so` or `librampart.dylib`) must be installed. It's included in Homebrew installs and release tarballs, or build from `preload/` in the source tree.

## Performance

The library adds <1ms per intercepted call via Unix socket, <3ms via TCP. Fail-open is instant (<0.01ms).

## Monitor

```bash
rampart watch
```
