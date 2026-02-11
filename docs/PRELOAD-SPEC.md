# Rampart Preload — Syscall-Level Agent Protection

**Status:** Spec / Not yet implemented  
**Target:** v0.2.0  
**Effort:** 4-5 weeks

## Overview

`rampart preload` provides universal agent protection via LD_PRELOAD (Linux) / DYLD_INSERT_LIBRARIES (macOS). It intercepts exec syscalls at the process level and routes them through Rampart's policy engine before execution.

This is the fallback for agents that don't have hook systems. Native hooks (Claude Code, Cline) remain the preferred integration — preload is for everything else.

## User Experience

```bash
# Protect any agent, zero configuration in the agent itself
rampart preload -- codex
rampart preload -- python my_agent.py
rampart preload -- node agent.js

# Monitor mode (log only, don't block)
rampart preload --mode monitor -- risky_tool

# Uses existing policy file
rampart preload --config ~/.rampart/policies/standard.yaml -- agent
```

## Architecture

```
Agent Process
  └─ calls execve("rm", ["-rf", "/"], env)
       └─ librampart.so intercepts (loaded via LD_PRELOAD)
            └─ HTTP POST to rampart serve /v1/preflight/exec
                 └─ Policy engine evaluates
                      ├─ allow → call real execve()
                      └─ deny  → return EPERM, log to audit
```

The preload library is a thin HTTP client. All policy logic stays in `rampart serve`.

## Components

### 1. `librampart.so` / `librampart.dylib` (~500 lines C)

Intercepts:
- `execve` — primary exec syscall
- `execvp` / `execvpe` — PATH-resolved variants
- `system` — libc shell wrapper
- `popen` — pipe to shell command
- `posix_spawn` — modern spawn API (macOS uses this heavily)

Each intercepted call:
1. Extracts the command + arguments
2. Builds JSON payload: `{"agent":"preload","session":"<id>","params":{"command":"<cmd>"}}`
3. HTTP POST to `$RAMPART_URL/v1/preflight/exec` with `$RAMPART_TOKEN`
4. If `allowed: true` → call original function via `dlsym(RTLD_NEXT, "execve")`
5. If `allowed: false` → set `errno = EPERM`, return -1
6. If HTTP fails → fail-open (configurable via `$RAMPART_FAIL_OPEN`)

Dependencies: libcurl (HTTP), no JSON library needed (hand-build the simple payload).

### 2. `rampart preload` CLI command (Go)

```go
// cmd/rampart/cli/preload.go
func newPreloadCmd(opts *rootOptions) *cobra.Command {
    // 1. Find librampart.so in known locations
    // 2. Ensure rampart serve is running (start if needed)
    // 3. Set LD_PRELOAD + RAMPART_URL + RAMPART_TOKEN env vars
    // 4. exec the target command
}
```

Library search order:
1. `~/.rampart/lib/librampart.{so,dylib}`
2. `/usr/local/lib/librampart.{so,dylib}`
3. Next to the `rampart` binary

### 3. Build system

```makefile
# Makefile in preload/ directory
librampart.so: librampart.c
    $(CC) -shared -fPIC -o $@ $< -lcurl -ldl

librampart.dylib: librampart.c
    $(CC) -dynamiclib -o $@ $< -lcurl
```

Cross-compiled in goreleaser alongside the Go binary. Distributed as part of the release tarball.

## Environment Variables

The library reads from env (set by `rampart preload` command):

| Variable | Default | Description |
|----------|---------|-------------|
| `RAMPART_URL` | `http://127.0.0.1:19090` | Policy server URL |
| `RAMPART_TOKEN` | (none) | Bearer auth token |
| `RAMPART_MODE` | `enforce` | enforce / monitor / disabled |
| `RAMPART_FAIL_OPEN` | `1` | Fail-open when serve unreachable |
| `RAMPART_AGENT` | `preload` | Agent name for audit |
| `RAMPART_SESSION` | `preload-<pid>` | Session ID |
| `RAMPART_DEBUG` | `0` | Log to stderr |

## Platform Support

### Linux (primary target)
- LD_PRELOAD is universally supported for dynamically-linked binaries
- ~95% coverage (static binaries are not interceptable)
- No special permissions needed

### macOS
- DYLD_INSERT_LIBRARIES works for non-SIP-protected binaries
- ✅ Works: Homebrew packages, Node.js (nvm/volta), Python (pyenv/homebrew), Go binaries, npm globals
- ❌ Blocked: /usr/bin/*, /System/*, Apple-signed hardened binaries
- ~70-85% coverage for typical developer environments
- No need to disable SIP — AI agents are user-installed software

### Windows
- No equivalent mechanism. Not supported. Use native hooks or `rampart serve` API instead.

## Security Considerations

### What this catches
- AI agent hallucinating `rm -rf /`
- Malicious skills/plugins executing credential theft
- Unintended network exfiltration via curl/wget
- Any exec call from the agent process tree

### What this does NOT catch
- Agent explicitly unsetting LD_PRELOAD before exec (deliberate bypass)
- Direct syscalls bypassing libc (requires assembly, unlikely from AI agents)
- Statically-linked binaries (no dynamic linker = no preload)
- Non-exec actions (file reads via open(), network via connect())

### Threat model alignment
Our threat is **hallucinating/manipulated AI agents**, not **adversarial human attackers**. An AI agent doesn't know to unset LD_PRELOAD. The bypass resistance is low against a determined human but high against the actual threat.

## Performance

- ~5-15ms overhead per intercepted exec call (HTTP round-trip to localhost)
- Negligible for AI agent workloads (agents exec commands seconds apart, not milliseconds)
- No overhead on non-exec syscalls (read, write, connect are not intercepted)
- Library loads once at process start, stays in memory

## Implementation Plan

### Week 1: C library proof of concept
- [ ] `preload/librampart.c` — intercept execve, execvp, system
- [ ] HTTP client using libcurl
- [ ] Test with `LD_PRELOAD=./librampart.so bash`
- [ ] Verify against live `rampart serve`

### Week 2: CLI integration
- [ ] `cmd/rampart/cli/preload.go` — find library, start serve, set env, exec
- [ ] `rampart preload -- <command>` working end-to-end
- [ ] Auto-start `rampart serve` if not running

### Week 3: macOS + polish
- [ ] Build `librampart.dylib` for macOS
- [ ] Test with DYLD_INSERT_LIBRARIES
- [ ] Document SIP limitations
- [ ] Add `posix_spawn` interception (macOS preference)
- [ ] Goreleaser integration (ship library with releases)

### Week 4: Testing + docs
- [ ] Test with real agents: Codex CLI, Python agent, Node.js agent
- [ ] Performance benchmarks
- [ ] README section + docs page
- [ ] Security review of C code

## Example Policy (works with existing format)

No policy changes needed. The preload library sends standard `/v1/preflight/exec` requests, same as the shell shim. Existing policies work automatically.

## Alternatives Considered

| Approach | Why not (for now) |
|----------|-------------------|
| ptrace | Linux-only, complex, high maintenance |
| seccomp-bpf | Linux-only, kernel-level, needs root |
| eBPF | Linux-only, high effort, needs recent kernel |
| macOS Endpoint Security | macOS-only, needs entitlements/approval |

LD_PRELOAD is the only approach that works cross-platform with reasonable effort. The kernel-level approaches can be v0.3+ for users who need higher bypass resistance.

## Success Criteria

- Works with Codex CLI, Python agents, Node.js agents on Linux
- Works with Homebrew-installed tools on macOS
- < 20ms average overhead per exec call
- Existing policies enforce correctly
- Fails open when serve is down
- Zero crashes or memory corruption in library
