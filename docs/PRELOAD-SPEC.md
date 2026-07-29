# Rampart Preload — Optional Native Exec Interposition

**Status:** Optional, source-built native library | **Last updated: v1.4 development**

**See also:** `rampart preload --help`, [README](../README.md#ld_preload)

## Overview

`rampart preload` provides best-effort defense in depth via LD_PRELOAD (Linux) /
DYLD_INSERT_LIBRARIES (macOS). It interposes a documented set of libc
exec/spawn functions and routes those calls through Rampart before execution.
It is not a kernel boundary and does not cover every runtime or process.

The CLI command ships in release archives and Homebrew, but the native library
does not. Build the library from the matching source revision with
`make -C preload install` before using this path.

This is the fallback for agents that do not have hook systems. Native hooks
(Claude Code, Codex, and Cline) remain the preferred integration; preload is
optional defense in depth or a fallback for other processes.

## User Experience

```bash
# Protect a compatible agent without modifying that agent's configuration
rampart preload -- your-agent
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

### 1. `librampart.so` / `librampart.dylib`

Intercepts:
- `execve` — primary libc exec entry point
- `execvp` / `execvpe` — PATH-resolved variants
- `system` — libc shell wrapper
- `popen` — pipe to shell command
- `posix_spawn` — modern spawn API (macOS uses this heavily)
- `posix_spawnp` — PATH-resolved modern spawn API

Each intercepted call:
1. Extracts the command + arguments
2. Builds JSON payload: `{"agent":"preload","session":"<id>","params":{"command":"<cmd>"},"enforce":true}`
3. HTTP POST to `$RAMPART_URL/v1/preflight/exec` with `$RAMPART_TOKEN`
4. If `allowed: true` → call original function via `dlsym(RTLD_NEXT, "execve")`
5. If `allowed: false` → set `errno = EPERM`, return -1
6. If a transport or HTTP 5xx failure occurs → use `$RAMPART_FAIL_OPEN`
7. If authentication, request construction, response bounds, or JSON validation fails → deny in enforce mode

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

The current GoReleaser archives contain only the Go CLI. Native libraries are
not cross-compiled or distributed in release archives because each target must
be built and verified against its platform compiler and libcurl ABI.

## Environment Variables

The library reads from env (set by `rampart preload` command):

| Variable | Default | Description |
|----------|---------|-------------|
| `RAMPART_URL` | `http://127.0.0.1:9090` | Policy server URL |
| `RAMPART_TOKEN` | (none) | Bearer auth token |
| `RAMPART_MODE` | `enforce` | enforce / monitor / disabled |
| `RAMPART_FAIL_OPEN` | `1` | Allow transport/HTTP 5xx failures; authentication, protocol, and local safety failures still deny in enforce mode |
| `RAMPART_AGENT` | `preload` | Agent name for audit |
| `RAMPART_SESSION` | `preload-<pid>` | Session ID |
| `RAMPART_DEBUG` | `0` | Log to stderr |

The library snapshots these values and its loader chain at initialization. It
reconstructs explicit child environments so an `execve`/`execvpe`/
`posix_spawn*` caller cannot substitute less restrictive Rampart values for
the next compatible process.

## Platform Support

### Linux (primary target)
- LD_PRELOAD supports many dynamically linked user programs
- Static binaries, direct syscalls, secure-execution contexts, and runtimes
  that bypass the interposed libc symbols are not interceptable
- No special permissions needed

### macOS
- DYLD_INSERT_LIBRARIES works for non-SIP-protected binaries
- Can work with compatible non-hardened user programs
- ❌ Blocked: /usr/bin/*, /System/*, Apple-signed hardened binaries
- No need to disable SIP — AI agents are user-installed software

### Windows
- No equivalent mechanism. Not supported. Use native hooks or `rampart serve` API instead.

## Security Considerations

### What this catches
- AI agent hallucinating `rm -rf /`
- Malicious skills/plugins executing credential theft
- Unintended network exfiltration via curl/wget
- Calls through supported interposed libc functions in the loaded process tree

### What this does NOT catch
- Direct syscalls or runtimes that bypass libc interposition
- Statically-linked binaries (no dynamic linker = no preload)
- Processes where secure-execution, SIP, or hardening removes loader injection
- Non-exec actions (file reads via open(), network via connect())

### Threat model alignment
The intended threat is accidental or model-generated execution inside a
compatible process boundary, not a determined local attacker. Treat preload as
defense in depth; use native host hooks and OS containment where available.

## Performance

The implementation reuses one libcurl handle and its localhost HTTP
keep-alive connection per process. Each process has its own connection and
every intercepted call receives a fresh policy decision. Rampart does not
currently implement a Unix-domain-socket transport for this library.

Fallback path (if serve is unreachable): honor `RAMPART_FAIL_OPEN` after the bounded connection attempt. There are no retries. Authentication failures, malformed or oversized responses, and client-side safety failures never use this fallback in enforce mode.

**What we do NOT do:**
- No in-process policy evaluation (keeps library minimal and auditable)
- No shared memory mapping (complexity not justified)
- No caching of decisions (policies can change, every call must be fresh)

## Implementation History

LD_PRELOAD interception shipped in v0.1.5 with coverage of `execve`, `execvp`, `execvpe`, `system`, `popen`, `posix_spawn`, and `posix_spawnp`. The macOS `librampart.dylib` uses `DYLD_INSERT_LIBRARIES`; Linux uses `LD_PRELOAD`.

## Example Policy (works with existing format)

No policy changes needed. The preload library sends standard `/v1/preflight/exec` requests, same as the shell shim. Existing policies work automatically.

## Alternatives Considered

| Approach | Why not (for now) |
|----------|-------------------|
| ptrace | Linux-only, complex, high maintenance |
| seccomp-bpf | Linux-only, kernel-level, needs root |
| eBPF | Linux-only, high effort, needs recent kernel |
| macOS Endpoint Security | macOS-only, needs entitlements/approval |

Dynamic-loader interposition is the maintained optional fallback on Linux and
macOS. It trades portability and low setup cost for a weaker boundary than
kernel or OS-native containment.

## Success Criteria

- Works with the explicitly tested compatible agent/runtime matrix
- Existing policies enforce correctly without modification
- Applies the documented bounded degraded behavior when serve is unavailable
- Native unit and live contract suites pass on the supported Linux/macOS matrix
- The C boundary and its dependency surface remain directly auditable
