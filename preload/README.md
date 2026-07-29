# Rampart Preload Library

An optional native interposition library that asks Rampart before compatible
dynamically linked processes call supported libc exec/spawn functions. It is a
defense-in-depth fallback, not a universal or system-wide sandbox.

## Building

The compiled library is not included in GitHub release archives or the Homebrew
package. Build it from the same Rampart source revision as your CLI:

```bash
cd preload
make          # builds librampart.so (Linux) or librampart.dylib (macOS)
make install  # copies to ~/.rampart/lib/
```

**Dependencies:** `gcc`, `libcurl-dev`, `libpthread`

```bash
# Ubuntu/Debian
sudo apt install build-essential libcurl4-openssl-dev

# macOS
brew install curl
```

`rampart setup` does not compile native code. Run `make install` explicitly;
the CLI will then find the library in `~/.rampart/lib/`.

## Overview

The Rampart preload library (`librampart.so` / `librampart.dylib`) works by:

1. Intercepting supported libc entry points (`execve`, `execvp`, `system`, `popen`, etc.)
2. Consulting the Rampart policy server via HTTP before allowing execution
3. Applying the configured degraded behavior if the policy server is unreachable
4. Providing comprehensive logging and debugging capabilities

```
Agent Process → calls execve() → librampart.so intercepts
  → HTTP POST to rampart serve /v1/preflight/exec
  → allowed:true → call real execve via dlsym(RTLD_NEXT)
  → allowed:false → errno=EPERM, return -1
  → transport/5xx failure → RAMPART_FAIL_OPEN decides
  → auth/protocol/client failure → deny in enforce mode
```

## Building

### Prerequisites

- GCC or Clang compiler
- libcurl development headers
- pthread support
- Make

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get install build-essential libcurl4-openssl-dev
```

**Linux (CentOS/RHEL):**
```bash
sudo yum install gcc libcurl-devel
```

**macOS:**
```bash
# Install Xcode command line tools
xcode-select --install

# libcurl is included with macOS
```

### Build Commands

```bash
# Standard build
make

# Debug build with symbols
make debug

# AddressSanitizer build for development
make asan

# Cross-platform - automatically detects Linux/macOS
make all
```

**Build outputs:**
- Linux: `librampart.so`
- macOS: `librampart.dylib`

## Usage

### Manual Usage

**Linux:**
```bash
export LD_PRELOAD="./librampart.so"
export RAMPART_URL="http://127.0.0.1:9090"
export RAMPART_TOKEN="your-token-here"

# Run a compatible dynamically linked process tree
python my_agent.py
node agent.js
./my_binary
```

**macOS:**
```bash
export DYLD_INSERT_LIBRARIES="./librampart.dylib"
export RAMPART_URL="http://127.0.0.1:9090"
export RAMPART_TOKEN="your-token-here"

# Run a compatible dynamically linked process tree
python my_agent.py
```

### Via Rampart CLI (Recommended)

```bash
# The rampart CLI will handle all environment setup
rampart preload -- python my_agent.py
rampart preload -- codex
rampart preload --mode monitor -- risky_tool
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RAMPART_URL` | `http://127.0.0.1:9090` | Policy server URL |
| `RAMPART_TOKEN` | (none) | Bearer auth token |
| `RAMPART_MODE` | `enforce` | `enforce` / `monitor` / `disabled` |
| `RAMPART_FAIL_OPEN` | `1` | Allow transport and HTTP 5xx failures (1=yes, 0=no); never bypasses auth, malformed-response, or local safety failures in enforce mode |
| `RAMPART_AGENT` | `preload` | Agent name for audit logs |
| `RAMPART_SESSION` | `preload-<pid>` | Session ID for tracking |
| `RAMPART_DEBUG` | `0` | Debug logging to stderr (1=on, 0=off) |

These values and the initial loader chain are snapshotted when the library is
loaded. For APIs that accept an explicit child environment (`execve`,
`execvpe`, and `posix_spawn*`), Rampart removes caller-supplied replacements
for those control variables and passes the trusted snapshots to the child.

### Mode Behavior

- **enforce**: Block denied commands, allow approved commands
- **monitor**: Log all commands but never block (audit mode)
- **disabled**: Pass through all commands without policy checks

## Intercepted Functions

The library intercepts these libc functions:

- `execve(path, argv, envp)` — Primary libc exec entry point
- `execvp(file, argv)` — PATH-resolved exec
- `execvpe(file, argv, envp)` — PATH-resolved with environment (Linux only)
- `system(command)` — Shell command execution
- `popen(command, type)` — Pipe to shell command
- `posix_spawn(...)` — Modern spawn API (heavily used on macOS)
- `posix_spawnp(...)` — PATH-resolved modern spawn API

## Testing

### Integration Tests

Run the native-library test suite:

```bash
# Run all tests
./test_preload.sh

# Build and test
make test
```

**Test coverage:**
- Library loading without crashes
- Debug output functionality
- Policy enforcement (when `rampart serve` is running)
- Fail-open/fail-closed behavior for transport and server failures
- Fail-closed behavior for authentication, malformed, and oversized responses
- `posix_spawn` and `posix_spawnp` interception
- `system()` and `popen()` interception
- Monitor and disabled modes
- Child process inheritance

### Manual Testing

**Basic functionality:**
```bash
# Test library loads
LD_PRELOAD=./librampart.so echo "hello"

# Test debug output
RAMPART_DEBUG=1 LD_PRELOAD=./librampart.so echo "hello" 2>&1 | grep rampart

# Test fail-open (server unreachable)
RAMPART_URL=http://127.0.0.1:99999 LD_PRELOAD=./librampart.so echo "should work"
```

**Policy enforcement (requires `rampart serve` running):**
```bash
export LD_PRELOAD="./librampart.so"
export RAMPART_URL="http://127.0.0.1:9090"
export RAMPART_TOKEN="your-token"

# Should work (typically allowed)
echo "hello from preload"
ls /tmp

# Should be denied by policy (if configured)
rm -rf /tmp/test
curl http://example.com
```

## Installation

```bash
# Install to user directory
make install

# Library will be installed to ~/.rampart/lib/
```

The `rampart` CLI will automatically find libraries in:
1. `~/.rampart/lib/librampart.{so,dylib}`
2. `/usr/local/lib/librampart.{so,dylib}`
3. Next to the `rampart` binary

## Performance

The library is optimized for minimal latency:

- **Persistent HTTP keep-alive connection** — One connection per process, reused for all policy checks
- **Manual JSON parsing** — No external JSON library dependencies
- **Bounded degraded behavior** — Transport/5xx failures follow `RAMPART_FAIL_OPEN`; unsafe client/protocol failures deny in enforce mode
- **Thread/fork-safe transport state** — Uses a pthread mutex for the persistent curl handle and resets inherited connection state across `fork()` before the child performs policy checks

## Platform Support

### Linux ✅
- **Mechanism:** `LD_PRELOAD`
- **Works with:** compatible dynamically linked programs that call the intercepted libc symbols
- **Limitations:** static binaries, direct syscalls, secure-execution contexts, and runtimes that bypass those symbols are not intercepted

### macOS ✅
- **Mechanism:** `DYLD_INSERT_LIBRARIES`
- **Works with:** compatible non-hardened user software that calls the intercepted libc symbols
- **System Integrity Protection (SIP)** blocks system binaries but allows user software
- **Limitations:** 
  - `/usr/bin/*` and `/System/*` binaries are protected
  - Apple-signed hardened binaries may be protected
  - Static binaries cannot be intercepted

### Windows ❌
- Not supported. Use native hooks or direct Rampart API integration.

## Security Considerations

### Threat Model

This library is designed to protect against **hallucinating/manipulated AI agents**, not adversarial human attackers.

**What it catches:**
- AI agent executing `rm -rf /`
- Malicious skills/plugins running credential theft commands
- Unintended network exfiltration via `curl`/`wget`
- Calls through the supported interposed libc functions while the library remains loaded

**What it does NOT catch:**
- Direct syscalls or runtimes that bypass the interposed libc functions
- Statically-linked binaries (no dynamic linker)
- Secure-execution/SIP/hardened contexts that discard or reject loader injection
- Non-exec file operations (`open()`, `connect()`)

### Bypass Resistance

- **Low** against determined human attackers
- Useful against accidental or model-generated commands that remain inside the
  compatible process boundary; native host hooks remain preferred

## Known Limitations

1. **Static binaries**: Cannot be intercepted (no dynamic linking)
2. **macOS SIP**: System binaries are protected and cannot be intercepted
3. **Direct syscalls**: Rare, but possible to bypass libc wrappers
4. **Manual bypass**: Sophisticated attackers can unset `LD_PRELOAD`
5. **Non-exec attacks**: File system operations outside of exec are not monitored

## Development

### Code Quality

- **Strict compilation** — Built with `-Wall -Wextra -Werror -pedantic`
- **Thread-safe HTTP reuse** — Every shared easy-handle operation is serialized
- **Bounded inputs** — Request and response sizes are capped; malformed JSON fails closed in enforce mode
- **Minimal dependencies** — Only libcurl and pthreads

### Debugging

Enable debug logging:
```bash
export RAMPART_DEBUG=1
LD_PRELOAD=./librampart.so your_command 2>&1 | grep rampart
```

Use AddressSanitizer for development:
```bash
make asan
RAMPART_DEBUG=1 LD_PRELOAD=./librampart.so your_command
```

### Contributing

1. Keep the security boundary auditable and avoid unnecessary dependencies
2. All changes must pass `make test` and the Linux `test_preload.sh` contract suite
3. Test on both Linux and macOS
4. Run AddressSanitizer builds before submitting
5. Update tests for new functionality

## Troubleshooting

**Library won't load:**
- Check that libcurl is installed
- Verify library architecture matches binary (64-bit vs 32-bit)
- Try `ldd librampart.so` (Linux) or `otool -L librampart.dylib` (macOS)

**Commands not being intercepted:**
- Enable debug logging with `RAMPART_DEBUG=1`
- Check that binary is dynamically linked: `file your_binary`
- On macOS, check if binary is SIP-protected: `codesign -dv your_binary`

**Server connection fails:**
- Verify `rampart serve` is running on the configured port
- Check `RAMPART_URL` and `RAMPART_TOKEN` are correct
- Test server directly: `curl -H "Authorization: Bearer $RAMPART_TOKEN" $RAMPART_URL/health`

**Performance issues:**
- Check if keep-alive connections are working (server logs)
- Monitor network latency to policy server

## License

See the main Rampart repository for license information.
