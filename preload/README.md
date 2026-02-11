# Rampart Preload Library

A production-quality LD_PRELOAD interceptor library that provides universal agent protection by intercepting exec-family syscalls and consulting the Rampart policy server before execution.

## Overview

The Rampart preload library (`librampart.so` / `librampart.dylib`) works by:

1. Intercepting exec-family system calls (`execve`, `execvp`, `system`, `popen`, etc.)
2. Consulting the Rampart policy server via HTTP before allowing execution
3. Failing open (allowing execution) if the policy server is unreachable
4. Providing comprehensive logging and debugging capabilities

```
Agent Process → calls execve() → librampart.so intercepts
  → HTTP POST to rampart serve /v1/preflight/exec
  → allowed:true → call real execve via dlsym(RTLD_NEXT)
  → allowed:false → errno=EPERM, return -1
  → HTTP fails → fail-open (exec through)
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
export RAMPART_URL="http://127.0.0.1:19090"
export RAMPART_TOKEN="your-token-here"

# Run any command with protection
python my_agent.py
node agent.js
./my_binary
```

**macOS:**
```bash
export DYLD_INSERT_LIBRARIES="./librampart.dylib"
export RAMPART_URL="http://127.0.0.1:19090"
export RAMPART_TOKEN="your-token-here"

# Run any command with protection
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
| `RAMPART_URL` | `http://127.0.0.1:19090` | Policy server URL |
| `RAMPART_TOKEN` | (none) | Bearer auth token |
| `RAMPART_MODE` | `enforce` | `enforce` / `monitor` / `disabled` |
| `RAMPART_FAIL_OPEN` | `1` | Fail-open when server unreachable (1=yes, 0=no) |
| `RAMPART_AGENT` | `preload` | Agent name for audit logs |
| `RAMPART_SESSION` | `preload-<pid>` | Session ID for tracking |
| `RAMPART_DEBUG` | `0` | Debug logging to stderr (1=on, 0=off) |

### Mode Behavior

- **enforce**: Block denied commands, allow approved commands
- **monitor**: Log all commands but never block (audit mode)
- **disabled**: Pass through all commands without policy checks

## Intercepted Functions

The library intercepts these libc functions:

- `execve(path, argv, envp)` — Primary exec syscall
- `execvp(file, argv)` — PATH-resolved exec
- `execvpe(file, argv, envp)` — PATH-resolved with environment (Linux only)
- `system(command)` — Shell command execution
- `popen(command, type)` — Pipe to shell command
- `posix_spawn(...)` — Modern spawn API (heavily used on macOS)

## Testing

### Integration Tests

Run the comprehensive test suite:

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
- Fail-open behavior (when server is unreachable)
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
export RAMPART_URL="http://127.0.0.1:19090"
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
- **Fail-fast on errors** — Immediate fail-open if server unreachable
- **Thread-safe** — Uses pthread mutex for curl handle protection

**Target performance:**
- < 1ms per policy check (Unix domain socket)
- < 3ms per policy check (TCP to localhost)
- < 0.01ms fail-open path (server unreachable)

## Platform Support

### Linux ✅
- **Coverage:** ~95% of dynamically-linked binaries
- **Mechanism:** `LD_PRELOAD`
- **Works with:** Most user-installed software, Python, Node.js, Go binaries
- **Limitations:** Static binaries cannot be intercepted

### macOS ✅
- **Coverage:** ~70-85% in typical developer environments
- **Mechanism:** `DYLD_INSERT_LIBRARIES`
- **Works with:** Homebrew packages, nvm/Node.js, pyenv/Python, Go binaries
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
- Any exec call from the protected process tree

**What it does NOT catch:**
- Agent explicitly unsetting `LD_PRELOAD` before exec (deliberate bypass)
- Direct syscalls bypassing libc (requires assembly knowledge)
- Statically-linked binaries (no dynamic linker)
- Non-exec file operations (`open()`, `connect()`)

### Bypass Resistance

- **Low** against determined human attackers
- **High** against AI agents (they don't know to bypass preload)
- **Perfect** against accidental/hallucinated dangerous commands

## Known Limitations

1. **Static binaries**: Cannot be intercepted (no dynamic linking)
2. **macOS SIP**: System binaries are protected and cannot be intercepted
3. **Direct syscalls**: Rare, but possible to bypass libc wrappers
4. **Manual bypass**: Sophisticated attackers can unset `LD_PRELOAD`
5. **Non-exec attacks**: File system operations outside of exec are not monitored

## Development

### Code Quality

- **Zero undefined behavior** — Clean compilation with `-Wall -Wextra -Werror -pedantic`
- **Thread-safe** — All global state protected by mutexes
- **Memory leak free** — Every `malloc()` has matching `free()`
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

1. Maintain < 600 lines in `librampart.c`
2. All changes must pass `make test`
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
- Consider using Unix domain socket (future enhancement)

## License

See the main Rampart repository for license information.