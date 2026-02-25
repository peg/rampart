# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Rampart, please report it responsibly.

**Email:** rampartsec@pm.me (or open a [private security advisory](https://github.com/peg/rampart/security/advisories/new) on GitHub)

**Please include:**
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

**Response timeline:**
- Acknowledgment within 48 hours
- Initial assessment within 7 days
- Fix or mitigation within 30 days for critical issues

## Scope

The following are in scope:
- Policy engine bypass (tool call allowed when policy should deny)
- Audit trail tampering that evades `rampart audit verify`
- Authentication bypass on the proxy or daemon API
- Remote code execution
- Denial of service against the proxy/daemon

The following are **known limitations**, not vulnerabilities:
- **Pattern evasion via obfuscation** (e.g., variable expansion `$CMD`, base64 encoding). Rampart matches against the literal command string. For common shell wrappers (`bash -c`, `sh -c`), the standard policy includes explicit patterns. For obfuscation, combine with [semantic verification](https://github.com/peg/rampart-verify).
- **Proxy bypass** when the agent has direct shell access and isn't using daemon mode. The proxy is voluntary; use daemon mode with OpenClaw for enforced evaluation.
- **Agent modifying policy files** when it has write access to the filesystem. Restrict file permissions or use daemon mode.
- **Shim token extraction** when using `rampart wrap`. The proxy auth token is embedded in the shim script and readable by the wrapped agent. Use `rampart hook` (Claude Code native integration) for stronger isolation — no token is exposed.
- **Fail-open on proxy unavailability** when using `rampart wrap`. If the proxy process dies, the shim allows commands through rather than blocking the agent entirely. This is a deliberate design tradeoff — fail-closed would brick the agent.
- **Interpreter-based execution** (e.g., `python3 -c "os.system('rm -rf /')"`) bypasses shell-level interception. The hook integration catches this for agents that route all tool calls through the hook system.
- **Audit trail rewrite** by anyone with filesystem write access. The hash chain detects partial tampering but not a complete rewrite. No external trust anchor is used.

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest main | ✅ |
| < v1.0.0 | Pre-release, best-effort |

## Threat Model

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full threat model, including honest discussion of what Rampart does and doesn't protect against.
