# Threat Model

> Last reviewed: 2026-03-03 | Applies to: v0.7.4

Rampart is a policy engine for AI agents — not a sandbox, not a hypervisor, not a full isolation boundary. This document describes what Rampart protects against, what it doesn't, and why.

## What Rampart Is

A firewall for AI agent tool calls. It evaluates agent tool calls — shell commands, file operations, and fetch requests — against YAML policies and makes allow/deny/log decisions in microseconds. Rampart sees what the agent framework sends it (tool call metadata), not raw syscalls or network traffic. It's designed to catch the 95%+ case: an AI agent that hallucinated a dangerous command or got manipulated by a prompt injection.

## Primary Threat: Misbehaving AI Agents

Rampart's target threat is an AI agent that:

- **Hallucinated a destructive command** (`rm -rf /`, `DROP TABLE`)
- **Was manipulated by prompt injection** (malicious content in a file or webpage told it to exfiltrate data)
- **Made a well-intentioned mistake** (wrong environment, wrong file, wrong server)
- **Escalated beyond its intended scope** (sub-agent spawning unrestricted tool calls)

These agents aren't adversarial — they're confused, manipulated, or wrong. Rampart catches them reliably.

## Not the Target: Adversarial Human Attackers

Rampart does **not** claim to stop a skilled human who has already compromised your system. If an attacker has shell access, they can bypass Rampart the same way they'd bypass any userspace tool. Rampart is one layer in defense-in-depth, not a replacement for OS hardening, network segmentation, or access control.

## Trust Boundaries

```
┌─────────────────────────────────────────────┐
│ Trusted                                      │
│  • Policy files (admin-authored YAML)        │
│  • Rampart binary                            │
│  • rampart serve process                     │
│  • Audit log directory (when user-separated) │
│  • Policy registry sources (when verified)   │
│  • HMAC signing key (~/.rampart/signing.key) │
├─────────────────────────────────────────────┤
│ Untrusted                                    │
│  • AI agent tool calls (all input)           │
│  • Agent-generated commands                  │
│  • MCP tool call parameters                  │
│  • Webhook response payloads (validated)     │
│  • Project-local .rampart/policy.yaml files  │
│  • Community policies (verified by SHA-256)  │
└─────────────────────────────────────────────┘
```

Policy files are the security boundary. If an attacker can modify policy files, Rampart's guarantees do not hold. This is why [user separation](../README.md#security-recommendations) is recommended for production.

## Known Limitations

### 1. Interpreter Bypass

Rampart evaluates the command string passed to the shell. This applies to **all integration methods** — native hooks (Claude Code, Cline), wrap mode, LD_PRELOAD, and the HTTP API all see the same command string. If an agent runs `python3 script.py`, Rampart sees and evaluates `python3 script.py` — but cannot inspect what `script.py` does internally.

**Mitigations:**
- **LD_PRELOAD cascade** (v0.1.9+): `rampart preload` and `rampart wrap` intercept child processes spawned by allowed commands. `python3 script.py` calling `os.system("rm -rf /")` is caught — the subprocess goes through Rampart's policy engine.
- **Interpreter one-liner blocking** (v0.6.9+): Patterns like `python3 -c`, `node -e`, `ruby -e`, `perl -e` with dangerous system calls are blocked by default in standard/paranoid policies.
- The optional [rampart-verify](https://github.com/peg/rampart-verify) sidecar uses LLM classification to assess intent of ambiguous commands via `action: webhook`.

**Remaining surface:** LD_PRELOAD cascade only applies to wrap/preload modes, not native hooks (Claude Code, Cline). Programs that use native file I/O without shelling out, or setuid binaries that drop LD_PRELOAD, are not covered.

**Multi-step sequences:** With file tool coverage enabled (native hooks or `--patch-tools`), write-then-execute sequences are evaluated at both steps independently — the write is checked against file policies and the exec against command policies.

### 2. Audit Log Rewrite

The hash-chained audit trail detects **partial tampering** — editing, inserting, or deleting individual records breaks the chain. However, a complete rewrite from scratch with a new valid chain is not detectable from the log file alone.

**Mitigations:**
- Run `rampart serve` as a [separate user](../README.md#security-recommendations) so the agent can't access audit files
- Enable SIEM export (`--syslog` or `--cef`) to send events to an external immutable system
- Webhook notifications send real-time alerts to Discord/Slack — a separate record
- External chain anchors every 100 events provide additional integrity checkpoints

**For compliance environments:** Pair with external immutable logging (CloudTrail, Wazuh, etc.) for an independent trust anchor. See the [SIEM integration guide](../README.md#siem-integration).

### 3. Token Exposure in Wrap Mode

The `rampart wrap` shim needs a bearer token to authenticate with `rampart serve`. The token is stored in a `0600` file (not embedded in the shim script). However, the agent user can still read this file.

**Mitigations:**
- Run `rampart serve` as a separate user and store the token in that user's home directory with restricted permissions
- Use native hooks (`rampart setup claude-code`) instead of wrap mode — hooks don't require a token file

**Resolution:** Use [user separation](../README.md#security-recommendations) for production deployments, or prefer native hooks which don't require a token file.

### 4. Encoding and Obfuscation

An agent could encode commands to bypass pattern matching:
- Base64-encoded payloads
- Variable expansion and command splitting
- Subshell nesting, heredocs, process substitution

**Mitigations (v0.6.9+):**
- Rampart decodes base64 commands before pattern matching
- Leading shell comments and ANSI escape sequences are stripped
- Null bytes and control characters are removed
- Subcommand extraction: `$(cmd)`, backticks, `eval 'cmd'` — inner commands are matched independently
- Common obfuscation patterns (`base64 *`, `eval *`, `xxd -r | bash`) trigger deny rules in standard policy
- The semantic verification sidecar classifies intent regardless of encoding

**Coverage:** The two-layer approach (pattern matching + LLM classification) significantly reduces the obfuscation surface. Pattern matching catches known encodings; the LLM layer catches intent regardless of how the command is formatted. v0.6.9 closed 10 specific bypass vectors identified in a security audit.

### 5. Framework-Specific Patching

Some agent frameworks (e.g., OpenClaw) don't expose hook points for file operations. Rampart's `--patch-tools` option modifies framework source files to add policy checks before read/write/edit operations. These patches don't survive framework upgrades — they modify files in `node_modules` that get replaced on update.

**Mitigations:**
- `rampart setup openclaw --patch-tools` must be re-run immediately after OpenClaw upgrades to restore protection
- Native hook integrations (Claude Code, Cline) don't have this limitation — they use the framework's own hook system

**Security implications:**
- **Timing window:** Between framework upgrade and re-patch, file tools bypass all policies (exec shim remains active)
- **Silent degradation:** If the target code changes in a new version, patches fail to apply and file tools fail-open without warning. The patch script exits with an error, but if run unattended this could go unnoticed.

**Trade-off:** Monkey-patching is fragile but functional. It closes a real security gap today while proper upstream hook support is developed. The patches fail-open — if the patched code changes in an upgrade, the worst case is that file tools bypass Rampart (reverting to the pre-patch state), not that they break.

### 6. Fail-Open Behavior

When `rampart serve` is unreachable (crashed, network issue), the shim defaults to **fail-open** — commands execute without policy checks. This is a deliberate design choice: fail-closed would lock you out of your own machine.

**Mitigations:**
- Monitor the Rampart service and alert on downtime
- Use systemd/launchd to auto-restart on failure (`rampart serve install` does this)
- Webhook notifications confirm the service is actively evaluating commands

**Trade-off:** Fail-open means a brief security gap during outages. Fail-closed means a crashed Rampart bricks your agent (and potentially your system). We chose availability over strict enforcement. This is configurable for environments where fail-closed is preferred.

### 7. Regex Complexity Limits

Rampart imposes limits on regex patterns used for response matching to prevent ReDoS.

**Current limits:**
- **Maximum pattern length**: 500 characters
- **Nested quantifiers**: Rejected at load time (patterns like `(a+)*`)
- **Execution timeout**: 100ms per regex match
- **Response cap**: 1MB maximum for response-side evaluation

These limits protect against both accidental performance degradation and malicious patterns. They prevent policy authors from creating DoS conditions, and prevent attackers from injecting malicious regex patterns via webhook-driven policy updates. Patterns exceeding these limits are rejected at policy load time with clear error messages.

### 8. No TLS on HTTP API

`rampart serve` communicates over plaintext HTTP. On localhost this is acceptable; for remote or team deployments, this means policy decisions transit unencrypted.

**Mitigations:**
- Default bind is `127.0.0.1` (localhost only)
- For remote access, use a reverse proxy with TLS or SSH tunnel
- TLS support for `rampart serve` is planned for a future release

### 9. In-Memory Approval Store

Pending approvals are stored in memory and lost on service restart. If `rampart serve` restarts while an approval is pending, the requesting agent receives a timeout/denial.

**Mitigations:**
- Approvals typically resolve within seconds (human clicks approve/deny)
- Service restarts are rare during active sessions
- Persistent approval storage is planned for a future release

### 10. Project Policy Trust

Project-local `.rampart/policy.yaml` files are loaded automatically when present. A malicious repository could include a permissive project policy.

**Mitigations (v0.6.9+):**
- Project policies can only **add restrictions**, not weaken global policies (deny-wins)
- Set `RAMPART_NO_PROJECT_POLICY=1` to skip project policy loading in untrusted repos
- Project policy denials are prefixed with `[Project Policy]` for visibility

### 11. Community Policy Supply Chain

`rampart policy fetch` downloads policies from the registry with SHA-256 verification. However, the registry itself is hosted in the main repo — a compromise of the repository could introduce malicious policies.

**Mitigations:**
- SHA-256 verification prevents modification after registry publication
- `--dry-run` flag allows inspection before installation
- Policy linting (`rampart policy lint`) validates syntax and flags suspicious patterns

## Integration-Specific Notes

| Integration | Exec Coverage | File Coverage | Response Scanning | Cascade |
|-------------|--------------|---------------|-------------------|---------|
| Native hooks (Claude Code) | ✅ | ✅ (via hooks) | ✅ PostToolUse | ❌ |
| Native hooks (Cline) | ✅ | ✅ (via hooks) | ❌ | ❌ |
| `rampart wrap` | ✅ | ❌ | ❌ | ✅ LD_PRELOAD |
| `rampart preload` | ✅ | ❌ | ❌ | ✅ LD_PRELOAD |
| `rampart setup openclaw --patch-tools` | ✅ (shim) | ✅ (patched) | ❌ | ❌ |
| HTTP proxy | ✅ | ✅ | ✅ | ❌ |
| MCP proxy | ✅ | ✅ | ✅ | ❌ |

### Platform Notes: macOS

v0.4.4 added 17 macOS-specific built-in policies to the standard and paranoid profiles. These cover:

- **Keychain access** — blocks unauthorized reads from the macOS Keychain (`security` tool abuse)
- **Gatekeeper bypass** — blocks attempts to disable or circumvent Gatekeeper (`spctl`, `xattr -d com.apple.quarantine`)
- **Persistence mechanisms** — blocks writes to `~/Library/LaunchAgents/`, `~/Library/LaunchDaemons/`, and login items
- **User management** — blocks `dscl` and `sysadminctl` commands that create or elevate user accounts
- **AppleScript shell execution** — blocks `osascript -e "do shell script …"` patterns used to run commands via AppleScript

These policies are active automatically when using the standard or paranoid profile on macOS.

### Platform Notes: Windows

v0.6.6 added Windows policy parity. Key differences from Linux/macOS:

- **No LD_PRELOAD** — `rampart preload` is not available. Use native hooks or wrap mode instead.
- **No POSIX file permissions** — `chmod 0600` is not enforced by the OS. Token files and signing keys are created with default permissions; use Windows ACLs for hardening.
- **Binary upgrade** — Windows forbids overwriting a running executable. `rampart upgrade` renames the current binary to `.rampart.exe.old` first, then installs the new one.
- **Path separators** — Rampart normalizes backslashes to forward slashes internally for consistent policy matching.
- **Service management** — `rampart serve install` creates a Windows service (not systemd/launchd). Auto-restart is configured by default.

## Deployment Recommendations

| Setup | Agent reads audit? | Agent modifies policy? | Best for |
|-------|-------------------|----------------------|----------|
| Same user (default) | ✅ Yes | ✅ Yes | Development, testing |
| Separate user | ❌ No | ❌ No | Production, unsupervised agents |
| Separate user + SIEM | ❌ No | ❌ No | Enterprise, compliance |

**Prerequisite:** The agent must run as a non-root user. If the agent runs as root, user separation provides no protection — root can read and modify all files regardless of ownership.

**Sudo caveat:** Many real-world deployments grant the agent user `sudo` access for system administration tasks. An agent with unrestricted `sudo` (e.g., `NOPASSWD: ALL`) can bypass user separation by running `sudo cat /etc/rampart/policy.yaml` or `sudo rm -rf /var/lib/rampart/audit/`. Rampart still catches the common case — a hallucinating or prompt-injected agent won't think to `sudo` around a deny rule — but it's not a hard boundary.

**Best practice:** Restrict sudo to the specific commands your agent needs (e.g., `apt`, `systemctl`, `k3s`) rather than granting blanket access. This limits the blast radius regardless of Rampart.

### 12. API Self-Approval

The HTTP API uses a single bearer token for both tool call evaluation and administrative actions (approving requests, deleting rules, reloading policy). In same-user deployments, the agent can read `~/.rampart/token` and approve its own denied requests by hitting `POST /v1/approvals/{id}/resolve` directly.

**Mitigations:**
- User separation prevents the agent from reading the token file
- The standard policy blocks reads of `**/.rampart/**` via write/edit tools
- Splitting eval and admin tokens is tracked in [#180](https://github.com/peg/rampart/issues/180)

**Current status:** This is a known gap in same-user deployments. The fix (separate eval and admin tokens) is designed and will ship in a future release with zero user friction — both tokens auto-generate and the shim only receives the eval token.

## Self-Modification Protection

Rampart protects its own configuration from agent tampering through two layers:

1. **Exec-level:** The standard policy blocks `rampart allow`, `rampart block`, `rampart init`, and shell redirects to `.rampart/` directories. This prevents agents from running CLI commands that modify policy.
2. **Write/Edit-level:** The standard policy blocks write and edit tool calls targeting `**/.rampart/**`. This prevents agents from directly overwriting policy files, config, or audit logs via file tools.

Both layers are active by default in the `standard` and `paranoid` profiles. The `yolo` profile disables these protections — it's named that way for a reason.

**Remaining surface:** An agent with exec access could modify Rampart's binary on disk (if file permissions allow), or kill the `rampart serve` process (triggering fail-open). User separation mitigates both: run `rampart serve` as a different user than the agent.

## Philosophy

Rampart is a **seatbelt, not a roll cage**. It catches the vast majority of dangerous situations an AI agent will encounter — accidental or manipulated. It doesn't claim to stop every possible attack vector, and we're honest about what falls outside its scope.

If you need full isolation, use a sandbox (container, VM, or a tool like [nono](https://github.com/nicholasgasior/nono)). Rampart and sandboxes are complementary — use both for defense in depth.

---

## Reporting Security Issues

If you've found a vulnerability not covered here, please email [rampartsec@pm.me](mailto:rampartsec@pm.me). We'll acknowledge within 48 hours and work with you on coordinated disclosure. Please do **not** open public issues for security vulnerabilities.
