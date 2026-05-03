# Threat Model

> Last reviewed: 2026-04-30 | Applies to: v1.0.0-rc.1+

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

Policy files are the security boundary. If an attacker can modify policy files, Rampart's guarantees do not hold. This is why [user separation](../deployment/production-checklist.md) is recommended for production.

## Known Limitations

### 1. Interpreter Bypass

Rampart evaluates the command string passed to the shell. This applies to **all integration methods** — native hooks (Claude Code, Cline), wrap mode, LD_PRELOAD, and the HTTP API all see the same command string. If an agent runs `python3 script.py`, Rampart sees and evaluates `python3 script.py` — but cannot inspect what `script.py` does internally.

**Mitigations:**
- **LD_PRELOAD cascade** (v0.1.9+): `rampart preload` and `rampart wrap` intercept child processes spawned by allowed commands. `python3 script.py` calling `os.system("rm -rf /")` is caught — the subprocess goes through Rampart's policy engine.
- **Interpreter one-liner blocking** (v0.6.9+): Patterns like `python3 -c`, `node -e`, `ruby -e`, `perl -e` with dangerous system calls are blocked by default in standard/paranoid policies.
- The optional [rampart-verify](https://github.com/peg/rampart-verify) sidecar uses LLM classification to assess intent of ambiguous commands via `action: webhook`.

**Remaining surface:** LD_PRELOAD cascade only applies to wrap/preload modes, not native hooks (Claude Code, Cline). Programs that use native file I/O without shelling out, or setuid binaries that drop LD_PRELOAD, are not covered.

**Multi-step sequences:** With file tool coverage enabled (native hooks, OpenClaw native plugin, or legacy `--patch-tools`), write-then-execute sequences are evaluated at both steps independently — the write is checked against file policies and the exec against command policies.

### 2. Audit Log Rewrite

The hash-chained audit trail detects **partial tampering** — editing, inserting, or deleting individual records breaks the chain. However, a complete rewrite from scratch with a new valid chain is not detectable from the log file alone.

**Mitigations:**
- Run `rampart serve` as a [separate user](../deployment/production-checklist.md) so the agent can't access audit files
- Enable SIEM export (`--syslog` or `--cef`) to send events to an external immutable system
- Webhook notifications send real-time alerts to Discord/Slack — a separate record
- External chain anchors every 100 events provide additional integrity checkpoints

**For compliance environments:** Pair with external immutable logging (CloudTrail, Wazuh, etc.) for an independent trust anchor. See the [SIEM integration guide](../features/siem-integration.md).

### 3. Token Exposure in Wrap Mode

The `rampart wrap` shim needs a bearer token to authenticate with `rampart serve`. The token is stored in a `0600` file (not embedded in the shim script). However, the agent user can still read this file.

**Mitigations:**
- Run `rampart serve` as a separate user and store the token in that user's home directory with restricted permissions
- Use native hooks (`rampart setup claude-code`) instead of wrap mode — hooks don't require a token file

**Resolution:** Use [user separation](../deployment/production-checklist.md) for production deployments, or prefer native hooks which don't require a token file.

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

Older OpenClaw builds did not expose a native file-tool hook, so Rampart added `--patch-tools` as a compatibility path that modifies framework source files before read/write/edit operations. These patches don't survive framework upgrades — they modify files in `node_modules` that get replaced on update.

**Mitigations:**
- Prefer the native OpenClaw plugin on current builds (`rampart setup openclaw`) — it covers tool calls without dist patching
- `rampart setup openclaw --patch-tools` must be re-run immediately after OpenClaw upgrades to restore protection on legacy setups
- Native hook integrations (Claude Code, Cline) don't have this limitation — they use the framework's own hook system

**Security implications:**
- **Timing window:** Between framework upgrade and re-patch, file tools bypass all policies (exec shim remains active)
- **Silent degradation:** If the target code changes in a new version, patches fail to apply and file tools fail-open without warning. The patch script exits with an error, but if run unattended this could go unnoticed.

**Trade-off:** Monkey-patching is fragile but functional. It closes a real security gap today while proper upstream hook support is developed. The patches fail-open — if the patched code changes in an upgrade, the worst case is that file tools bypass Rampart (reverting to the pre-patch state), not that they break.

### 6. Degraded-Mode Behavior

Rampart does **not** behave identically across every integration when policy evaluation becomes unavailable. That difference is a real security boundary and has to be understood clearly.

**Current behavior:**
- `rampart wrap` and `rampart preload` default to **fail-open** — if `rampart serve` is unreachable, commands continue without policy checks unless you configure fail-closed behavior.
- The native OpenClaw plugin is stricter: sensitive tools such as `exec`, `write`, `edit`, `browser`, and `message` block when `rampart serve` is unavailable, while explicitly configured lower-risk tools (`read`, `web_fetch`, `web_search`, `image` by default) remain fail-open.
- Native hook integrations (Claude Code, Cline) evaluate policies locally in-process, so they do not depend on `rampart serve` for the core allow/deny path.

**Mitigations:**
- Monitor the Rampart service and alert on downtime
- Use systemd/launchd to auto-restart on failure (`rampart serve install` does this)
- Prefer native hooks or the native OpenClaw plugin when you want less reliance on a long-running local service
- For OpenClaw, tighten `failOpenTools` if your environment prefers a stricter degraded-mode posture

**Trade-off:** Fail-open improves availability but creates a temporary security gap during outages. Fail-closed reduces bypass risk but can break agent workflows when the policy service is sick. Rampart makes that trade-off explicit per integration rather than pretending one answer fits everything.

### 7. Regex Complexity Limits

Rampart imposes limits on regex patterns used for response matching to prevent ReDoS.

**Current limits:**
- **Maximum pattern length**: 500 characters
- **Nested quantifiers**: Rejected at load time (patterns like `(a+)*`)
- **Execution timeout**: 100ms per regex match
- **Response cap**: 1MB maximum for response-side evaluation

These limits protect against both accidental performance degradation and malicious patterns. They prevent policy authors from creating DoS conditions, and prevent attackers from injecting malicious regex patterns via webhook-driven policy updates. Patterns exceeding these limits are rejected at policy load time with clear error messages.

### 8. TLS on HTTP API

As of v0.7.4, `rampart serve` supports TLS via `--tls-auto` (self-signed ECDSA P-256) or `--tls-cert`/`--tls-key` (bring your own). On localhost, plaintext is still acceptable; for remote or team deployments, enable TLS.

**Notes:**
- Default bind is `127.0.0.1` (localhost only). Use `--addr 0.0.0.0` or another explicit interface only when you intend remote access.
- `--tls-auto` generates a self-signed cert stored in `~/.rampart/tls/` (1-year validity)
- The SHA-256 fingerprint is printed on startup for manual verification
- For production, use proper certs via `--tls-cert`/`--tls-key` or a reverse proxy

### 9. Approval Persistence Limits

Pending approvals are now persisted to a local JSONL journal in normal `rampart serve` setups, so a routine service restart no longer necessarily wipes the queue. That said, approvals are still a live runtime workflow, not a durable transaction system.

**Remaining limits:**
- Older or custom setups that disable persistence can still lose pending approvals on restart
- A corrupted or deleted persistence file can drop pending approval state
- An approval request that times out or restarts mid-flow can still surface to the agent as a denial/timeout

**Mitigations:**
- Keep the default approval persistence path intact
- Avoid unnecessary restarts during active approval flows
- Treat approvals as short-lived human decisions, not long-running queued work

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
| `rampart setup openclaw` | ✅ | ✅ | ❌ | ❌ |
| `rampart setup openclaw --patch-tools` | ✅ (shim) | ✅ (patched) | ❌ | ❌ |
| `rampart setup codex` | ✅ (LD_PRELOAD) | ❌ | ❌ | ✅ LD_PRELOAD |
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

Rampart now supports **per-agent tokens** with explicit scopes. Eval-only tokens can submit tool calls but cannot approve requests, reload policy, or mutate rules. That closes one big part of the old self-approval story.

The remaining risk is narrower but still real: in same-user deployments, any integration that exposes a readable **admin-capable token** to the agent process can still let that agent approve or mutate its own policy state by calling administrative endpoints directly.

**Where this still matters most:**
- `rampart wrap`
- `rampart preload`
- ad hoc HTTP clients using the shared admin token from `~/.rampart/token`

**Mitigations:**
- Use user separation so the agent cannot read the admin token
- Use per-agent eval-only tokens for HTTP/MCP clients whenever possible
- Prefer native hook/plugin integrations where the agent is not handed a general-purpose admin bearer token

**Current status:** Better than before, not magically solved. Scoped per-agent tokens reduce the blast radius, but same-user deployments with readable admin tokens are still not a hard security boundary.

### 13. Temporal Allow Expiry

v0.7.4 introduced temporal allows (`--for`, `--once`). Expired rules are **skipped during evaluation** but remain in the policy YAML until manually removed.

**Security implications:**
- Expired rules exist in the YAML but are inert — the engine checks `expires_at` before matching
- `--once` rules are now consumed after their first successful match and removed from the backing policy file by the proxy layer
- That removal is operationally best-effort rather than transactional: a crash at the wrong moment could leave a consumed `once` rule behind until cleanup or the next evaluation path removes it
- Automatic cleanup of expired rules is still not universal — use `rampart rules remove` or explicit cleanup flows to keep policy files tidy
- Clock skew: expiry is evaluated against the system clock. If the system clock is set backwards, an expired rule could become active again. Use NTP.
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
