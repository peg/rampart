# Threat Model

> Last reviewed: 2026-02-13 | Applies to: v0.1.9-dev (with file tool patching)

Rampart is a policy engine for AI agents — not a sandbox, not a hypervisor, not a full isolation boundary. This document describes what Rampart protects against, what it doesn't, and why.

## What Rampart Is

A firewall for AI agent tool calls. It evaluates commands against YAML policies and makes allow/deny/log decisions in microseconds. It's designed to catch the 95%+ case: an AI agent that hallucinated a dangerous command or got manipulated by a prompt injection.

## Primary Threat: Misbehaving AI Agents

Rampart's target threat is an AI agent that:

- **Hallucinated a destructive command** (`rm -rf /`, `DROP TABLE`)
- **Was manipulated by prompt injection** (malicious content in a file or webpage told it to exfiltrate data)
- **Made a well-intentioned mistake** (wrong environment, wrong file, wrong server)

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
├─────────────────────────────────────────────┤
│ Untrusted                                    │
│  • AI agent tool calls (all input)           │
│  • Agent-generated commands                  │
│  • MCP tool call parameters                  │
│  • Webhook response payloads (validated)     │
└─────────────────────────────────────────────┘
```

Policy files are the security boundary. If an attacker can modify policy files, Rampart's guarantees do not hold. This is why [user separation](../README.md#security-recommendations) is recommended for production.

## Known Limitations

### 1. Interpreter Bypass

Rampart evaluates the command string passed to the shell. This applies to **all integration methods** — native hooks (Claude Code, Cline), wrap mode, LD_PRELOAD, and the HTTP API all see the same command string. If an agent runs `python3 script.py`, Rampart sees and evaluates `python3 script.py` — but cannot inspect what `script.py` does internally.

**Mitigations:**
- **LD_PRELOAD cascade** (v0.1.9+): When using `rampart preload` or `rampart wrap`, child processes spawned by allowed commands automatically inherit the interceptor. This means `python3 script.py` calling `os.system("rm -rf /")` is caught — the subprocess goes through Rampart's policy engine. Covers `execve`, `execvpe`, and `posix_spawn` call paths.
- The optional [rampart-verify](https://github.com/peg/rampart-verify) sidecar uses LLM classification to assess intent of commands like `python3 -c "..."` based on the inline code
- Patterns like `python3 -c *` can be routed to semantic verification via `action: webhook`

**Remaining surface:** The cascade only applies to wrap/preload modes, not native hooks (Claude Code, Cline). Programs that use native file I/O without shelling out, or setuid binaries that drop LD_PRELOAD, are not covered.

**Multi-step sequences:** With file tool coverage enabled (native hooks or `--patch-tools`), write-then-execute sequences are evaluated at both steps independently — the write is checked against file policies and the exec against command policies.

### 2. Audit Log Rewrite

The hash-chained audit trail detects **partial tampering** — editing, inserting, or deleting individual records breaks the chain. However, a complete rewrite from scratch with a new valid chain is not detectable from the log file alone.

**Mitigations:**
- Run `rampart serve` as a [separate user](../README.md#security-recommendations) so the agent can't access audit files
- Enable SIEM export (`--syslog` or `--cef`) to send events to an external system the agent can't modify
- Webhook notifications send real-time alerts to Discord/Slack — a separate record

**For compliance environments:** Pair with external immutable logging (CloudTrail, Wazuh, etc.) for an independent trust anchor.

### 3. Token Exposure in Wrap Mode

The `rampart wrap` shim needs a bearer token to authenticate with `rampart serve`. As of v0.1.8, the token is stored in a `0600` file (not embedded in the shim script). However, the agent user can still read this file.

**Mitigations:**
- Run `rampart serve` as a separate user and store the token in that user's home directory with restricted permissions
- Use native hooks (`rampart setup claude-code`) instead of wrap mode — hooks don't require a token file

**Resolution:** Use [user separation](../README.md#security-recommendations) for production deployments, or prefer native hooks which don't require a token file.

### 4. Encoding and Obfuscation

An agent could potentially encode commands to bypass pattern matching:

- Base64-encoded payloads
- Variable expansion, command splitting

**Mitigations:**
- Rampart decodes base64 commands before pattern matching
- Leading shell comments are stripped before evaluation
- The semantic verification sidecar classifies intent regardless of encoding
- Common obfuscation patterns (`base64 *`, `eval *`) can trigger webhook verification

**Coverage:** The two-layer approach (pattern matching + LLM classification) significantly reduces the obfuscation surface. Pattern matching catches known encodings; the LLM layer catches intent regardless of how the command is formatted.

### 5. Framework-Specific Patching

Some agent frameworks (e.g., OpenClaw) don't expose hook points for file operations. Rampart provides a `--patch-tools` option that modifies framework source files to add policy checks before read/write/edit operations. These patches don't survive framework upgrades — they modify files in `node_modules` that get replaced on update.

**Mitigations:**
- `rampart setup openclaw --patch-tools` must be re-run immediately after OpenClaw upgrades to restore protection
- Native hook integrations (Claude Code, Cline) don't have this limitation — they use the framework's own hook system
- A feature request for generic tool authorization hooks benefits the entire ecosystem and would eliminate the need for patching

**Security implications:**
- **Timing window:** Between OpenClaw upgrade and re-patch, file tools bypass all policies (exec shim remains active)
- **Silent degradation:** If the target code changes in a new version, patches fail to apply and file tools fail-open without warning. The patch script exits with an error, but if run unattended this could go unnoticed.

**Trade-off:** Monkey-patching is fragile but functional. It closes a real security gap today while proper upstream support is developed. The patches fail-open — if the patched code changes in an upgrade, the worst case is that file tools bypass Rampart (reverting to the pre-patch state), not that they break.

### 6. Fail-Open Behavior

When `rampart serve` is unreachable (crashed, network issue), the shim defaults to **fail-open** — commands execute without policy checks. This is a deliberate design choice: fail-closed would lock you out of your own machine.

**Mitigations:**
- Monitor the Rampart service and alert on downtime
- Use systemd/launchd to auto-restart on failure
- Webhook notifications confirm the service is actively evaluating commands

**Trade-off:** Fail-open means a brief security gap during outages. Fail-closed means a crashed Rampart bricks your agent (and potentially your system). We chose availability over strict enforcement. This is configurable for environments where fail-closed is preferred.

## Deployment Recommendations

| Setup | Agent reads audit? | Agent modifies policy? | Best for |
|-------|-------------------|----------------------|----------|
| Same user (default) | ✅ Yes | ✅ Yes | Development, testing |
| Separate user | ❌ No | ❌ No | Production, unsupervised agents |
| Separate user + SIEM | ❌ No | ❌ No | Enterprise, compliance |

## Philosophy

Rampart is a **seatbelt, not a roll cage**. It catches the vast majority of dangerous situations an AI agent will encounter — accidental or manipulated. It doesn't claim to stop every possible attack vector, and we're honest about what falls outside its scope.

If you need full isolation, use a sandbox (container, VM, or a tool like [fluid.sh](https://fluid.sh)). Rampart and sandboxes are complementary — use both for defense in depth.

---

## Reporting Security Issues

If you've found a vulnerability not covered here, please email [rampartsec@pm.me](mailto:rampartsec@pm.me). We'll acknowledge within 48 hours and work with you on coordinated disclosure. Please do **not** open public issues for security vulnerabilities.
