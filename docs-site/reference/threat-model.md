---
title: Threat Model
description: "See what Rampart protects against: hallucinated destructive commands, prompt injection, and accidental secret access, plus clear non-goals and trust boundaries."
---

# Threat Model

Rampart is a policy engine for AI agents — not a sandbox, not a hypervisor, not a full isolation boundary. This document describes what Rampart protects against, what it doesn't, and why.

## Primary Threat: Misbehaving AI Agents

Rampart's target threat is an AI agent that:

- **Hallucinated a destructive command** — `rm -rf /`, `DROP TABLE`
- **Was manipulated by prompt injection** — malicious content told it to exfiltrate data
- **Made a well-intentioned mistake** — wrong environment, wrong file, wrong server

These agents aren't adversarial — they're confused, manipulated, or wrong. Rampart catches them reliably.

## Not the Target: Adversarial Humans

Rampart does **not** claim to stop a skilled human who has already compromised your system. If an attacker has shell access, they can bypass Rampart the same way they'd bypass any userspace tool.

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

## Known Limitations

### 1. Interpreter Bypass

If an agent runs `python3 script.py`, Rampart evaluates `python3 script.py` but can't inspect what `script.py` does internally.

**Mitigations:**

- **LD_PRELOAD cascade** — child processes spawned by allowed commands inherit the interceptor. `python3 script.py` calling `os.system("rm -rf /")` is caught.
- **Semantic verification** — the [rampart-verify](https://github.com/peg/rampart-verify) sidecar classifies intent of commands like `python3 -c "..."`
- **File + exec coverage** — with native hooks or manual file tool patches, write-then-execute sequences are evaluated at both steps

### 2. Audit Log Rewrite

The hash chain detects partial tampering. A complete rewrite with a new valid chain is not detectable from the log alone.

**Mitigations:** [User separation](../deployment/user-separation.md), SIEM export, webhook notifications.

### 3. Glob Pattern Evasion via Shell Metacharacters

Glob matching operates on **raw command strings** and does not interpret shell semantics. An agent (or prompt injection) can evade deny-list patterns using quoting (`'rm' -rf /`), variable expansion (`$CMD`), backslash escaping (`r\m`), or path variations (`/bin/rm` vs `rm`).

**Mitigations:**

- Use `default_action: deny` with allowlists instead of deny-lists for high-security deployments
- Combine with [semantic verification](https://github.com/peg/rampart-verify) which classifies intent regardless of syntax
- LD_PRELOAD interceptor catches commands at the execve level

### 4. Encoding and Obfuscation

Commands can be encoded (base64, variable expansion) to bypass pattern matching.

**Mitigations:**

- Rampart decodes base64 before matching
- Leading shell comments are stripped
- The [anti-exfiltration policy](../getting-started/configuration.md#example-anti-exfiltration-policy) catches common encoding patterns
- Semantic verification classifies intent regardless of encoding

### 5. Fail-Open Behavior

When `rampart serve` is unreachable, commands execute without policy checks. This is deliberate — fail-closed locks you out of your machine.

**Mitigations:** Service monitoring, auto-restart, webhook notifications as liveness signal.

### 6. Framework Patching Fragility

File tool patches modify framework source files that get replaced on upgrades. Between upgrade and re-patch, file tools bypass Rampart.

### 7. Token Exposure

In wrap mode, the bearer token is stored in a `0600` file. The agent user can still read it. Use native hooks or user separation for stronger guarantees.

## Philosophy

!!! quote "Seatbelt, not a roll cage"
    Rampart catches the vast majority of dangerous situations an AI agent will encounter. It doesn't claim to stop every possible attack vector.

    If you need full isolation, use a sandbox (container, VM, [fluid.sh](https://fluid.sh)). Rampart and sandboxes are complementary — use both for defense in depth.

## Reporting Security Issues

Found a vulnerability not covered here? Email [rampartsec@pm.me](mailto:rampartsec@pm.me). We'll acknowledge within 48 hours.

**Do not** open public issues for security vulnerabilities.
