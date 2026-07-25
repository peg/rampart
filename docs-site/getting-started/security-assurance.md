---
title: Security Assurance
description: "How Rampart ties integration support claims to executable tests, isolated host checks, and public evidence."
---

# Security Assurance

Rampart's support claims are backed by a machine-readable integration manifest,
a shared adversarial policy corpus, and integration-specific compatibility
checks. Coverage always means actions an agent exposes through the named hook,
plugin, proxy, or process boundary. It does not mean Rampart inspects arbitrary
syscalls, packets, hosted actions, or behavior inside an already allowed
process.

## Evidence levels

| Level | Meaning |
| --- | --- |
| **Tested** | The Rampart adapter, mapping, or protocol response is exercised in isolation. |
| **Verified** | A completed live host-boundary run is recorded, or the installed integration has an active safe verifier for that boundary. |
| **Partial** | Some routes are covered, with documented exclusions. |
| **Unknown** | Rampart does not make a reliable coverage claim yet. |

Support tiers are separate from coverage breadth. A supported integration can
have a verified shell boundary and only tested file mappings. An experimental
integration can have a successful live proof while still depending on an
upstream failure or approval contract that is not strong enough for full
support.

## Current host evidence

| Integration | Current evidence | Important remaining gap |
| --- | --- | --- |
| **OpenClaw** | Active, non-executing `rampart verify openclaw` canaries plus isolated compatibility and approval-path tests. | Dedicated MCP and delegated-agent live canaries. |
| **Claude Code** | Isolated Claude Code 2.1.220 macOS proof: deny did not execute, allow executed, and pre/post tool-call identity correlated. | Live file, network, MCP, subagent, crash, and timeout conformance. |
| **Codex** | Isolated Codex CLI 0.145.0 macOS proof: deny did not execute, allow executed, and pre/post tool-call identity correlated. | Physical Windows host proof and host-timeout guarantees. |
| **Gemini CLI** | Rolling-latest isolated configuration and adapter gate plus active local adapter verification. | Authenticated model/tool host proof and physical Windows proof. |
| **GitHub Copilot CLI / VS Code** | Rolling-latest isolated CLI/configuration gate plus a dual-schema destructive-call adapter canary. | Authenticated CLI and VS Code host proof; VS Code hooks remain Preview and CLI timeouts fail open. |
| **Cline** | Adapter and setup regression tests. | A rolling latest-Cline job and completed real-host proof; native Windows is not currently claimed. |
| **Hermes Agent** | Isolated Hermes 0.19.0 Linux proof: deny did not execute, allow executed, and pre-tool audit identity correlated. | Hermes can skip crashing plugin callbacks and does not expose a stable plugin approval/resume primitive. |

The canonical source is
[`assurance/integrations.yaml`](https://github.com/peg/rampart/blob/main/assurance/integrations.yaml).
Sanitized completed-run summaries are stored under
[`assurance/evidence/`](https://github.com/peg/rampart/tree/main/assurance/evidence).
They omit credentials, raw model output, hostnames, and temporary paths. These
summaries are reviewable maintainer attestations tied to a candidate commit;
they are not cryptographic signatures or substitutes for rerunning the harness.

## Run the local gate

From a Rampart source checkout:

```bash
make security-assurance
```

This validates the assurance manifest and evidence paths, evaluates the public
adversarial corpus through the real policy engine, exercises fuzz seed corpora,
and runs the bundled OpenClaw and Hermes regressions. Corpus commands are data
only and are never executed.

The public corpus contains fixed regression cases. Report a suspected unpatched
bypass privately using the process in
[`SECURITY.md`](https://github.com/peg/rampart/blob/main/SECURITY.md); a regression
case can be published after the fix is available.

## Opt-in real-host checks

These maintainer checks may invoke a configured model, so they are deliberately
separate from ordinary CI:

```bash
scripts/compat-codex-host.sh --yes --rampart-bin ./rampart
scripts/compat-claude-host.sh --yes --rampart-bin ./rampart
scripts/compat-hermes-host.sh --yes --rampart-bin ./rampart
```

Each harness uses disposable state, harmless marker canaries, and explicit
isolation checks. A harness existing in the repository proves that the check is
available; only a completed sanitized run substantiates a host-passed claim.

See the [Release Compatibility Gate](release-compatibility-gate.md) for the full
candidate-release procedure.
