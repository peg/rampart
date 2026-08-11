---
title: Security Assurance
description: "How Rampart ties integration support claims to portable tests and active verification."
---

# Security Assurance

Rampart's support claims are backed by a machine-readable integration manifest,
a shared adversarial policy corpus, and integration-specific compatibility
checks. Coverage means actions exposed through the named hook, plugin, proxy,
or process boundary. It does not mean Rampart inspects arbitrary syscalls,
packets, hosted actions, or behavior inside an already allowed process.

## Evidence levels

| Level | Meaning |
| --- | --- |
| **Verified** | The installed integration has an active, safe verifier for the claimed host boundary. |
| **Tested** | The Rampart adapter, mapping, or protocol response is exercised in isolation. |
| **Partial** | Some routes are covered, with documented exclusions. |
| **Not covered** | The integration does not intercept the surface. |

Support tiers are separate from coverage breadth. A supported integration can
have a verified shell boundary and only tested file mappings. An experimental
integration can pass isolated compatibility checks while still depending on an
upstream contract that is not strong enough for full support.

The canonical claim source is
[`assurance/integrations.yaml`](https://github.com/peg/rampart/blob/main/assurance/integrations.yaml).

## Verify an installation

```bash
rampart verify --all
rampart verify --all --json
```

The aggregate checks the policy path and configured integrations with active,
non-executing verifiers. It does not invoke a model or execute a represented
action. Exit status 1 means at least one target failed; status 2 means no target
failed but at least one remained unverified.

Static-only integrations are deliberately absent. Use `rampart doctor` to
inspect their installation state.

## Run the source gate

```bash
make security-assurance
```

This validates the assurance manifest and evidence paths, evaluates the public
adversarial corpus through the real policy engine, exercises fuzz seed corpora,
and runs portable OpenClaw and Hermes compatibility checks. Corpus commands are
data only and are never executed.

The public corpus contains fixed regression cases. Report a suspected unpatched
bypass privately using [`SECURITY.md`](https://github.com/peg/rampart/blob/main/SECURITY.md);
a regression case can be published after the fix is available.

See the repository's
[`assurance/README.md`](https://github.com/peg/rampart/blob/main/assurance/README.md)
for the release bar and evidence vocabulary.
