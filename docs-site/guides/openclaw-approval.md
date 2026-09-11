---
title: OpenClaw Approval Flow
description: How Rampart and OpenClaw share policy decisions, native approvals, and complete action review.
---

# OpenClaw Approval Flow

## Recommended path

For current OpenClaw versions, the **native Rampart plugin** is the primary integration path. OpenClaw owns the operator-facing approval UI, while Rampart owns policy evaluation, audit logging, and complete redacted action review.

That means:

- OpenClaw owns the visible approval UI and pending approval state
- Rampart evaluates tool calls and returns `allow`, `deny`, or `ask`
- OpenClaw shows native approvals when human review is needed
- Native plugin approvals authorize one call; explicit policies define persistent allowances

## Approval ownership model

For OpenClaw-hosted workflows, there should be exactly **one** human-facing approval object per action.

- OpenClaw owns the pending approval and native channel UX
- Rampart owns policy evaluation, audit, and the redacted review payload
- Rampart must not create a second pending approval record for the same OpenClaw-hosted action

## Primary integration path

Use the managed zero-configuration protection path:

```bash
rampart protect openclaw
```

This installs the plugin and service, activates the managed OpenClaw + Guard
policy set, enables fail-closed degraded behavior, restarts the gateway, and
runs non-executing behavioral canaries. Use `rampart setup openclaw` only when
you are deliberately managing the integration by hand.

The plugin integrates through OpenClaw's native hook APIs and is the preferred path because it survives upgrades much better than direct `dist/` patching.

## What the plugin does

For each tool call:

1. OpenClaw invokes the Rampart plugin hook
2. Rampart evaluates the tool call through `rampart serve`
3. Rampart returns one of:
   - `allow`
   - `deny`
   - `ask`
4. If `ask`, OpenClaw owns the native approval flow
5. The user can allow once or deny. A request exceeding the native full-review limit is blocked before an approval is created. See [complete action approval](../integrations/openclaw.md#complete-action-approval) for size and host-composition limits.

## Exec-event compatibility bridge

Rampart retains a separate bridge for OpenClaw's `exec.approval.*` events.
These are distinct from the native plugin's `plugin.approval.*` requests.

- OpenClaw owns the pending exec approval and its UI.
- In legacy bridge-first mode, Rampart can resolve policy-allowed commands as
  allow-once. With the native plugin enabled, the bridge leaves allow/watch
  decisions pending so it does not override a separate host approval requirement.
- In enforce mode, a correlated exec-event `allow-always` resolution can write
  a command override. That is a persistent command policy, not an approval bound
  to every parameter of the original action.

This compatibility behavior is not an `allow-always` capability of the native
plugin. The managed plugin path offers allow-once and deny, and persistent
allowances require explicit operator policy. The plugin verifier does not
establish current-host approval delivery or rule persistence for the bridge.

## Legacy compatibility path

Older setups used:

```bash
sudo rampart setup openclaw --patch-tools --force
```

That direct `dist/` patching approach is now **legacy compatibility**, not the recommended default. It is more fragile across OpenClaw upgrades.

## Verify the plugin path

```bash
rampart verify openclaw
rampart doctor
```

`rampart doctor` checks installation state. `rampart verify openclaw` performs
preflight checks and asks the loaded gateway plugin to evaluate non-executing
policy canaries. It does not send an agent turn, execute a tool, exercise normal
audit persistence, or prove native approval delivery and resume.

For an end-user acceptance check, use a disposable harmless action and observe
the actual host: no effect before review, no effect after deny or expiry, and
exactly one effect after allow-once. Review the complete redacted action and
correlate its policy audit record. A policy decision alone is not proof that
the host executed the action. See the [support matrix](../getting-started/support-matrix.md)
for evidence levels and integration limits.

## Practical guidance

If you are choosing what to support for current Rampart releases:

- **Supported primary path:** native OpenClaw plugin
- **Separate compatibility path:** exec-event bridge; do not infer its behavior from plugin verification
- **Legacy/compatibility only:** direct `dist/` patching

## Long-term goal

The long-term goal is a clean OpenClaw integration that:

- survives OpenClaw upgrades
- uses only supported seams
- keeps one approval queue per action
- avoids `dist/` patching except as explicit legacy fallback
