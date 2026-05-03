# OpenClaw Integration

## Recommended path

For current OpenClaw versions, the **native Rampart plugin** is the primary integration path for non-legacy installs, but native OpenClaw exec approvals remain the UX reference path for exec approval behavior.

That means:

- OpenClaw owns the operator-facing approval UI/state
- Rampart evaluates tool calls and returns `allow`, `deny`, or `ask`
- OpenClaw shows native approvals when human review is needed
- Rampart persists `allow-always` behavior without creating a second approval queue

## Approval ownership model

For OpenClaw-hosted workflows, there should be exactly **one** human-facing approval object per action.

- OpenClaw owns the pending approval and native channel UX
- Rampart owns policy evaluation, audit, and persistence
- Rampart must not create a second pending approval record for the same OpenClaw-hosted action

## Primary integration path

Use the native plugin setup:

```bash
rampart setup openclaw
```

Use `--plugin` only if you need to force the native plugin path explicitly.

The plugin integrates via OpenClaw's native hook APIs and is the preferred path because it survives upgrades much better than direct `dist/` patching.

## What the plugin does

For each tool call:

1. OpenClaw invokes the Rampart plugin hook
2. Rampart evaluates the tool call through `rampart serve`
3. Rampart returns one of:
   - `allow`
   - `deny`
   - `ask`
4. If `ask`, OpenClaw owns the native approval flow
5. If the user chooses **Allow Always**, Rampart persists a rule so future matching calls are auto-allowed

## Native exec approvals

Rampart also supports OpenClaw native exec approval events as a **secondary seam**.

This is useful for host-exec/native approval flows that already produce OpenClaw approval events. In that mode:

- OpenClaw still owns the pending approval UI/state
- Rampart may auto-resolve deny decisions
- in native plugin mode, Rampart leaves allow/watch decisions pending because they mean “Rampart does not object,” not “the human approved”
- in legacy bridge-first mode, Rampart may still auto-resolve allow/watch decisions for compatibility
- Rampart writes `allow-always` persistence after native resolution

This native exec approval path is supported and remains the reference UX for exec approval behavior. The plugin path should match its single-queue ownership model and, where possible, its native approval UX.

## Legacy compatibility path

Older setups used:

```bash
sudo rampart setup openclaw --patch-tools --force
```

That direct `dist/` patching approach is now **legacy compatibility**, not the recommended default. It is more fragile across OpenClaw upgrades.

## Verify the plugin path

```bash
rampart doctor
```

You should verify at minimum that:

- Rampart plugin is installed in OpenClaw
- `rampart serve` is running
- plugin decisions are reaching Rampart
- OpenClaw-hosted `ask` decisions do not create a second Rampart approval queue

## Practical guidance

If you are choosing what to support for current Rampart releases:

- **Supported primary path:** native OpenClaw plugin
- **Supported secondary seam:** native exec approval events where they fit cleanly
- **Legacy/compatibility only:** direct `dist/` patching

## Long-term goal

The long-term goal is a clean OpenClaw integration that:

- survives OpenClaw upgrades
- uses only supported seams
- keeps one approval queue per action
- avoids `dist/` patching except as explicit legacy fallback
