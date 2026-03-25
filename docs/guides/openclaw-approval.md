# OpenClaw Native Integration

## Overview

Rampart integrates natively with OpenClaw via a WebSocket bridge that connects to the OpenClaw gateway. This gives Rampart visibility into all exec approvals and lets it enforce policy before the Discord approval UI appears.

## How it works

```text
Agent exec call
    → OpenClaw gateway creates approval
    → gateway broadcasts exec.approval.requested
    → Rampart bridge receives event
    → Rampart evaluates command against policy

  If DENY:
    → Bridge resolves immediately (deny)
    → Discord embed never shown
    → "Exec denied (rampart-policy)" in chat

  If ALLOW:
    → Bridge resolves immediately (allow-once)
    → Command runs silently, no embed shown

  If ASK:
    → Bridge defers — does not resolve
    → OpenClaw shows Discord embed (Allow Once / Always Allow / Deny)
    → User clicks button
    → gateway broadcasts exec.approval.resolved
    → If "Always Allow": bridge writes rule to ~/.rampart/policies/user-overrides.yaml
    → Command runs or is blocked based on user's choice
```

## Setup

```bash
sudo rampart setup openclaw --patch-tools
```

This installs three layers:

1. **Gateway bridge** — connects to OpenClaw gateway via WebSocket, intercepts exec approval events
2. **Shell shim** — intercepts exec calls from Claude Code and other agents running under OpenClaw
3. **Tool patches** — patches web_fetch, browser, message, and exec in OpenClaw's dist files

## What survives OpenClaw upgrades

| Layer | Survives upgrade? |
|-------|------------------|
| Gateway bridge | ✅ Yes — pure Rampart code, nothing in OpenClaw |
| Shell shim | ✅ Yes — installed in ~/.local/bin |
| Tool patches (web_fetch/browser/message/exec) | ❌ No — re-run `sudo rampart setup openclaw --patch-tools --force` after each upgrade |

The bridge (exec approval interception) never stops working. Between upgrade and re-patch, web_fetch/browser/message bypass Rampart — exec enforcement via the bridge remains active throughout.

## Policy behavior

Rampart's standard policy applies to all exec calls. Examples:

| Command | Policy decision | What happens |
|---------|----------------|--------------|
| `rm -rf /` | DENY | Blocked instantly, no Discord embed |
| `cat ~/.ssh/id_rsa` | DENY | Blocked instantly, no Discord embed |
| `git status` | ALLOW | Runs silently, no Discord embed |
| `sudo kubectl apply` | ASK | Discord embed shown, user decides |
| `sudo echo "test"` (after Always Allow) | ALLOW (user-overrides.yaml) | Runs silently |

## Always Allow persistence

When you click "Always Allow" in Discord, Rampart writes a rule to `~/.rampart/policies/user-overrides.yaml`:

```yaml
- name: user-allow-294747b6
  match:
    tool: exec
  rules:
    - when:
        command_matches:
          - "sudo kubectl apply*"
      action: allow
      message: "User allowed (always)"
```

This file is never overwritten by `rampart setup` or upgrades.

## Verify the integration

```bash
rampart doctor
```

All patches should show ✅. If any are missing:

```bash
rampart doctor --fix
# or
sudo rampart setup openclaw --patch-tools --force
```

## Verify it's working

Check that the bridge connected successfully after starting OpenClaw:

```bash
journalctl --user -u rampart-serve -n 20 | grep "bridge: connected"
```

You should see a line like `bridge: connected to gateway ws://localhost:9000`. No output means the bridge hasn't connected — check that `rampart serve` is running and OpenClaw's gateway is up.

> **Note:** `rampart doctor` will soon include an explicit `ask: on-miss` check to verify the OpenClaw config is set correctly. Once that fix lands, `rampart doctor` will flag misconfigured setups automatically.

## OpenClaw config recommendation

For the best experience, set `ask` to `on-miss` in `~/.openclaw/openclaw.json`:

```json
{
  "ask": "on-miss"
}
```

With `ask: off` (OpenClaw default), no approval events are created and Rampart's bridge never intercepts. With `ask: on-miss`, commands that miss the allowlist go through the approval flow and Rampart policy is enforced.

Restart OpenClaw after changing this setting.
