# OpenClaw

For [OpenClaw](https://github.com/openclaw/openclaw) users, Rampart provides a shell shim and background service integration.

## Setup

```bash
rampart setup openclaw
```

This installs a shell shim that intercepts all `exec` tool calls and sets up a background service (systemd on Linux, launchd on macOS).

### Full File Coverage

For complete protection including file operations (Read, Write, Edit):

```bash
rampart setup openclaw
```

This patches OpenClaw's tool implementations to check Rampart before file operations. Requires write access to the OpenClaw installation directory (may need `sudo` for global npm installs).

!!! warning "Re-run after upgrades"
    File tool coverage (read/write/edit/grep) requires manual patching of OpenClaw's `node_modules`. See the [README](https://github.com/peg/rampart#openclaw) for the patch script. Re-run after every OpenClaw upgrade.

## Compatibility

Supports OpenClaw `2026.1.30`+.

## How It Works

```
OpenClaw
  └─ exec tool call → Shell Shim → rampart serve → Policy Engine
  └─ file tool call → Patched Tool → rampart serve → Policy Engine
                                                    → Audit Trail
```

## Monitor

```bash
rampart watch
```
