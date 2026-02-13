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
rampart setup openclaw --patch-tools
```

This patches OpenClaw's tool implementations to check Rampart before file operations. Requires write access to the OpenClaw installation directory (may need `sudo` for global npm installs).

!!! warning "Re-run after upgrades"
    The `--patch-tools` option modifies files in `node_modules` that get replaced on OpenClaw upgrades. Re-run after every upgrade. Between upgrade and re-patch, file tools bypass Rampart (the exec shim remains active).

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
