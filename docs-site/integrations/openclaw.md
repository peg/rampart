# OpenClaw

For [OpenClaw](https://github.com/openclaw/openclaw) users, Rampart provides a shell shim and background service integration.

## Setup

```bash
rampart setup openclaw
```

This installs a shell shim that intercepts all `exec` tool calls and sets up a background service (systemd on Linux, launchd on macOS).

## What Gets Intercepted

| Tool Call | Method | Setup |
|-----------|--------|-------|
| Shell commands | Shell shim (automatic) | `rampart setup openclaw` |
| File reads/writes/edits | Tool patching (optional) | Manual patch script |

### Optional: File Tool Coverage

By default, only shell commands go through Rampart. For complete protection including file operations (read, write, edit, grep), you can apply patches to OpenClaw's tool implementations. See the [README](https://github.com/peg/rampart#openclaw) for the patch script.

!!! info "This is temporary"
    File tool patching modifies OpenClaw's `node_modules` and needs re-running after upgrades. We're working with the OpenClaw team on native tool authorization hooks to replace this.

## Compatibility

Supports OpenClaw `2026.1.30`+.

## How It Works

```
OpenClaw
  └─ exec tool → Shell Shim → rampart serve → Policy Engine
  └─ file tool → Patched Tool → rampart serve → Policy Engine
                                               → Audit Trail
```

## Monitor

```bash
rampart watch
```

## Uninstall

```bash
rampart setup openclaw --remove
```

This stops the background service, removes the shim and service file. Your policies and audit logs in `~/.rampart/` are preserved.
