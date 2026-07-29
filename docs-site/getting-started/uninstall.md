---
title: Uninstall
description: "Uninstall Rampart cleanly while preserving agent configuration, credentials, histories, sessions, and memories."
---

# Uninstall

## 1. Remove Rampart-managed integrations and services

The top-level command removes Rampart-owned hooks and plugins from Claude Code,
Cline, Codex, GitHub Copilot, Antigravity, Gemini CLI, Hermes Agent, and
OpenClaw, then stops and removes the Rampart service:

```bash
rampart uninstall
# Non-interactive automation:
rampart uninstall --yes
```

Removal is ownership-aware: it preserves agent credentials, histories,
sessions, memories, workspaces, unrelated hooks/plugins, and non-Rampart
configuration. If Rampart cannot prove that a file or directory belongs to it,
the command leaves that path in place, reports it, and exits unsuccessfully so
automation cannot mistake a partial uninstall for success.

To remove only one integration, use its setup command directly:

```bash
rampart setup claude-code --remove
rampart setup cline --remove
rampart setup codex --remove
rampart setup copilot --remove
rampart setup antigravity --remove
rampart setup gemini --remove
rampart setup hermes --remove
rampart setup openclaw --remove
```

## 2. Remove the Binary

### Homebrew

```bash
brew uninstall rampart
```

### Go Install

```bash
rm $(which rampart)
# Usually: rm ~/go/bin/rampart
```

### Manual

```bash
sudo rm /usr/local/bin/rampart
```

## 3. Clean Up Rampart Data (Optional)

Rampart stores everything under `~/.rampart/`:

```bash
# See what's there first
ls -la ~/.rampart/

# Remove everything (policies, audit logs, signing key)
rm -rf ~/.rampart/
```

| Directory | Contents | Safe to delete? |
|-----------|----------|-----------------|
| `~/.rampart/policies/` | Your YAML policy files | Yes (back up first if custom) |
| `~/.rampart/audit/` | Hash-chained audit logs | Yes (consider archiving) |
| `~/.rampart/signing.key` | HMAC key for approval URLs | Yes (auto-regenerated) |
| `~/.rampart/lib/` | LD_PRELOAD library | Yes |

Deleting `~/.rampart/` is deliberately separate from `rampart uninstall` so
policy and audit evidence are never destroyed implicitly.

## 4. Remove Legacy Environment Variables (If Set)

Check your shell profile (`~/.bashrc`, `~/.zshrc`, `~/.profile`) for:

```bash
# Remove these lines if present
# Older pre-native-hook installations may have added this obsolete hook:
export NODE_OPTIONS="--require $HOME/clawd/rampart/hooks/node-fs-hook.js"
export LD_PRELOAD=~/.rampart/lib/librampart.so
```

## Verify Clean Removal

```bash
# Should say "not found"
which rampart

# Should not exist
ls ~/.rampart/

# The agent's own state should remain intact
claude   # or another previously protected agent
```
