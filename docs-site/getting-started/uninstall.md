---
title: Uninstall
description: "Uninstall Rampart cleanly by removing agent hooks, stopping services, and deleting local state. Restore Claude Code, Cline, or OpenClaw to original behavior."
---

# Uninstall

## 1. Remove Agent Hooks

Remove Rampart hooks from each agent you set up:

```bash
# Claude Code
rampart setup claude-code --remove

# Cline
rampart setup cline --remove

# OpenClaw
rampart setup openclaw --remove
```

This restores agent settings to their pre-Rampart state. Your agent will work exactly as it did before.

## 2. Stop Running Services

```bash
# If using rampart serve as a systemd service
sudo systemctl stop rampart-serve
sudo systemctl disable rampart-serve

# If running manually
pkill -f 'rampart serve'
pkill -f 'rampart daemon'
```

## 3. Remove the Binary

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

## 4. Clean Up Data (Optional)

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

## 5. Remove Environment Variables (If Set)

Check your shell profile (`~/.bashrc`, `~/.zshrc`, `~/.profile`) for:

```bash
# Remove these lines if present
export NODE_OPTIONS="--require $HOME/clawd/rampart/hooks/node-fs-hook.js"
export LD_PRELOAD=~/.rampart/lib/librampart.so
```

## Verify Clean Removal

```bash
# Should say "not found"
which rampart

# Should not exist
ls ~/.rampart/

# Agent should work normally
claude   # or your agent of choice
```
