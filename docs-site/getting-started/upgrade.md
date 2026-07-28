---
title: Upgrade
description: "Upgrade Rampart safely with Homebrew, Go, or install script workflows. Keep policy protections current for Claude Code and other AI coding agents."
---

# Upgrade

## Check Your Version

```bash
rampart version
```

## Upgrade Methods

### Homebrew

```bash
brew upgrade rampart
```

If `rampart serve install` was run from an older Homebrew release, its service
definition may contain a versioned `Cellar` path. Reinstall that service once
after upgrading (repeat any non-default service flags you use):

```bash
rampart serve install --force
```

Current releases persist Homebrew's stable `rampart` symlink after verifying it
resolves to the running binary, so later `brew upgrade rampart` operations do
not strand the service on a removed version directory.

### Go Install

```bash
go install github.com/peg/rampart/cmd/rampart@latest
```

### Windows

Rerun the official PowerShell installer:

```powershell
irm https://rampart.sh/install.ps1 | iex
```

Use this installer for every Windows binary upgrade; in-process self-upgrade is
intentionally disabled on Windows. The installer also repairs the affected
legacy `~\.rampart` ACL found on v1.2.x installations.

### Manual Binary

Download the latest release from [GitHub Releases](https://github.com/peg/rampart/releases):

```bash
# macOS (Apple Silicon)
curl -sL https://github.com/peg/rampart/releases/latest/download/rampart_$(curl -s https://api.github.com/repos/peg/rampart/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d v)_darwin_arm64.tar.gz | tar xz
sudo mv rampart /usr/local/bin/

# macOS (Intel)
curl -sL https://github.com/peg/rampart/releases/latest/download/rampart_$(curl -s https://api.github.com/repos/peg/rampart/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d v)_darwin_amd64.tar.gz | tar xz
sudo mv rampart /usr/local/bin/

# Linux (x64)
curl -sL https://github.com/peg/rampart/releases/latest/download/rampart_$(curl -s https://api.github.com/repos/peg/rampart/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d v)_linux_amd64.tar.gz | tar xz
sudo mv rampart /usr/local/bin/
```

### Verify

```bash
rampart version
rampart upgrade --no-binary
rampart protect
```

Run `rampart protect` once after replacing the binary. It preserves user-owned
configuration, refreshes Rampart-managed hooks and plugins for detected agents,
migrates recognized legacy integrations, and runs the matching behavioral
verification. This is especially important when a release adds a newer native
host boundary.

## What Upgrades Preserve

Binary upgrades preserve user-owned state. The self-upgrader also refreshes
unchanged Rampart-managed built-in policy profiles; edited and custom policies
are preserved:

| Preserved | Location |
|-----------|----------|
| Your policies | `~/.rampart/policies/` |
| Audit logs | `~/.rampart/audit/` |
| Signing key | `~/.rampart/signing.key` |
| Agent configuration and non-Rampart hooks | `~/.claude/settings.json` etc. |

Existing Rampart hooks keep calling the upgraded binary, so enforcement remains
in place during the transition. Run `rampart protect` once to refresh only the
managed integration entries and adopt any newer hook or plugin format. Custom
policies, unrelated host hooks, memories, sessions, and credentials are not
replaced.

## Breaking Changes

Check the [CHANGELOG](https://github.com/peg/rampart/blob/main/CHANGELOG.md) before upgrading. Breaking changes (if any) are listed under each version.

Notable past changes:

- **v0.2.0**: Webhook JSON fields changed to snake_case. If you parse webhook payloads, update your field names.
