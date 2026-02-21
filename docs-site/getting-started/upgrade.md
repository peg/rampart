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

### Go Install

```bash
go install github.com/peg/rampart/cmd/rampart@latest
```

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
rampart doctor
```

## What Upgrades Preserve

Upgrades only replace the binary. Everything else stays:

| Preserved | Location |
|-----------|----------|
| Your policies | `~/.rampart/policies/` |
| Audit logs | `~/.rampart/audit/` |
| Signing key | `~/.rampart/signing.key` |
| Agent hooks | `~/.claude/settings.json` etc. |

No need to re-run `rampart setup` after upgrading — your hooks and policies carry over.

## Breaking Changes

Check the [CHANGELOG](https://github.com/peg/rampart/blob/main/CHANGELOG.md) before upgrading. Breaking changes (if any) are listed under each version.

Notable past changes:

- **v0.2.0**: Webhook JSON fields changed to snake_case. If you parse webhook payloads, update your field names.
