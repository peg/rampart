---
title: Git-based Policy Sync
description: Distribute Rampart policies across your team using a git repository.
---

# Git-based Policy Sync

`rampart policy sync` lets your team share a single policy from a git repository. When the repo updates, every developer's Rampart picks up the change automatically.

## Requirements

- `git` must be installed and in `PATH`
- Repository must be accessible over **HTTPS** (SSH and `git://` are not supported)
- Repository must be public (no authentication)

## One-shot sync

Pull the latest policy from a git repo:

```bash
rampart policy sync https://github.com/your-org/rampart-policies
```

Rampart searches for a policy file in this order:
1. `rampart.yaml`
2. `policy.yaml`
3. `.rampart/policy.yaml`

The synced policy is installed to `~/.rampart/policies/org-sync.yaml` and hot-reloaded immediately.

## Continuous sync with `--watch`

Keep the policy in sync as the repo changes:

```bash
rampart policy sync https://github.com/your-org/rampart-policies --watch
```

This polls for changes every 5 minutes by default. Adjust with `--interval`:

```bash
rampart policy sync https://github.com/your-org/rampart-policies --watch --interval 1m
```

Run this alongside `rampart serve` in a separate terminal, or add it to your startup scripts.

> **Note:** Auto-sync on `rampart serve` startup is planned for a future release. For now, run `rampart policy sync --watch` separately.

## Checking sync status

```bash
rampart policy sync status
```

Example output:

```
Git URL:     https://github.com/your-org/rampart-policies
Last sync:   2026-02-28T22:00:00Z (3 minutes ago)
Last commit: abc1234 — "Add deny rule for production S3 buckets"
Status:      up to date
```

## Stopping a watch process

```bash
rampart policy sync stop
```

## Setting up a team policy repo

Create a repository with a `rampart.yaml` at the root:

```yaml
# rampart.yaml
version: "1"
default_action: allow

policies:
  - name: block-production-writes
    match:
      tool: ["write", "edit"]
    rules:
      - action: deny
        when:
          path_matches:
            - "**/production/**"
            - "**/prod/**"
        message: "[Team Policy] Production files are read-only for AI agents"
```

Commit and push. Team members sync with:

```bash
rampart policy sync https://github.com/your-org/rampart-policies
```

## How it works

On first sync, Rampart runs `git clone --depth 1 <url> ~/.rampart/sync-repo`. On subsequent syncs it runs `git pull`. The policy file is copied to `~/.rampart/policies/org-sync.yaml`.

Sync state (URL, last commit, timestamps) is persisted to `~/.rampart/sync-state.json`.

## Comparison with other approaches

| Method | Best for |
|---|---|
| `policy sync` | Team-wide policies from a shared git repo |
| `rampart init --project` | Per-repo policies committed alongside code |
| Community registry | Getting started with pre-built profiles |

For the community policy registry, see [Community Policy Registry](policy-registry.md).
