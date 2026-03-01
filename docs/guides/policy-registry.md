---
title: Community Policy Registry
description: Browse, install, and share Rampart policies with the community registry.
---

# Community Policy Registry

Rampart ships with a built-in registry of community policies. Browse and install them without writing YAML.

## Browsing available policies

```bash
rampart policy list
```

Example output:

```
NAME              VERSION  DESCRIPTION
research-agent    1.0.0    Read-only web research agent — allows browsing, blocks exec and writes
mcp-server        1.0.0    MCP server context — default allow with exec/credential guards
```

## Installing a policy

```bash
rampart policy fetch research-agent
```

This downloads the policy, verifies its SHA256 checksum, and installs it to `~/.rampart/policies/research-agent.yaml`. The policy is active immediately — no restart needed.

Use `--force` to overwrite an existing installation:

```bash
rampart policy fetch research-agent --force
```

Preview without installing:

```bash
rampart policy fetch research-agent --dry-run
```

## Removing a policy

```bash
rampart policy remove research-agent
```

Built-in profiles (`standard`, `paranoid`, `yolo`, `ci`, `research-agent`, `mcp-server`) are protected and cannot be removed this way. Use `rampart init --force` to reset a built-in profile.

## Available policies

### `research-agent`

For agents that browse the web, read files, and summarise — but must not execute arbitrary code or write to the filesystem.

- ✅ Allows: web fetch, browser tools, file reads (non-credential paths)
- ✅ Allows: read-only exec (`ls`, `grep`, `cat`, `find`, `curl` GET-only)
- ❌ Blocks: shell exec, file writes, credential access, network exfil

```bash
rampart init --profile research-agent
```

### `mcp-server`

For agents exposed via MCP (Model Context Protocol), e.g. Claude Desktop extensions.

- ✅ Default allow (MCP servers need broad access)
- ❌ Blocks: exec, credential file reads, system path writes, known exfil domains
- ⚠️ Asks: outbound fetch requests

```bash
rampart init --profile mcp-server
```

## Registry integrity

Every policy in the registry is verified with a SHA256 checksum before installation. The manifest is fetched from:

```
https://raw.githubusercontent.com/peg/rampart/main/registry/registry.json
```

The manifest is cached for 1 hour. Use `--refresh` to force a fresh fetch:

```bash
rampart policy list --refresh
```

## Contributing a policy

To add a policy to the community registry:

1. Write and test your policy YAML
2. Open a PR adding it to `registry/policies/` in the [Rampart repo](https://github.com/peg/rampart)
3. Update `registry/registry.json` with the name, description, path, and SHA256

Community policies must pass `rampart policy lint` with no warnings before merging.

## Team policies vs. community policies

| | Community registry | Git sync |
|---|---|---|
| Source | Rampart's curated list | Any HTTPS git repo |
| Updates | Manual (`fetch --force`) | Automatic (`--watch`) |
| Use case | Getting started, standard profiles | Team-wide policy distribution |

For team-managed policies, see [Git-based Policy Sync](policy-sync.md).
