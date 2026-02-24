---
title: Customizing Policy
description: "Add allow and deny rules without editing YAML using rampart allow, rampart block, and rampart rules. Per-project and global scopes, denial hints, and self-modification protection."
---

# Customizing Policy

Rampart ships with `standard.yaml` — a policy that blocks dangerous commands and watches suspicious ones. When you need to adjust what's allowed or blocked, you don't have to edit YAML by hand.

`rampart allow` and `rampart block` add rules from the command line. They write to a separate `custom.yaml` file (or a project-local equivalent), hot-reload the daemon, and stay out of the way of future policy upgrades.

## Allow a blocked command

If Rampart blocks something it shouldn't, unblock it:

```bash
rampart allow "npm install *"
```

Output:

```
  Adding rule to global policy (~/.rampart/policies/custom.yaml):

    Action:  allow
    Pattern: npm install *
    Tool:    exec

  Add this rule? [y/N] y

  ✓ Rule added to custom.yaml

    Action:  allow
    Pattern: npm install *
    Tool:    exec

  Policy reloaded (26 rules active)
```

The rule takes effect immediately. No restart needed.

### Skip the confirmation prompt

```bash
rampart allow "npm install *" --yes
# or
rampart allow "npm install *" -y
```

### Useful examples

```bash
# Development package managers
rampart allow "npm install *"
rampart allow "yarn add *"
rampart allow "pip install *"
rampart allow "go get *"
rampart allow "cargo add *"

# Git operations
rampart allow "git push origin *"
rampart allow "git fetch *"

# Test runners
rampart allow "go test ./..."
rampart allow "pytest *"

# Build tools
rampart allow "make *"
rampart allow "docker build *"

# Read a specific directory
rampart allow "/tmp/**" --tool read

# Write to a build directory
rampart allow "$(pwd)/dist/**" --tool write
```

## Block an additional command

```bash
rampart block "npm publish *"
rampart block "curl * | bash"
rampart block "pip install --index-url *"  # block custom PyPI mirrors
```

Block rules use the same flags as allow:

```bash
rampart block "npm publish *" --yes --message "Publishing requires human review"
```

## Pattern auto-detection

Rampart automatically classifies patterns as path-based or command-based:

| Pattern | Detected as | Applies to |
|---------|-------------|-----------|
| `npm install *` | command | `exec` |
| `curl https://api.example.com/*` | command | `exec` |
| `/tmp/**` | path | `read`, `write`, `edit` |
| `~/projects/**` | path | `read`, `write`, `edit` |
| `**/node_modules/**` | path | `read`, `write`, `edit` |

Override with `--tool`:

```bash
rampart allow "/var/log/**" --tool read    # read only
rampart allow "/tmp/build/**" --tool write # write only
rampart allow "docker exec *" --tool exec  # force exec (not path)
```

Valid `--tool` values: `exec`, `read`, `write`, `edit`

## Rule scopes: global vs project

Rules live in one of two files:

| Scope | Path | When |
|-------|------|------|
| **Project** | `.rampart/policy.yaml` | Inside a git repo (automatic) |
| **Global** | `~/.rampart/policies/custom.yaml` | Outside a git repo (automatic) |

Rampart auto-detects your scope by looking for a `.git` directory. Force it explicitly:

```bash
rampart allow "npm install *" --global   # always global
rampart allow "npm install *" --project  # always project (.rampart/policy.yaml)
```

### Project-scoped rules (team sharing)

Project rules travel with the repo. Commit `.rampart/policy.yaml` to share allow/block rules with your team:

```bash
# In your project root
rampart allow "npm install *" --project
rampart allow "yarn build" --project
git add .rampart/policy.yaml
git commit -m "chore: add rampart project rules"
```

When a teammate clones the repo, `rampart serve` picks up the project rules automatically.

### Global rules (personal overrides)

Global rules apply everywhere on your machine regardless of which project you're working in. Use them for personal workflow preferences:

```bash
rampart allow "gh pr create *" --global
rampart allow "brew install *" --global
```

## List your custom rules

```bash
rampart rules
```

```
  Custom Rules
  ──────────────────────────────────────────────────────────────

  Global  (~/.rampart/policies/custom.yaml)

  #     ACTION   TOOL      PATTERN                              ADDED
     1  allow    exec      npm install *                        2 hours ago
     2  allow    exec      go test ./...                        1 day ago
     3  deny     exec      npm publish *                        3 days ago

  Project  (.rampart/policy.yaml)

  #     ACTION   TOOL      PATTERN                              ADDED
     4  allow    exec      make build                           1 week ago

  ──────────────────────────────────────────────────────────────
  Total: 30 rules (26 standard + 4 custom)
  Manage: rampart rules remove <#>
```

Filter by scope:

```bash
rampart rules --global    # global rules only
rampart rules --project   # project rules only
```

JSON output for scripting:

```bash
rampart rules --json
```

```json
[
  {
    "index": 1,
    "source": "global",
    "action": "allow",
    "tool": "exec",
    "pattern": "npm install *",
    "added_at": "2026-02-24T06:00:00Z"
  }
]
```

## Remove a rule

```bash
rampart rules remove 3    # remove rule #3 from the list
```

Use `--force` to skip the confirmation prompt:

```bash
rampart rules remove 3 --force
```

## Reset all custom rules

```bash
rampart rules reset
```

This removes every rule added via `rampart allow` and `rampart block` — both global and project — and leaves the standard policy untouched.

```bash
rampart rules reset --force   # skip confirmation
```

## Add a reason for a rule

The `--message` flag sets the text displayed when the rule matches or fires a denial:

```bash
rampart allow "npm install *" --message "Allowed: frontend dependencies during dev"
rampart block "npm publish *" --message "Publishing to npm requires manual review"
```

Messages appear in `rampart watch` and the audit log.

## Manually editing custom.yaml

Both scope files are plain Rampart policy YAML. Open them in an editor to batch-add rules or fine-tune conditions:

```yaml
# ~/.rampart/policies/custom.yaml
# Rampart custom policy — managed by `rampart allow` / `rampart block`.
# You can edit this file manually. Changes take effect on reload.

version: "1"
policies:
  - name: custom-allow-commands
    match:
      tool: [exec]
    rules:
      - action: allow
        when:
          command_matches:
            - "npm install *"
            - "yarn add *"
            - "go test ./..."
        message: "User-allowed dev tools"
        added: 2026-02-24T06:00:00Z

  - name: custom-allow-paths
    match:
      tool: [read, write, edit]
    rules:
      - action: allow
        when:
          path_matches:
            - "/tmp/**"
            - "~/projects/**"
        message: "User-allowed project paths"
        added: 2026-02-24T06:00:00Z
```

Changes hot-reload automatically. Or trigger a reload manually:

```bash
curl -X POST http://localhost:9090/v1/policy/reload \
  -H "Authorization: Bearer $(rampart token)" \
  -H "Content-Type: application/json" \
  -d '{}'
```

## Denial hints

When Rampart blocks a tool call, the error message includes a ready-to-run `rampart allow` command:

```
Rampart: denied — command_matches "curl * | bash" (block-exfil)

To allow this command, run:
  rampart allow "curl https://api.example.com/data"
  rampart allow "curl *"   # allows any curl command
```

The agent sees this message and can surface it to you. Copy-paste the command to unblock.

Safe wildcard suggestions are generated automatically. Wildcards are **not** suggested for:

- Destructive commands (`rm`, `shred`, `dd`, `mkfs`, etc.)
- Sensitive paths (`/etc/`, `~/.ssh/`, `*.pem`, etc.)

## Self-modification protection

`rampart allow`, `rampart block`, and `rampart rules` are **blocked when run by an AI agent**. The standard policy includes:

```yaml
- name: block-self-modification
  description: "Prevent AI agents from modifying their own Rampart policy"
  match:
    tool: ["exec"]
  rules:
    - action: deny
      when:
        command_matches:
          - "rampart allow *"
          - "rampart block *"
          - "rampart rules *"
          - "rampart policy generate*"
          - "rampart init *"
      message: "Policy modification commands must be run by a human, not an agent"
```

This means:

- ✅ **You** can run `rampart allow "npm install *"` in your terminal
- ❌ **Your agent** cannot run `rampart allow "npm install *"` to unblock itself
- ✅ When your agent is denied and shows you the `rampart allow` hint, **you** run it

This keeps the security boundary intact. Agents can request permission by surfacing the denial hint; you decide whether to grant it.

## Flags reference

### `rampart allow <pattern>` / `rampart block <pattern>`

| Flag | Default | Description |
|------|---------|-------------|
| `--global` | — | Write to global policy (`~/.rampart/policies/custom.yaml`) |
| `--project` | — | Write to project policy (`.rampart/policy.yaml`) |
| `--tool` | auto | Tool type: `exec`, `read`, `write`, `edit` |
| `--message` | auto | Reason displayed when the rule fires |
| `--yes` / `-y` | false | Skip confirmation prompt |
| `--api` | `http://127.0.0.1:9090` | Rampart serve address for hot reload |
| `--token` | `RAMPART_TOKEN` | API auth token |

### `rampart rules`

| Flag | Default | Description |
|------|---------|-------------|
| `--global` | — | Show global rules only |
| `--project` | — | Show project rules only |
| `--json` | false | JSON output |

### `rampart rules remove <index>`

| Flag | Default | Description |
|------|---------|-------------|
| `--force` | false | Skip confirmation |

### `rampart rules reset`

| Flag | Default | Description |
|------|---------|-------------|
| `--force` | false | Skip confirmation |

## Workflow: agent denied, you unblock it

1. Agent tries to run `npm install typescript`
2. Rampart denies it (matches `block-npm-registry` or similar)
3. Agent shows you: _"Rampart denied. To allow: `rampart allow "npm install *"`"_
4. You run `rampart allow "npm install *"` in your terminal
5. Rampart hot-reloads. Agent retries — it goes through.

No restarts. No YAML editing. The rule is saved for future sessions.
