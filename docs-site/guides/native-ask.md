---
title: Native Ask Prompt
description: Use action:ask to trigger Claude Code's inline approval dialog for sensitive commands.
---

# Native Ask Prompt (`action: ask`)

`action: ask` surfaces Claude Code's built-in inline approval dialog when a policy rule matches, instead of blocking the command outright. The user sees the command details and can approve or deny without leaving their session.

## When to Use It

Use `action: ask` when a command is sensitive but not always dangerous — you want a human in the loop without hard-blocking legitimate use:

- Running destructive-but-sometimes-needed commands (`rm -rf build/`, database resets)
- Outbound network calls in trusted projects
- Commands that modify configuration files
- Anything where context matters and you trust the user to decide

For commands that should **never** run (credential access, exfiltration), use `action: deny` instead.

## Policy Syntax

`action` and `when` must be nested inside a `rules:` list — **not** at the policy level:

```yaml
policies:
  - name: ask before running tests
    rules:
      - action: ask
        when:
          command_contains:
            - pytest
            - npm test
        message: "Running test suite — proceed?"

  - name: ask before dropping databases
    rules:
      - action: ask
        when:
          command_matches:
            - "dropdb *"
            - "psql * DROP *"
        message: "This will delete a database. Are you sure?"
```

## Ask Options

### `audit: true` — Log User Decisions

By default, `action: ask` prompts don't log the user's response. Add `audit: true` to record approvals and denials:

```yaml
policies:
  - name: audited-deploys
    rules:
      - action: ask
        ask:
          audit: true    # ← log the user's decision
        when:
          command_matches:
            - "kubectl apply *"
        message: "Deploy to cluster?"
```

With `audit: true`, the audit trail includes whether the user approved or denied the prompt. This is useful for compliance, debugging, and understanding agent behavior patterns.

### `headless_only: true` — Block in CI

Use `headless_only: true` when you want interactive approval locally but hard denies in CI/headless environments:

```yaml
policies:
  - name: production-safety
    rules:
      - action: ask
        ask:
          audit: true
          headless_only: true    # ← deny in CI, prompt interactively
        when:
          command_matches:
            - "*--env=production*"
        message: "Production operation requires approval"
```

**Behavior:**
- **Interactive session** (TTY, user present): Shows native approval prompt
- **Headless/CI** (no TTY, no `rampart serve`): Blocks with a deny

This lets you write one policy that works both locally (with prompts) and in CI (with denies). See [CI/Headless Agents](ci-headless.md) for more details.

### `require_approval` Alias

`action: require_approval` is a deprecated alias for `action: ask` with `audit: true`:

```yaml
# These are equivalent:
- action: require_approval
  message: "Needs approval"

- action: ask
  ask:
    audit: true
  message: "Needs approval"
```

!!! warning "Deprecated in v0.9.9"
    `action: require_approval` is now a hard error in v0.9.9+. Update your policies to use `action: ask` explicitly.

> ⚠️ Common mistake: putting `action: ask` directly inside the policy (as a sibling of `name` or `rules`). `rampart policy lint` will catch this and explain the correct structure.

## What the User Sees

When a matching command is intercepted, Claude Code displays:

```
Hook PreToolUse:Bash requires confirmation for this command:
Rampart: Running test suite — proceed?

Do you want to proceed?
> 1. Yes
  2. No

Esc to cancel · Tab to amend · ctrl+e to explain
```

Pressing `ctrl+e` expands an AI-generated explanation of what the command does and its risk level — this is a Claude Code native feature, not Rampart.

## Scoping to Specific Tools

By default, a policy applies to all tools. Scope it to bash-only or specific tools using `match`:

```yaml
policies:
  - name: ask before shell commands with curl
    match:
      tool: Bash
    rules:
      - action: ask
        when:
          command_contains:
            - curl
```

## Limitations

### Works in `--dangerously-skip-permissions` mode

`action: ask` shows the native approval prompt even when Claude Code is launched with `--dangerously-skip-permissions`. Claude Code honors hook-returned `permissionDecision: ask` regardless of the bypass flag — the user still sees the inline dialog and must approve or deny.

### Claude Code only

`action: ask` triggers Claude Code's native permission prompt. On other agents:

- **Cline** — treated as a block (`cancel: true`)
- **Other agents** — treated as deny

`rampart policy lint` will warn if you use `action: ask` without scoping the policy to `match.agent: [claude-code]`.

### Requires Claude Code v2.0+

The `permissionDecision: ask` hook response was introduced in Claude Code v2.0. Older versions may treat it as allow.

## Testing Your Policy

Use `rampart policy lint` to validate before deploying:

```bash
rampart policy lint ~/.rampart/policies/my-policy.yaml
```

And test end-to-end:

```bash
rampart test "kubectl apply -f prod.yaml"
```

## See Also

- [CI/Headless Agents](ci-headless.md) — headless_only behavior in detail
- [Testing Policies](testing-policies.md) — test your rules before deploying
