---
title: Project Policies
description: Add repo-specific Rampart rules that apply automatically to anyone working in the project.
---

# Project Policies

Drop a `.rampart/policy.yaml` file in any git repository to add project-specific rules. These rules load automatically on top of your global policy when you work in that directory.

## Why Use Project Policies

- **Team consistency** — everyone gets the same rules without per-developer config
- **Context-aware security** — stricter rules for production repos, relaxed rules for experiments
- **Version controlled** — policy changes go through code review like everything else
- **Zero friction** — commit the file, push, done

## Quick Start

```bash
# In your repo root
rampart init --project
```

This creates `.rampart/policy.yaml` with a starter template:

```yaml
version: "1"
policies:
  - name: project-example
    match:
      tool: ["exec"]
    rules:
      - action: deny
        when:
          command_matches:
            - "*--env=production*"
        message: "Production operations require human review"
```

Commit it:

```bash
git add .rampart/policy.yaml
git commit -m "Add Rampart project policy"
```

## How It Works

When Rampart evaluates a tool call:

1. **Global policy** (`~/.rampart/policies/*.yaml`) is loaded first
2. **Project policy** (`.rampart/policy.yaml` in cwd or parent) is merged on top
3. Both are evaluated; deny always wins

The project policy **adds** rules — it cannot remove or override global denies. This ensures your global security baseline is never weakened by a malicious or misconfigured project policy.

## The `[Project Policy]` Prefix

When a project policy blocks a command, the deny message includes a prefix so you know the rule came from the repo:

```
[Project Policy] Production migrations blocked — use staging first
```

This distinguishes project-level rules from global Rampart rules:

```
Destructive command blocked           # ← global policy
[Project Policy] No direct DB access  # ← project policy
```

## Example: Staging-First Workflow

```yaml
# .rampart/policy.yaml
version: "1"
policies:
  - name: staging-first
    description: "Require staging deployment before production"
    match:
      tool: ["exec"]
    rules:
      - action: deny
        when:
          command_matches:
            - "*kubectl apply*production*"
            - "*terraform apply*prod*"
            - "*deploy*--env=prod*"
        message: "Deploy to staging first, then get approval for production"
```

## Example: Database Safety

```yaml
# .rampart/policy.yaml
version: "1"
policies:
  - name: protect-prod-db
    match:
      tool: ["exec"]
    rules:
      - action: deny
        when:
          command_matches:
            - "*psql*prod*DROP*"
            - "*mysql*production*DELETE*"
            - "*mongosh*prod*db.*.remove*"
        message: "Direct production database modifications are not allowed"
      - action: ask
        when:
          command_matches:
            - "*psql*prod*"
            - "*mysql*production*"
        message: "Production database access — proceed?"
```

## Example: Secrets in This Repo

```yaml
# .rampart/policy.yaml
version: "1"
policies:
  - name: protect-project-secrets
    match:
      tool: ["read"]
    rules:
      - action: deny
        when:
          path_matches:
            - "**/.keys/**"
            - "**/secrets/**"
            - "**/config/credentials.*"
        message: "This project's secrets directory is protected"
```

## Disabling Project Policies

In some cases you may want to skip project policy loading:

```bash
# Disable for a single command
RAMPART_NO_PROJECT_POLICY=1 rampart wrap -- my-agent

# Or in CI where you want only the global CI policy
export RAMPART_NO_PROJECT_POLICY=1
```

Use cases:
- **Security testing** — verify global policy catches things without project overrides
- **Untrusted repos** — cloning a repo shouldn't change your security posture
- **Debugging** — isolate whether an issue is global vs project policy

## Policy Precedence

When both global and project policies have rules that match:

1. **Deny always wins** — if any rule denies, the action is denied
2. **Lower priority number = evaluated first** — use `priority: 0` to ensure your rule is checked early
3. **Project rules can't weaken global rules** — they can only add restrictions or allow things the global policy doesn't cover

```yaml
# This project policy allows something, but if the global policy denies it,
# the deny wins:
policies:
  - name: try-to-allow-rm
    rules:
      - action: allow
        when:
          command_matches: ["rm -rf /"]  # ← still denied by global policy
```

## Discovering Active Policies

```bash
# See if a project policy is active
rampart doctor

# Output includes:
#   ✓ Project policy: .rampart/policy.yaml (3 rules)

# Test a command against all active policies
rampart test "kubectl apply -f prod.yaml"
```

## Best Practices

1. **Keep project policies focused** — don't duplicate global rules
2. **Document why** — use the `description` field liberally
3. **Test before committing** — `rampart policy check .rampart/policy.yaml`
4. **Review policy PRs carefully** — they affect everyone on the team

## See Also

- [Writing Policies](../README.md#writing-policies) — full policy syntax reference
- [CI/Headless Agents](./ci-headless.md) — combining project policies with CI mode
- [Native Ask Prompt](./native-ask.md) — interactive approval for sensitive operations
