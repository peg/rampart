---
title: CI/Headless Agents
description: Configure Rampart for unattended agents with strict defaults and no interactive approvals.
---

# CI/Headless Agents

When running AI agents in CI pipelines, automated workflows, or other headless environments, interactive approval prompts are impossible. Rampart provides the `ci.yaml` policy preset to convert all approval-required operations into hard denies.

## Quick Start

```bash
# Use the CI preset instead of standard
rampart init --profile ci

# Or copy to your policies directory
cp ~/.rampart/policies/ci.yaml ~/.rampart/policies/active.yaml
```

## What CI Mode Does

The `ci.yaml` preset is a strict variant of the standard policy:

| Standard Policy | CI Policy |
|-----------------|-----------|
| `action: ask` → native prompt | `action: deny` |
| `action: ask` (with `audit: true`) → dashboard | `action: deny` |
| Package installs → approval | Package installs → **blocked** |
| Cloud uploads → approval | Cloud uploads → **blocked** |
| Persistence changes → approval | Persistence changes → **blocked** |

## Why Use It

**Problem:** In CI, there's no human to click "Allow" on Claude Code's permission prompt. Without the CI preset:
- `action: ask` rules hang forever waiting for input
- `action: ask` (with `audit: true`) rules poll the dashboard indefinitely
- Your pipeline times out or runs forever

**Solution:** The CI preset converts all interactive rules to denies. The agent completes (or fails fast) with no human intervention needed.

## The `headless_only` Flag

For fine-grained control, use `headless_only: true` in your ask rules:

```yaml
policies:
  - name: production-deploys
    match:
      tool: ["exec"]
    rules:
      - action: ask
        ask:
          audit: true
          headless_only: true    # ← blocks in CI, prompts interactively
        when:
          command_matches:
            - "kubectl apply *"
        message: "Production deployment requires approval"
```

**How it works:**
- **Interactive session** (Claude Code with user): Shows native approval prompt
- **Headless/CI** (no `rampart serve`, no TTY): Blocks with a deny

This lets you write one policy that works both locally (with prompts) and in CI (with denies).

### Detecting Headless Mode

Rampart considers a session "headless" when:
1. `rampart serve` is not running, OR
2. The hook is invoked without a TTY (piped stdin)

You can force headless mode with `RAMPART_HEADLESS=1`.

## Example: GitHub Actions

```yaml
# .github/workflows/ai-agent.yml
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Rampart
        run: curl -fsSL https://rampart.sh/install | bash
      
      - name: Configure CI policy
        run: rampart init --profile ci
      
      - name: Run agent
        run: |
          rampart wrap -- python agent.py
        env:
          RAMPART_HEADLESS: "1"
```

## Customizing CI Behavior

The built-in `ci.yaml` is intentionally strict. To customize:

```bash
# Create a custom CI policy based on the preset
cp ~/.rampart/policies/ci.yaml ~/.rampart/policies/ci-custom.yaml
```

Then edit `ci-custom.yaml` to allow specific operations:

```yaml
# Allow npm install in CI (after the built-in deny rule)
policies:
  - name: ci-allow-npm
    priority: 0    # Higher priority than default rules
    match:
      tool: ["exec"]
    rules:
      - action: allow
        when:
          command_matches:
            - "npm ci"        # Deterministic installs only
            - "npm install --frozen-lockfile"
```

## Combining with Project Policies

Project policies (`.rampart/policy.yaml` in your repo) are loaded on top of the global policy. In CI:

1. Global CI policy (`ci.yaml`) provides the strict baseline
2. Project policy adds repo-specific overrides
3. `RAMPART_NO_PROJECT_POLICY=1` disables project policies if needed

```yaml
# .rampart/policy.yaml in your repo
version: "1"
policies:
  - name: project-allow-specific-deploy
    match:
      tool: ["exec"]
    rules:
      - action: allow
        when:
          command_matches:
            - "kubectl apply -f k8s/staging/"  # Allow staging only
```

## Audit in CI

Even with denies, you want visibility. Run `rampart serve` in the background for audit collection:

```yaml
- name: Start Rampart audit
  run: |
    rampart serve --background
  
- name: Run agent
  run: rampart wrap -- python agent.py
  
- name: Upload audit
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: rampart-audit
    path: ~/.rampart/audit/*.jsonl
```

## See Also

- [Native Ask Prompt](./native-ask.md) — interactive approval for local development
- [Project Policies](./project-policies.md) — team-shared rules in your repo
- [Wazuh Integration](./wazuh-integration.md) — SIEM integration for CI audit trails
