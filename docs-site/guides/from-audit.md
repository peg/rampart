# Generate Policy from Observed Behavior

Instead of writing policy rules by hand, let Rampart watch what your agent actually does — then generate rules to match.

This is the fastest way to go from "no policy" to "production-ready policy" without guessing what your agent needs.

## How it works

```
1. Run Rampart in monitor mode        → logs every tool call
2. Let your agent do its normal work   → builds a behavior profile
3. rampart init --from-audit           → generates policy YAML from logs
4. Review, tweak, deploy               → enforce with confidence
```

## Step 1: Run in monitor mode

Start Rampart with `--mode monitor` so it logs everything but blocks nothing:

```bash
rampart serve --mode monitor
```

Now run your agent through its typical workflows — coding tasks, file operations, API calls, whatever it normally does. The more representative the workload, the better the generated policy.

!!! tip "How long to observe?"
    A few hours of real work is usually enough. If your agent has distinct workflows (coding vs. research vs. deployment), run each one.

## Step 2: Generate policy from audit logs

```bash
rampart init --from-audit ~/.rampart/audit/
```

This reads the audit log, identifies patterns, and outputs a policy YAML file. Only **allowed** events are used — if something was denied (by a pre-existing rule), it won't be included.

### Useful flags

| Flag | Description |
|------|-------------|
| `--since 24h` | Only use events from the last 24 hours |
| `--since 2026-03-01` | Only use events after a specific date |
| `--dry-run` | Preview the generated policy without writing |
| `--output custom.yaml` | Write to a specific file |

### Example: last 24 hours, preview first

```bash
# See what would be generated
rampart init --from-audit ~/.rampart/audit/ --since 24h --dry-run

# Looks good — write it
rampart init --from-audit ~/.rampart/audit/ --since 24h --output my-agent-policy.yaml
```

## Step 3: Review and refine

The generated policy is a starting point, not a finished product. Review it for:

- **Over-permissive rules** — Did your agent `curl` a URL during testing that shouldn't be allowed in production? Remove it.
- **Missing deny rules** — `--from-audit` generates allow rules. Add explicit deny rules for things you never want (e.g., `rm -rf /`, writing to `/etc/`).
- **Consolidation** — Multiple specific `command_matches` rules might be better as one glob pattern.

## Step 4: Deploy

```bash
# Copy to your policy directory
cp my-agent-policy.yaml ~/.rampart/policies/

# Restart in enforce mode
rampart serve --mode enforce
```

## Best practices

**Start with monitor, graduate to enforce.** Don't jump straight to enforcement on a new agent. A few days of monitoring catches edge cases you'd never think of.

**Re-generate periodically.** As your agent's capabilities evolve, re-run `--from-audit` on recent logs to catch new patterns. Diff the output against your existing policy.

**Version control your policies.** Policy YAML belongs in your repo alongside the code it protects. Review policy changes in PRs just like code changes.

**Combine with the policy registry.** Start with a community policy from `rampart init --registry`, then layer your generated policy on top for agent-specific rules.
