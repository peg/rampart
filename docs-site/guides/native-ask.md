---
title: Native Ask Prompt
description: "Use action: ask with Claude Code's native approval UI and understand audit mirroring and external approval mode."
---

# Native Ask Prompt (`action: ask`)

For Claude Code's normal native-hook path, Rampart returns
`permissionDecision: "ask"` when a policy requires review. Claude owns the
visible prompt, the user's decision, and resumed execution. Use `deny` for
operations that must not be authorized through a prompt.

Other integrations have different owners and capabilities. See
[Approval paths and limits](../getting-started/support-matrix.md#approval-paths-and-limits)
before relying on the same policy across hosts.

## Policy syntax

Use Rampart's normalized tool names such as `exec`, not host names such as
`Bash`. Put `action` and `when` inside the policy's `rules` list:

```yaml
version: "1"
policies:
  - name: review-deployment
    match:
      tool: [exec]
    rules:
      - action: ask
        when:
          command_matches: ["kubectl apply *"]
        message: "Review this deployment"
```

An applicable deny still wins. The prompt does not grant an exception to a
Rampart deny or prove what an allowed program will do internally.

## Ask options

### `audit: true` — Mirror native review activity

```yaml
ask:
  audit: true
```

For native Claude asks, this enables best-effort pending-state mirroring to a
reachable `rampart serve` and outcome correlation from later host tool events.
The native prompt still owns execution. Resolving the mirrored dashboard entry
does not resume or cancel Claude's prompt, and a missing later event does not
prove which choice the human made. Ordinary policy decisions are audited
independently of this optional mirroring.

### `headless_only: true` — Use the external approval queue

```yaml
ask:
  headless_only: true
```

Despite the option's name, this selects the service-backed blocking approval
path instead of Claude's native prompt; it does not detect whether a person or
TTY is present. A reachable `rampart serve` is required. The hook waits for an
external resolution for up to five minutes, with no native ask fallback.
A shorter host hook timeout can end the wait first, subject to that host's
failure behavior.

For unattended jobs that must never wait for review, use explicit `deny` rules
or the `ci` profile. See [CI/Headless Agents](ci-headless.md).

## Host limits

Keep Claude's own permission and sandbox settings appropriate to the work.
Rampart cannot turn a host hook launch failure or timeout into a veto; normal
host permissions apply. Native prompt rendering, permission modes, and resume
semantics belong to the installed Claude version. Consult the
[Claude integration guide](../integrations/claude-code.md#failure-boundary)
for the current reviewed boundary.

## Check your policy and installation

```bash
rampart policy lint ~/.rampart/policies/my-policy.yaml
rampart test --tool exec --config ~/.rampart/policies/my-policy.yaml "kubectl apply -f example.yaml"
rampart verify claude-code
```

`test` is a policy dry run; `verify` checks installed configuration and adapter
behavior. For an actual host approval and execution check, use the
[harmless marker walkthrough](../getting-started/tutorial.md).

Old policy files using `require_approval` must migrate to `ask`; see the
[upgrade note](../getting-started/upgrade.md#legacy-approval-actions).
