---
title: CI/Headless Agents
description: "Choose explicit denial or an external approval queue for unattended agents, and verify the installed enforcement boundary."
---

# CI/Headless Agents

Decide whether an unattended job should deny sensitive actions immediately or
wait for an operator. Use explicit `deny` rules when nobody will review the
job. `ask` is appropriate only when the integration has a reachable approval
owner and the job can tolerate its wait and timeout behavior.

## Use a policy with no approval prompts

```bash
rampart init --profile ci
rampart policy lint rampart.yaml
```

The shipped `ci` profile uses denies for its sensitive operations, including
package installation, cloud uploads, and persistence changes. It does not
rewrite other policy files or automatically convert every custom `ask` rule.
Review the active policy set and test the commands your job needs.

Configure your actual host with its [integration guide](../integrations/index.md)
and verify that it invokes the installed boundary. The presence of a policy
file alone does not protect a process. `rampart wrap` only covers a cooperative
`$SHELL` path; wrapping a Python process does not intercept arbitrary Python
file, network, or subprocess APIs.

## External review for a headless job

For the Claude hook, `ask.headless_only: true` selects Rampart's blocking
external approval queue instead of the native prompt:

```yaml
version: "1"
policies:
  - name: reviewed-deployment
    match:
      tool: [exec]
    rules:
      - action: ask
        ask:
          headless_only: true
        when:
          command_matches: ["kubectl apply *"]
        message: "Deployment requires operator review"
```

Run `rampart serve` and have the operator review the complete request in the
dashboard or with `rampart pending --details`, then use `rampart approve <id>`
or `rampart deny <id>`. Agent credentials should not have approval authority.

This option does not inspect the TTY or detect CI. The hook requires a
reachable service and waits up to five minutes for a result; it does not fall
back to a native prompt. An earlier host timeout follows that host's documented
failure behavior. Codex, Cursor, and Gemini already use external approval for
`ask`; integrations without a resolver refuse the action. See the
[approval support table](../getting-started/support-matrix.md#approval-paths-and-limits).

## Customize without weakening the baseline accidentally

Copy a profile to a custom policy and edit only the restrictions you intend to
change. Then point the integration at the intended policy set. Adding an
ordinary higher-priority allow policy does **not** override an applicable deny.
A project policy can tighten the global policy but cannot loosen a global deny.

```bash
rampart policy lint /path/to/ci-custom.yaml
rampart test --config /path/to/ci-custom.yaml "npm ci"
rampart test --config /path/to/ci-custom.yaml "kubectl apply -f k8s/staging/"
```

Treat these as policy checks. Before using the job unattended, verify an allowed
marker reaches the real dispatcher, a denied marker does not, and the installed
host behaves as documented when the approval/service path is unavailable.
Use the [marker walkthrough](../getting-started/tutorial.md) as a starting point
and run failure cases in disposable state.

## Audit and retention

Native hooks write local audit records; `rampart serve` is required for the
external queue and integrations that delegate evaluation to it. Check the
correlated decisions and run `rampart audit verify` after the job.

Audit logs contain operational metadata even after credential redaction. Export
only to access-controlled storage with deliberate retention. Do not upload
personal agent state or credentials as CI artifacts.

- [Project Policies](project-policies.md)
- [Audit Trail](../features/audit-trail.md)
- [SIEM Integration](../features/siem-integration.md)
