---
title: Troubleshooting
description: "Find the next step for Rampart installation, policy, approval, and integration problems, or share a minimal redacted bug report."
---

# Troubleshooting

Start with the symptom you can observe. A policy test, an installed hook, and
an agent actually invoking that hook establish different things.

- [The CLI is not found](#rampart-command-not-found)
- [Commands are not blocked](#commands-not-blocked)
- [Expected work is blocked](#everything-blocked)
- [Claude Code reports a hook error](#hook-error-startup)
- [OpenClaw is not protected](#openclaw-plugin-not-intercepting-tool-calls)
- [Report a problem](#still-stuck)

## First checks

```bash
rampart version
rampart doctor
rampart verify --all
```

Read these results locally. `doctor` inspects configuration; `verify` checks
the supported configured boundaries that have an active verifier, without a
model request. `adapter_verified` does not prove that an authenticated host
invoked its hooks. Use the [support matrix](support-matrix.md) to interpret the
result for your integration. You do not need to publish the complete output
to [report a problem](#still-stuck).

## `rampart: command not found` {#rampart-command-not-found}

Open a new terminal after installation. If the command is still missing, check
the install method in the [installation guide](installation.md).

**Homebrew:** check that the package is installed, then link its executable:

```bash
brew list rampart
brew link rampart
```

**Go install:** add Go's bin directory to this shell's `PATH`:

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
rampart version
```

If that works, add the export to the appropriate startup file for your shell.
The Unix installer normally uses `~/.local/bin`; the Windows installer uses
`~/.rampart/bin`. Use the path reported by your installer if you chose a custom
location. Avoid replacing an unrelated executable or symlink to fix `PATH`.

## Commands aren't being blocked {#commands-not-blocked}

!!! warning "Suspected security bypass?"
    If a covered action can bypass a deny rule, follow the private reporting
    route in [SECURITY.md](https://github.com/peg/rampart/blob/main/SECURITY.md).
    Do not post bypass details in a public issue or execute a destructive
    command to demonstrate the problem.

### 1. Check the configured integration {#1-are-hooks-installed}

Use `rampart doctor` and `rampart verify --all` first. If an owned integration
is missing or stale, refresh the agent you use, for example:

```bash
rampart protect claude-code
```

Follow the agent's restart or hook-enablement instructions. Check its
[integration guide](../integrations/index.md) for coverage, host failure
behavior and modes that disable hooks. An installed adapter alone does not
establish interception.

### 2. Check the policy you intended to load {#2-is-your-policy-loading}

Run diagnostics against the specific policy file you are investigating:

```bash
rampart policy lint ./policy.yaml
rampart --config ./policy.yaml policy explain "git status"
```

Replace the example filename with your policy. These diagnostics inspect that
file; they do not prove the host or service loaded it. Check the integration's
configured policy location and any project policies or service overrides in
the [configuration guide](configuration.md).

### 3. Test the represented action {#3-does-your-rule-actually-match}

```bash
rampart --config ./policy.yaml test "git status"
rampart --config ./policy.yaml test --tool read "/etc/shadow"
```

These commands evaluate the supplied text. They do not execute `git status`
or read `/etc/shadow`. Match the tool class and action that the integration
actually exposes. For agent- or session-scoped rules, use the corresponding
`--agent` and `--session` options on `policy explain`.

If the local result differs from your expectation, inspect the matching rule,
its scope and its pattern syntax. See [testing policies](../guides/testing-policies.md)
and the [policy schema](../reference/policy-schema.md). If policy tests pass but
the host behaves differently, investigate the configured integration boundary.

## Everything is blocked {#everything-blocked}

Read the denial reason before changing policy. A default-deny policy needs
explicit allowances for intended work; a matched deny rule takes precedence
over an allow rule. Configuration, service or approval failures can also block
an action.

Use `policy explain` with the relevant policy and a harmless example of the
intended action. Correct the narrow rule or configuration problem, then test
both an expected allowance and an expected denial. Keep unrelated protections
in place. The [policy customization guide](../guides/customizing-policy.md)
explains scopes and rule precedence.

If an approval cannot be completed, check the integration's supported approval
flow. After upgrading, read the [approval-state and OpenClaw review notes](upgrade.md#approval-state-and-openclaw-review)
before restoring old state or retrying an oversized native approval.

## Hook error on Claude Code startup {#hook-error-startup}

First confirm `rampart version` works in the environment that launches Claude
Code. After moving or upgrading the binary, refresh the owned hook configuration:

```bash
rampart protect claude-code
rampart doctor
```

Restart Claude Code if it requests that. If an error remains, check the
[Claude Code guide](../integrations/claude-code.md) and record only the short
relevant error for a report. You do not need to share your full settings file.

## How do I uninstall? {#uninstall}

Use the [uninstall guide](uninstall.md) for your integration and install method.
Removing hooks, removing the binary, and deleting policies or audit history are
separate choices. Keep the data you need before choosing the optional cleanup.

## How do I check if it's working? {#check-working}

Run the [first checks](#first-checks), then follow your integration's evidence
level in the [support matrix](support-matrix.md). For policy-only examples:

```bash
rampart test "git status"
rampart test --tool read "/etc/shadow"
```

A local policy result does not establish that every action in an allowed
process is intercepted. See the [threat model](../reference/threat-model.md)
for the boundary's limits.

## OpenClaw plugin not intercepting tool calls

Inspect the installed plugin and Rampart configuration:

```bash
openclaw plugins list
rampart doctor
```

The plugin's component version may differ from the Rampart CLI patch version.
For supported OpenClaw versions, repair owned state and run its verifier with:

```bash
rampart protect openclaw
```

Use `rampart protect openclaw --reinstall` if you need to replace the bundled
plugin files. Follow the [OpenClaw guide](../integrations/openclaw.md) for version
requirements and restart behavior. An OpenClaw upgrade can require its own
[configuration migration](upgrade.md#approval-state-and-openclaw-review)
before protection succeeds.

**Service unavailable:** managed OpenClaw protection installs an empty
`failOpenTools` list, so tool calls block when the Rampart service is unavailable.
An operator can explicitly opt tools into degraded fail-open behavior; do not
assume that a routine tool is exempt by default. Check `rampart status` and the
configured service URL. If you manage the service separately, restart it with
its existing service configuration. For manual background mode, the supported
command is `rampart serve --background`.

## Still stuck?

For a non-security bug or confusing setup step, [check existing issues](https://github.com/peg/rampart/issues)
and send a short report. The form asks for:

- Rampart and agent/integration versions, plus OS and architecture.
- The install or setup step where you got stuck.
- What you expected and what happened instead.
- The smallest harmless, redacted reproduction you can share, if available.

[Report a non-security bug](https://github.com/peg/rampart/issues/new?template=bug-report.yml){ .md-button .md-button--primary }

Reports are public. Use synthetic filenames and inputs; omit credentials,
personal paths, full logs, configuration files, prompts, sessions and memories.
A short redacted error is enough to start. If you cannot reduce the problem
safely, describe the step that fails without attaching private data.

For a suspected bypass, exposed secret or other vulnerability, use the private
contact in [SECURITY.md](https://github.com/peg/rampart/blob/main/SECURITY.md)
instead of the public form.
