---
title: Quick Start
description: "Install Rampart, protect a supported agent, and inspect the evidence from its configured boundary."
---

# Quick Start

Install Rampart, configure the integration, and inspect what it actually
verified. For a hands-on check of host execution and approval, continue with
the [harmless marker walkthrough](tutorial.md).

## Install

=== "Homebrew"

    ```bash
    brew install peg/tap/rampart
    ```

=== "macOS / Linux script"

    ```bash
    curl -fsSL https://rampart.sh/install | sh
    ```

=== "Windows PowerShell"

    ```powershell
    irm https://rampart.sh/install.ps1 | iex
    ```

=== "Go"

    ```bash
    go install github.com/peg/rampart/cmd/rampart@latest
    ```

For requirements and package details, see [Installation](installation.md).

## Protect detected agents

```bash
rampart protect
```

This discovers integrations in Rampart's auto-protect registry, installs the
managed Guard policy, starts or verifies the local service, configures the
appropriate boundary, and runs its safe verification. You can choose a single
supported integration instead:

```bash
rampart protect claude-code
rampart protect openclaw
```

OpenClaw protection restarts its gateway. Follow any host trust or activation
instructions in the result before relying on the integration.

Experimental integrations require explicit setup and remain outside bare
`protect` detection. For example, `rampart setup hermes` installs its experimental
plugin. Use the [support matrix](support-matrix.md) to choose the right path and
understand approval, platform, and host-failure limits.

`rampart quickstart` remains a deprecated compatibility command for existing
scripts; new installations should use `protect`.

## Inspect the result

```bash
rampart verify --all
rampart doctor
rampart status
rampart watch
```

`verify --all` runs fixed, non-executing canaries without invoking a model.
It checks configured integrations with active safe verifiers; static-only
integrations such as Hermes are omitted and remain visible in `doctor`.
Exit status 1 means a failed expectation; 2 means an incomplete or unreachable
check without a failed expectation.

Read the reported evidence level. Installed configuration and adapter checks
do not prove that a running host loaded and invoked the integration. Use your
agent normally and inspect its decisions in `watch`; the
[marker walkthrough](tutorial.md) explains how to confirm the actual host path.

## Approval UX by integration

An `ask` rule requires human review. The integration determines where it appears
and whether it can resume a held call:

- Claude Code normally uses its native prompt; OpenClaw uses its native UI.
- Codex and Cursor use Rampart's external queue and require `rampart serve`.
- Cline and standalone `rampart mcp` refuse asks because they have no connected
  resolver. Starting `serve` alone does not add one.

For Rampart-owned pending requests, open the dashboard at
`http://localhost:9090/dashboard/`, or run `rampart pending --details`, followed
by `rampart approve <id>` or `rampart deny <id>`. **Approve Pending** resolves
only the reviewed calls. **Allow Future** separately grants temporary authority
for the exact displayed run and credential owner.

See [approval paths and limits](support-matrix.md#approval-paths-and-limits)
for the complete integration table.

## Customize protection

Run policy changes yourself in a terminal. Start by inspecting the matched rule:

```bash
rampart policy explain "npm install example"
rampart rules
```

Use [Customizing Policy](../guides/customizing-policy.md) for durable allow/block
rules, [Project Policies](../guides/project-policies.md) for repository-specific
restrictions, and [Testing Policies](../guides/testing-policies.md) to check a
change before relying on it. An ordinary allow policy cannot override an
applicable deny.

For an MCP server or non-native agent, follow [MCP Proxy](../features/mcp-proxy.md)
or [Any CLI Agent](../integrations/any-cli-agent.md); those paths have distinct
observation and approval limits.
