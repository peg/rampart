---
title: GitHub Copilot CLI and VS Code
description: Protect Copilot CLI and VS Code agent tool calls with one shared native hook integration.
---

# Securing GitHub Copilot with Rampart

Rampart uses native `PreToolUse` and `PostToolUse` hooks to protect both
[GitHub Copilot CLI](https://docs.github.com/en/copilot/reference/hooks-reference)
and [VS Code agent sessions](https://code.visualstudio.com/docs/agent-customization/hooks).
Both hosts load user hooks from `~/.copilot/hooks`, and Copilot CLI supports the
VS Code-compatible PascalCase payload. Rampart therefore installs one hook file
and one policy adapter rather than maintaining separate integrations.

The latest published CLI package startup and Rampart adapter are tested
separately. An authenticated host run proving that Copilot dispatched the hook
is still pending. VS Code is covered by the shared schema and adapter tests, not
by a separate physical editor host run.

!!! note "VS Code hooks are Preview"
    Copilot CLI hooks are the stable primary support surface. VS Code agent
    hooks are currently an upstream Preview feature, so their configuration or
    behavior may change between VS Code releases.

## Zero-configuration protection

If Copilot CLI or the VS Code Copilot Chat extension is installed:

```bash
rampart protect copilot
```

For setup without the managed protection workflow:

```bash
rampart setup copilot
```

Rampart writes `~/.copilot/hooks/rampart.json` (or
`$COPILOT_HOME/hooks/rampart.json`) with cross-platform `PreToolUse` and
`PostToolUse` commands. Restart Copilot CLI or reload VS Code after setup.

The file is owned entirely by Rampart. Setup refuses to replace an unrelated
`rampart.json` unless `--force` is supplied, and uninstall removes only a file
that still contains Rampart's complete hook contract.

## What is protected

Rampart normalizes Copilot CLI's documented shell, PowerShell, file, search,
web, task, and delegated-agent tools. It also recognizes the documented VS Code
terminal and file-tool forms, including their camelCase and snake_case input
properties. Multi-file edits evaluate every reported path; the most restrictive
decision wins.

Unknown future `PreToolUse` names deny in enforce mode until Rampart classifies
their security consequence. An allow response is empty JSON, preserving
Copilot's own permission prompts and sandbox instead of silently auto-approving
the tool. `ask` uses the host's native approval UI.

Coverage applies only to tool calls the host emits through this lifecycle
boundary. Inline completions and host/server actions that do not emit a hook
are outside the integration.

## Enterprise Copilot CLI policy

Copilot CLI supports administrator-owned machine policy hooks that load before
user hooks and cannot be disabled by users:

```bash
# Linux or macOS
sudo rampart setup copilot --policy

# Windows: run from an elevated PowerShell
rampart setup copilot --policy
```

This installs `50-rampart.json` under Copilot CLI's platform policy directory.
On POSIX systems the resulting file must remain root-owned and not group- or
world-writable. Rampart must be installed at a stable, machine-accessible path.

The `--policy` boundary is **Copilot CLI-only**. For managed VS Code fleets,
deploy the user hook file with MDM or another device-management system, force
the VS Code `ChatHooks` policy on, restrict agent auto-approval, and protect the
deployed file with OS permissions. VS Code does not currently expose Copilot
CLI's administrator policy-hook directory.

## Failure behavior

Copilot CLI `PreToolUse` command-hook crashes and non-zero exits deny, but
Copilot CLI hook **timeouts always fail open**, including administrator policy
hooks. Keep Rampart local and fast, monitor verification, and do not describe
the boundary as absolute containment.

VS Code's Preview hook host blocks on exit code 2 but treats other non-zero
codes as warnings. Rampart normally returns a structured decision with exit
code 0. Unexpected VS Code adapter crashes are not claimed fail-closed.

## Verify

```bash
rampart verify copilot
```

Verification checks the shared hook file, invokes the real adapter with a
non-executing destructive canary, requires both the Copilot CLI and VS Code
deny fields, checks session-correlated audit output, and exercises the live
local policy path. It does not ask a model to execute the canary.

The weekly rolling gate confirms that the latest published `@github/copilot`
package starts in isolated state while Rampart separately validates the shared
schema and adapter. The version command does not prove that Copilot loaded or
dispatched the hooks. An authenticated model/tool host run remains separate
release evidence.

## Uninstall

```bash
rampart setup copilot --remove

# Elevated; removes the CLI administrator policy hook
rampart setup copilot --policy --remove
```
