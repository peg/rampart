---
title: Gemini CLI
description: Protect Gemini CLI tool calls with native BeforeTool and AfterTool hooks.
---

# Securing Gemini CLI with Rampart

Rampart uses Gemini CLI's native
[`BeforeTool` and `AfterTool` hooks](https://geminicli.com/docs/hooks/reference/)
to evaluate host-exposed tool calls before execution and inspect responses
afterward.

!!! note "Current Google product split"
    Google moved unpaid and Google One users to Antigravity CLI on June 18,
    2026. Gemini CLI remains supported for Gemini Code Assist Standard and
    Enterprise organizations, Google Cloud users, and paid API-key access.
    This integration targets that continuing Gemini CLI enterprise surface; it
    does not claim Antigravity CLI compatibility.

## Zero-configuration protection

If Gemini CLI is installed or has a `~/.gemini` configuration directory:

```bash
rampart protect gemini
```

Running `rampart protect` without a target auto-detects Gemini CLI alongside
other supported local agents. It installs the managed Guard policy, ensures the
local service is available, configures the hooks, and runs safe verification.

For setup without the managed protection workflow:

```bash
rampart setup gemini
```

Setup adds wildcard lifecycle entries to `~/.gemini/settings.json`. Existing
settings and unrelated hooks are preserved, and rerunning setup is idempotent.

## Coverage and decisions

Rampart normalizes Gemini's documented shell, file, search/fetch, MCP, memory,
task, and delegated-agent tool surfaces. Unknown future `BeforeTool` names deny
in enforce mode until Rampart classifies their security consequence.

An allow result is emitted as empty JSON so Rampart never bypasses Gemini's own
permission and sandbox checks. Denials use Gemini's structured
`{"decision":"deny"}` response.

Gemini hooks do not currently expose a native `ask` response. Rampart therefore
uses its blocking external approval queue for approval-required calls. The
exact hook invocation resumes after approval; if `rampart serve` is unavailable,
the call denies instead of assuming the host will prompt or silently allowing it.

## Verify

```bash
rampart verify gemini
```

This confirms both lifecycle hooks are installed, invokes the real Rampart
adapter with a non-executing destructive canary, requires Gemini's structured
deny response, checks session-correlated audit output, and tests the live local
policy path. It does not invoke a model or execute the canary command.

The current support claim covers adapter behavior on Linux and macOS. A rolling
latest-Gemini compatibility job, authenticated live-host proof, and physical
Windows host proof remain release-assurance follow-ups.

## Uninstall

```bash
rampart setup gemini --remove
```

Only Rampart-owned hook entries are removed.
