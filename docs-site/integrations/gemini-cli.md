---
title: Gemini CLI
description: Experimentally protect enterprise/API-key Gemini CLI tool calls with native BeforeTool and AfterTool hooks.
---

# Securing Gemini CLI with Rampart

!!! warning "Experimental enterprise integration"
    This adapter is available for explicit testing but is not included in
    zero-configuration auto-protection. It has rolling adapter compatibility
    coverage, but no completed authenticated host-boundary proof.

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

## Explicit experimental setup

```bash
rampart setup gemini
rampart verify gemini
```

Rampart intentionally does not infer Gemini CLI from the shared `~/.gemini`
directory because Antigravity uses the same tree. This integration is never
installed by a bare `rampart protect` run.

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

The current experimental claim covers adapter behavior on Linux and macOS. A
rolling latest-Gemini compatibility job validates the published CLI and
generated settings without credentials. Authenticated live-host proof and
physical Windows host proof remain release-assurance follow-ups.

## Uninstall

```bash
rampart setup gemini --remove
```

Only Rampart-owned hook entries are removed.
