---
title: Release Compatibility Gate
description: "How Rampart validates advertised agent integrations before release, including latest OpenClaw and experimental Hermes Agent checks."
---

# Release Compatibility Gate

Use this checklist before publishing a Rampart release that advertises agent integration support. It keeps support claims tied to evidence from the exact candidate build, not a prior local install or stale plugin copy.

## Support tiers

Rampart uses these tiers in the support matrix:

- **Recommended**: actively tested against the current stable runtime, polished approval UX, and clear `rampart doctor` checks.
- **Supported**: documented and regression-covered, with narrower UX or less frequent runtime smoke coverage.
- **Experimental**: installable and useful, but with known limits that are still part of the public contract.
- **Legacy compatibility**: maintained where practical for older clients, but not the preferred path.

Hermes Agent remains **experimental** until Hermes exposes a stable plugin approval/resume primitive and a full end-to-end test proves a single user-facing approval, exact tool-call resume, deny non-bypass, and audit/result correlation.

## Required gate for release candidates

1. **Start from a clean candidate**
   - Fetch the target release branch and validate a clean worktree.
   - Build the exact candidate commit.
   - Reinstall bundled agent plugins from that exact build.
   - Compare binary version, plugin manifest version, and runtime-reported plugin version.

2. **Check upstream version currency**
   - Record latest stable OpenClaw from npm.
   - Record latest stable Hermes Agent from PyPI.
   - Treat upstream release notes touching plugin discovery, hook dispatch, approval behavior, native tool relay, model/tool execution, or security boundaries as compatibility-relevant.

3. **Validate latest stable OpenClaw**
   - Use a controlled OpenClaw state, not a dirty local gateway config.
   - Install the candidate Rampart OpenClaw plugin.
   - Run `openclaw config validate` when available.
   - Confirm plugin metadata reports the candidate version and startup activation.
   - Exercise allow, ask, and deny with a unique marker.
   - For command execution paths, require OpenClaw runtime evidence plus a correlated Rampart audit event for canonical `exec`.
   - Check for stale shim, dist patch, or duplicate enforcement paths before calling the result clean.

4. **Validate latest stable Hermes Agent in isolation**
   - Use a temporary `HERMES_HOME` or temporary home directory.
   - Install latest Hermes Agent in a temporary Python environment.
   - Install the candidate Rampart plugin into only that temporary Hermes plugin directory.
   - Enable only the temporary Hermes config.
   - Exercise the real Hermes plugin dispatcher, including plugin discovery and `pre_tool_call` hook registration.
   - Prove deny blocks before execution, allow continues, `ask` blocks with an approval-required/no-resume message, Rampart auth failures fail closed for mutating tools, and mutating tools fail closed when Rampart is unavailable.
   - Do not restart or mutate a live Discord, Telegram, or other long-running Hermes gateway for this gate.

5. **Run `rampart doctor` as a support-contract check**
   - Group findings by integration surface.
   - Classify each finding as blocker, expected optional local gap, or follow-up diagnostic improvement.
   - Do not collapse OpenClaw, Hermes, Claude Code, Codex, and Cline findings into one global yes/no.

6. **Publish claims that match the evidence**
   - OpenClaw can be called recommended only when the latest stable path has fresh runtime/audit proof.
   - Hermes can be called an experimental policy gate when isolated latest-Hermes plugin dispatch has deny, allow, ask-block, and fail-closed proof.
   - Full Hermes support requires Hermes-owned approval/resume APIs plus live or staging end-to-end validation.

## CI and local compatibility scripts

The repository includes compatibility harnesses for latest upstream agent checks:

```bash
python scripts/compat-hermes-latest.py
node scripts/compat-openclaw-latest.mjs --npm-latest
```

The Hermes harness installs or uses an isolated Hermes runtime and never touches the active gateway. The OpenClaw harness can run either the `openclaw` on `PATH` or `--npm-latest` for the latest npm package, uses a temporary home/state directory, and validates plugin installation plus the bundled plugin behavior checks.

For OpenClaw's recommended support tier, also run the opt-in runtime audit regression before a release promotion:

```bash
RAMPART_OPENCLAW_RUNTIME=1 node scripts/test-openclaw-codex-native-audit.mjs
```

That live regression is intentionally separate from scheduled CI because it temporarily enables the OpenClaw Rampart plugin, restarts local OpenClaw user services, runs one real OpenClaw Codex app-server turn, and requires correlated OpenClaw trajectory plus Rampart canonical `exec` audit proof.

A scheduled/manual GitHub Actions workflow runs these upstream checks outside the core unit-test matrix so external upstream breakage is visible without destabilizing ordinary pull-request CI.
