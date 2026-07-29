---
title: Release Compatibility Gate
description: "How Rampart validates Claude Code, Codex, experimental Gemini CLI, GitHub Copilot, Cline, OpenClaw, and Hermes Agent claims before release."
---

# Release Compatibility Gate

Use this checklist before publishing a Rampart release that advertises agent integration support. It keeps support claims tied to evidence from the exact candidate build, not a prior local install or stale plugin copy.

## Support tiers

Rampart uses these tiers in the support matrix:

- **Recommended**: actively tested against the current stable runtime, polished approval UX, and clear `rampart doctor` checks.
- **Supported**: documented and regression-covered, with narrower UX or less frequent runtime smoke coverage.
- **Experimental**: installable and useful, but with known limits that are still part of the public contract.
- **Legacy compatibility**: maintained where practical for older clients, but not the preferred path.

Gemini CLI remains **experimental** because consumer Google sign-in is retired, Antigravity uses a different plugin surface, and the gate does not make an authenticated model/tool call. Hermes Agent remains **experimental** until Hermes exposes a stable plugin approval/resume primitive and a full end-to-end test proves a single user-facing approval, exact tool-call resume, deny non-bypass, and audit/result correlation.

## Required gate for release candidates

1. **Start from a clean candidate**
   - Fetch the target release branch and validate a clean worktree.
   - Build the exact candidate commit.
   - Reinstall bundled agent plugins from that exact build.
   - Compare binary version, plugin manifest version, and runtime-reported plugin version.

2. **Check upstream version currency**
   - Record current Claude Code with `claude update` and `claude --version`.
   - Record the current Codex version exercised by the host harness.
   - Record the current Cline version reviewed or exercised; if no host run is
     completed, keep that limitation explicit in the support matrix.
   - Record latest stable Gemini CLI from npm and note whether the tested access
     is enterprise, Google Cloud, or paid API-key based.
   - Record latest stable GitHub Copilot CLI from the official npm package and
     the VS Code version used for any Preview hook-host claim.
   - Record latest stable OpenClaw from npm.
   - Record latest stable Hermes Agent from PyPI.
   - Treat upstream release notes touching plugin discovery, hook dispatch, approval behavior, native tool relay, model/tool execution, or security boundaries as compatibility-relevant.

3. **Validate current Claude Code**
   - Review Anthropic's current tool and hook references for newly hook-visible
     tools and documented host-owned exceptions.
   - Confirm every documented hook-visible tool is deliberately classified,
     and require unknown `PreToolUse` names to fail closed in enforce mode.
   - Install the candidate hooks into a disposable Claude home and confirm
     `PreToolUse`, `PostToolUse`, and `PostToolUseFailure` are present.
   - Run `scripts/compat-claude-host.sh --yes` only from an authenticated
     maintainer installation. Require a denied command that did not execute, an
     allowed command that did execute, and matching pre/post tool-call identity.
   - Do not call Claude host support verified when only adapter tests pass.

4. **Validate latest stable OpenClaw**
   - Use a controlled OpenClaw state, not a dirty local gateway config.
   - Install the candidate Rampart OpenClaw plugin.
   - Run `openclaw config validate` when available.
   - Confirm plugin metadata reports the candidate version and startup activation.
   - Exercise allow, ask, and deny with a unique marker.
   - For command execution paths, require OpenClaw runtime evidence plus a correlated Rampart audit event for canonical `exec`.
   - Check for stale shim, dist patch, or duplicate enforcement paths before calling the result clean.

5. **Validate current Codex**
   - Run `rampart verify codex` against the installed candidate hook definition.
   - Require the adapter canary to deny without execution and confirm existing
     unrelated user hooks remain intact.
   - Run `scripts/compat-codex-host.sh --yes --rampart-bin ./rampart` from an
     authenticated maintainer installation when making a real-host claim.
   - Require denied execution, successful allowed execution, and correlated
     pre/post tool-call identity from the disposable Codex home.
   - Record physical Windows validation separately; cross-compilation and
     Windows unit tests do not prove a live Windows Codex host boundary.

6. **Validate Cline without overstating it**
   - Exercise direct POSIX and `.ps1` setup, ownership/migration, current editor
     and CLI payload, batched command/path, and adapter regression tests.
   - Review the latest source-level hook discovery, payloads, and tool catalog
     for shell, file, web, agent/team, plugin, and MCP changes.
   - Confirm POSIX executable-bit activation, Windows PowerShell/file-presence
     behavior, `--data-dir` independence, and whether upstream `--hooks-dir`
     is actually consumed.
   - Confirm legacy CLI `--yolo` still disables runtime hooks and document it
     as incompatible with this boundary while that remains true.
   - Recheck whether CLI pre-hook failures/timeouts still continue and whether
     post-tool hook control responses are still ignored; do not claim
     fail-closed or CLI response blocking while those behaviors remain.
   - Do not claim rolling-latest or real-host verification until a current Cline
     installation invokes the candidate hooks and harmless allow/deny behavior
     is recorded.
   - Keep physical Windows host proof separate from source review, unit tests,
     and cross-compilation.

7. **Validate experimental enterprise Gemini CLI without conflating adapter and host proof**
   - Run `node scripts/compat-gemini-latest.mjs` to install the latest published
     package in a disposable home, generate candidate hooks, and require the
     documented destructive `BeforeTool` denial schema.
   - Run `rampart verify gemini` against the candidate settings.
   - Confirm every currently documented built-in tool has a deliberate mapping;
     unknown future `BeforeTool` names must deny in enforce mode.
   - Do not claim an authenticated host boundary until a real Gemini tool call
     proves the denied command did not execute and an allowed command did.
   - Do not describe this as Antigravity CLI coverage; it is a separate product
     surface after Google's June 2026 transition.

8. **Validate latest stable GitHub Copilot CLI and the shared VS Code schema**
   - Run `node scripts/compat-copilot-latest.mjs` with a disposable home and
     `COPILOT_HOME`.
   - Require the generated hook file to contain PascalCase `PreToolUse` and
     `PostToolUse` commands for Bash/PowerShell, then require both the Copilot
     CLI and VS Code destructive-call denial fields from the candidate adapter.
   - Run `rampart verify copilot` against the candidate hook file.
   - Do not call this authenticated host-boundary proof: the credential-free
     rolling gate starts the latest package and invokes the adapter directly;
     the version command does not prove that the host loaded or dispatched the
     generated hooks.
   - Record that Copilot CLI hook timeouts fail open, including administrator
     policy hooks, and that VS Code agent hooks remain an upstream Preview.

9. **Validate latest stable Hermes Agent in isolation**
   - Use a temporary `HERMES_HOME` or temporary home directory.
   - Install latest Hermes Agent in a temporary Python environment.
   - Install the candidate Rampart plugin into only that temporary Hermes plugin directory.
   - Enable only the temporary Hermes config.
   - Exercise the real Hermes plugin dispatcher, including plugin discovery and `pre_tool_call` hook registration.
   - Prove deny blocks before execution, allow continues, `ask` blocks with an approval-required/no-resume message, Rampart auth failures fail closed for mutating tools, and mutating tools fail closed when Rampart is unavailable.
   - Do not restart or mutate a live Discord, Telegram, or other long-running Hermes gateway for this gate.

10. **Run `rampart doctor` as a support-contract check**
   - Group findings by integration surface.
   - Classify each finding as blocker, expected optional local gap, or follow-up diagnostic improvement.
   - Do not collapse OpenClaw, Hermes, Claude Code, Codex, and Cline findings into one global yes/no.

11. **Publish claims that match the evidence**
   - Coverage means tool calls delivered through the named integration
     boundary, not all syscalls, packets, or behavior inside allowed processes.
   - A harness proves a live check is available; only a completed sanitized run
     can substantiate a host-passed claim.
   - A completed Claude Code shell host proof supports only the shell claim;
     file, network, MCP, subagent, crash, and timeout behavior keep their own
     evidence levels until separately exercised.
   - OpenClaw can be called recommended only when the latest stable path has fresh runtime/audit proof.
   - Hermes can be called an experimental policy gate when isolated latest-Hermes plugin dispatch has deny, allow, ask-block, and fail-closed proof.
   - First-class Hermes support requires Hermes-owned approval/resume APIs plus live or staging end-to-end validation.

## CI and local compatibility scripts

The repository includes compatibility harnesses for latest upstream agent checks:

```bash
python scripts/compat-hermes-latest.py
node scripts/compat-openclaw-latest.mjs --npm-latest
node scripts/compat-gemini-latest.mjs
node scripts/compat-copilot-latest.mjs
scripts/compat-claude-host.sh --yes
scripts/compat-codex-host.sh --yes
```

The Hermes harness installs or uses an isolated Hermes runtime and never touches the active gateway. The OpenClaw harness can run either the `openclaw` on `PATH` or `--npm-latest` for the latest npm package, uses a temporary home/state directory, and validates plugin installation plus the bundled plugin behavior checks. The Gemini and Copilot gates use disposable homes and start the latest published packages, then separately validate candidate-generated configuration shapes and exercise their adapters without credentials or model calls. Their version commands do not prove that either host ingested or dispatched the hooks. Harnesses propagate only an allowlist of runtime variables and standard credential-free registry/proxy URLs; URLs containing userinfo, query strings, or fragments are dropped.

For OpenClaw's recommended support tier, also run the opt-in runtime audit regression before a release promotion:

```bash
export RAMPART_OPENCLAW_ISOLATION_ROOT=/path/to/disposable/root
export HOME="$RAMPART_OPENCLAW_ISOLATION_ROOT/home"
export OPENCLAW_STATE_DIR="$HOME/.openclaw"
export OPENCLAW_CONFIG_PATH="$OPENCLAW_STATE_DIR/openclaw.json"
RAMPART_OPENCLAW_RUNTIME=1 \
RAMPART_OPENCLAW_RESTART_SERVICES= \
node scripts/test-openclaw-codex-native-audit.mjs
```

The isolation root must contain a prepared, disposable OpenClaw state and authenticated Codex test agent whose gateway is already running against that state. Configure `plugins.entries.rampart` with `enabled: true`, `serveUrl: http://127.0.0.1:19090`, and `failOpen: false` before starting that gateway. Never point the test at a primary OpenClaw home. The script refuses paths outside the isolation root and refuses service restarts.

That live regression is intentionally separate from scheduled CI because it uses a real OpenClaw Codex app-server. It proves routine native-shell interception, the complete hosted approval path (pending plugin approval, `allow-once`, exact tool-call resume, and successful execution), and a native hard-deny whose disposable canary remains unchanged. Every path requires correlated trajectory and Rampart canonical `exec` audit evidence.

A scheduled/manual GitHub Actions workflow runs these upstream checks outside the core unit-test matrix so external upstream breakage is visible without destabilizing ordinary pull-request CI.
