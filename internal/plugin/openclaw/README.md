# Rampart OpenClaw plugin smoke test

Deterministic local harness for the OpenClaw `before_tool_call` plugin path.

## Why this exists

Discord DM prompts are not a reliable validator for approval behavior because the model may choose not to call the real tool at all. This smoke test exercises the plugin decision path directly and verifies what Rampart returns to OpenClaw.

## Usage

From the repo root:

```bash
node internal/plugin/openclaw/smoke-test.mjs
node internal/plugin/openclaw/approval-regression.mjs
node internal/plugin/openclaw/degraded-mode-test.mjs
node internal/plugin/openclaw/tool-alias-test.mjs
node internal/plugin/openclaw/provider-surface-replay.mjs
```

Default behavior simulates:
- tool: `exec`
- params: `{ "command": "sudo true" }`
- Rampart verdict: `{ "decision": "ask", "policy": "test-policy", "message": "needs approval", "severity": "warning" }`

Expected output now:
- `result.requireApproval` exists for `exec`
- no `params.ask = "always"` mutation path

## Override inputs

```bash
node internal/plugin/openclaw/smoke-test.mjs \
  '{"decision":"deny","message":"blocked"}' \
  exec \
  '{"command":"sudo true"}'
```

Arguments:
1. tool result JSON
2. tool name
3. tool params JSON

## What to check

- `ask` returns `requireApproval`
- `deny` returns `block: true`
- `allow-always` calls `/v1/rules/learn`
- `allow` returns nothing or param adjustment only when explicitly requested by Rampart
- there is no legacy `params.ask = "always"` mutation path
- degraded mode blocks sensitive tools (`exec`, `write`) when serve is unreachable or returns 5xx
- configured fail-open tools (`read`, `web_fetch`, `web_search`, `image` by default) remain explicit and test-covered
- command-execution aliases such as OpenClaw `bash` map to Rampart `exec` for policy checks, learning, and audit events
- provider-surface replay covers canonical `exec`, nested `input.command`, command aliases, file tools, hosted approval, auth-error fail-closed behavior, audit normalization, and degraded sensitive-tool blocking

This is a deterministic harness for the highest-leverage plugin regression: approval-path behavior without depending on model tool selection.

It still does **not** prove that the currently installed OpenClaw + Codex app-server runtime is firing the hook for native shell calls. Use the live runtime regression below for that.

## Live Codex app-server shell-audit regression

Run this only when you intentionally want a real local OpenClaw runtime check:

```bash
RAMPART_OPENCLAW_RUNTIME=1 node scripts/test-openclaw-codex-native-audit.mjs
```

The live regression temporarily enables the Rampart OpenClaw plugin, points it at an ephemeral local `rampart serve`, restarts the OpenClaw user services, runs one real OpenClaw Codex app-server turn, and restores the prior OpenClaw config/token state before exit.

Pass criteria:
- a `*.jsonl.codex-app-server.json` metadata file exists for the test session
- the OpenClaw trajectory contains a native Codex `bash` tool call for the marker command
- the temporary Rampart audit log contains a correlated canonical `exec` event for that marker command

A successful assistant response or OpenClaw trajectory alone is not enough; this test fails unless Rampart audit proves the native shell call crossed the policy path.

## Live validation notes

For a real end-to-end OpenClaw validation, do not rely on plain chat text alone as proof. The important thing is that the assistant actually makes a real tool call.

Recommended live checks:
- `sudo true` after an `Allow Always` decision, should run without prompting
- `sudo id` as a fresh privileged command, should prompt
- `rm -rf /tmp`, should hard-deny

Important:
- make sure `rampart-serve.service` is running before drawing conclusions
- if Rampart serve is down, sensitive tools should now block instead of silently failing open; lower-risk tools listed in `failOpenTools` remain fail-open by configuration
- durable learned rules from the OpenClaw plugin are written to `~/.rampart/policies/user-overrides.yaml`
