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
- explicitly configured fail-open tools remain opt-in and test-covered; the deprecated coarse `failOpen: true` switch maps to `read`, `web_fetch`, `web_search`, and `image` for compatibility
- command-execution aliases such as OpenClaw `bash` map to Rampart `exec` for policy checks, learning, and audit events
- provider-surface replay covers canonical `exec`, nested `input.command`, command aliases, file tools, hosted approval, auth-error fail-closed behavior, audit normalization, and degraded sensitive-tool blocking

This is a deterministic harness for the highest-leverage plugin regression: approval-path behavior without depending on model tool selection.

These local checks do **not** prove that an installed OpenClaw + Codex
app-server runtime fires the hook for native shell calls. The single canonical
procedure and pass criteria for that credentialed proof live in the
[OpenClaw release acceptance checklist](../../../docs/design/openclaw-approval-acceptance-checklist.md).
