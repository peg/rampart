# Rampart OpenClaw plugin smoke test

Deterministic local harness for the OpenClaw `before_tool_call` plugin path.

## Why this exists

Discord DM prompts are not a reliable validator for approval behavior because the model may choose not to call the real tool at all. This smoke test exercises the plugin decision path directly and verifies what Rampart returns to OpenClaw.

## Usage

From the repo root:

```bash
node internal/plugin/openclaw/smoke-test.mjs
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

This is a deterministic harness for the highest-leverage regression: approval-path behavior without depending on model tool selection.

## Live validation notes

For a real end-to-end OpenClaw validation, do not rely on plain chat text alone as proof. The important thing is that the assistant actually makes a real tool call.

Recommended live checks:
- `sudo true` after an `Allow Always` decision, should run without prompting
- `sudo id` as a fresh privileged command, should prompt
- `rm -rf /tmp`, should hard-deny

Important:
- make sure `rampart-serve.service` is running before drawing conclusions
- if Rampart serve is down, sensitive tools should now block instead of silently failing open
- durable learned rules from the OpenClaw plugin are written to `~/.rampart/policies/user-overrides.yaml`
