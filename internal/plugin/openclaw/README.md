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
export RAMPART_OPENCLAW_ISOLATION_ROOT=/path/to/disposable/root
export HOME="$RAMPART_OPENCLAW_ISOLATION_ROOT/home"
export OPENCLAW_STATE_DIR="$HOME/.openclaw"
export OPENCLAW_CONFIG_PATH="$OPENCLAW_STATE_DIR/openclaw.json"
RAMPART_OPENCLAW_RUNTIME=1 \
RAMPART_OPENCLAW_RESTART_SERVICES= \
node scripts/test-openclaw-codex-native-audit.mjs
```

Run it only with a prepared, disposable OpenClaw state and authenticated Codex test agent whose gateway is already running against that state. Before starting the isolated gateway, configure `plugins.entries.rampart` with `enabled: true`, `serveUrl: http://127.0.0.1:19090`, and `failOpen: false`. The script starts the ephemeral policy service at that address, runs real OpenClaw Codex app-server turns, leaves OpenClaw config untouched, and restores the isolated token state. It proves routine native-shell interception plus a native plugin approval, `allow-once`, exact resume, and successful execution.

Pass criteria:
- a Codex app-server binding exists in modern OpenClaw plugin state (or the
  legacy `*.jsonl.codex-app-server.json` sidecar on older releases)
- the OpenClaw trajectory contains a native Codex `bash` tool call for the marker command
- the temporary Rampart audit log contains a correlated canonical `exec` event for that marker command
- a second safe command is approved once through `plugin.approval.resolve`, resumes, executes, and has correlated trajectory plus Rampart `ask` audit evidence

A successful assistant response or OpenClaw trajectory alone is not enough; this test fails unless Rampart audit proves the native shell call crossed the policy path.

## Live validation notes

For a real end-to-end OpenClaw validation, do not rely on plain chat text alone as proof. The important thing is that the assistant actually makes a real tool call.

Recommended live checks:
- `sudo true` after an `Allow Always` decision, should run without prompting
- `sudo id` as a fresh privileged command, should prompt
- `rm -rf /tmp`, should hard-deny

Important:
- make sure `rampart-serve.service` is running before drawing conclusions
- if Rampart serve is down, sensitive tools block instead of silently failing open; manual installs may keep lower-risk tools in `failOpenTools`, while `rampart protect openclaw` configures every tool to fail closed
- durable learned rules from the OpenClaw plugin are written to `~/.rampart/policies/user-overrides.yaml`
