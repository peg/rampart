# rampart-openclaw-plugin

**Rampart AI agent firewall — native OpenClaw plugin (v1.0)**

This OpenClaw plugin integrates [Rampart](https://github.com/peg/rampart) using the native `before_tool_call` hook API (OpenClaw ≥ 2026.3.28). It is the primary integration path, replacing the legacy dist-file patching approach.

---

## Quick start

```bash
# 1. Install Rampart
go install github.com/peg/rampart@latest

# 2. Start Rampart policy server (defaults to :9090)
rampart serve

# 3. Install this plugin
openclaw plugins install /path/to/rampart-openclaw-plugin
```

That's it. Every tool call is now checked against your Rampart policies.

---

## What happens on each decision

Every time the OpenClaw agent calls a tool (`exec`, `read`, `write`, `web_fetch`, `message`, etc.), this plugin intercepts the call **before it executes** and checks it against the running Rampart policy engine (`rampart serve`).

| Decision | What happens |
|----------|-------------|
| `allow`  | Tool call proceeds normally |
| `deny`   | Tool call is blocked; agent sees a `blockReason` message |
| `ask`    | OpenClaw pauses and prompts you for approval (120 s timeout → auto-deny) |

### The always-allow flow

When Rampart returns `ask` and you click **Allow Always** in the OpenClaw approval UI:

1. The plugin calls `POST /v1/approvals/{id}/resolve` with `persist: true`
2. Rampart writes a rule to `~/.rampart/policies/auto-allowed.yaml`
3. Future calls matching the same tool + pattern are automatically allowed — you are never asked again

### Fail-open behavior

If `rampart serve` is not running or unreachable, the plugin **fails open** (allows the call) and logs at debug level. This matches Rampart's existing default behavior and keeps OpenClaw functional when Rampart is down.

If `rampart serve` is reachable but returns a 5xx error, the plugin also fails open but logs a warning.

---

## Configuration

Plugin config lives in your OpenClaw config file under `plugins.rampart`:

```yaml
plugins:
  rampart:
    serveUrl: "http://localhost:9090"   # default
    enabled: true                        # default
    timeoutMs: 3000                      # ms to wait for Rampart before failing open
    approvalTimeoutMs: 120000            # ms before unanswered approval auto-denies
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `serveUrl` | string | `http://localhost:9090` | Rampart serve endpoint |
| `enabled` | boolean | `true` | Disable the plugin without uninstalling |
| `timeoutMs` | number | `3000` | Max ms to wait for Rampart before failing open |
| `approvalTimeoutMs` | number | `120000` | Ms before an unanswered approval auto-denies |

---

## Authentication

The plugin reads your Rampart token from (in order):

1. `RAMPART_TOKEN` environment variable
2. `~/.rampart/token` file

This matches the standard Rampart CLI token resolution.

---

## Security note

The plugin only makes network calls to **localhost** (or whatever `serveUrl` is configured to). It reads a single token file from `~/.rampart/token`. It does not phone home, send telemetry, or make any external network requests.

---

## Rampart API contract

The plugin calls:

```
POST http://localhost:9090/v1/tool/{toolName}
Content-Type: application/json
Authorization: Bearer <token>

{
  "agent":   "main",
  "session": "...",
  "run_id":  "...",
  "params":  { "command": "ls -la" }
}
```

Expected response shapes:

```json
{ "allowed": true,  "decision": "allow", "message": "..." }
{ "allowed": false, "decision": "deny",  "message": "blocked by policy X", "policy": "no-rm-rf" }
{ "allowed": false, "decision": "ask",   "message": "shell command requires approval", "severity": "warning" }
```

For OpenClaw-hosted plugin flows, Rampart evaluates the tool call but does **not** create a second hidden Rampart approval record. OpenClaw's native approval UI is the only operator-facing approval surface. When the user resolves the native OpenClaw approval:

- `allow-once` is handled entirely by OpenClaw
- `deny` is handled entirely by OpenClaw
- `allow-always` writes a persistent Rampart rule via `POST /v1/rules/learn`

The plugin also posts to `POST /v1/audit` after each tool call (best-effort, fire-and-forget).

---

## Replacing the dist-patching approach

Previously, Rampart intercepted OpenClaw tool calls by patching JavaScript files inside OpenClaw's bundled `dist/` directory:

```bash
sudo rampart setup openclaw --patch-tools --force
```

This was fragile — every `openclaw upgrade` would overwrite the patches.

With this plugin installed, you can remove the dist patches:

```bash
# Re-install OpenClaw without the patches (or let an upgrade overwrite them)
# The plugin handles interception through the stable hook API instead.
```

---

## Development

```bash
# Verify no syntax errors (ESM import test)
node -e "import('./index.js').then(() => console.log('ok')).catch(e => console.error(e))"

# Verify manifest JSON
cat openclaw.plugin.json | node -e "process.stdin.resume(); let d=''; process.stdin.on('data',c=>d+=c); process.stdin.on('end',()=>{JSON.parse(d); console.log('valid json')})"
```
