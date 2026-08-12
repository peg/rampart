---
title: Securing Hermes Agent
description: "Experimental Rampart integration for Hermes Agent using a user plugin and pre_tool_call policy checks."
---

# Hermes Agent

Rampart can protect Hermes Agent through an **experimental user plugin**. The plugin registers a Hermes `pre_tool_call` hook, sends a sanitized policy check to Rampart before selected tools execute, passes Hermes' top-level `tool_call_id` for audit correlation, and blocks the tool call when policy denies it.

!!! warning "Experimental integration"
    This integration is intentionally conservative. It does not patch Hermes or create a hidden Rampart approval queue. Current Hermes releases own the `ask` prompt and resume the same tool call; older releases fail closed with an upgrade message. It remains experimental because authenticated live-host proof and full host-failure behavior are not yet established.

## What it covers

The plugin maps common Hermes tools to Rampart policy classes:

| Hermes tool | Rampart class | Notes |
| --- | --- | --- |
| `terminal`, `execute_code` | `exec` | Sends command/script metadata; `execute_code` sends preview and size, not full code by default. |
| `read_file`, `search_files` | `read` | Sends path/pattern metadata. |
| `write_file` | `write` | Sends target path and content size/line counts, not file contents. |
| `patch` | `edit` | Sends mode, patch size, and touched paths. |
| Browser tools | `browser` / `web_fetch` / `web_search` | Sends URL/action metadata where available. |
| `send_message`, `text_to_speech` | `message` | Sends target and message size/preview. |
| `process`, `cronjob` | `process` | Sends action and job/session metadata. |

Unknown Hermes, plugin, and MCP tool names are blocked locally before a policy
request is sent. This prevents a newly introduced mutating capability from
falling through Rampart's generic policy defaults. Add a typed mapping and
tests before enabling a new tool surface.

For Hermes patch calls that carry multiple file updates, Rampart evaluates
every represented path and applies the most restrictive decision to the whole
call. One denied update cannot be hidden by an allowed update in the same
batch.

## Setup

Install the bundled Hermes plugin files:

```bash
rampart setup hermes
```

Then enable the plugin in Hermes and restart any long-running Hermes gateway so plugin discovery reloads:

```bash
hermes plugins enable rampart
# restart the Hermes gateway/service you use for Discord, Telegram, CLI daemon, etc.
```

You can install and enable in one step when `hermes` is available in `PATH`:

```bash
rampart setup hermes --enable
```

## Start Rampart serve

The plugin defaults to `http://127.0.0.1:9090` and reads `RAMPART_TOKEN` or `~/.rampart/token` when present.
It refuses non-loopback service URLs so that local bearer credentials cannot be
sent to an unintended remote endpoint.

```bash
rampart serve --addr 127.0.0.1 --port 9090
```

If your Rampart API uses a different URL, set one of:

```bash
export RAMPART_HERMES_URL=http://127.0.0.1:9090
# or
export RAMPART_URL=http://127.0.0.1:9090
```

Hermes plugin config can also be stored under `plugins.entries.rampart.config`:

```yaml
plugins:
  entries:
    rampart:
      config:
        serve_url: http://127.0.0.1:9090
        timeout_ms: 3000
        endpoint_mode: preflight
```

## Decision behavior

| Rampart decision | Hermes behavior |
| --- | --- |
| `allow`, `watch`, `log` | Tool call continues. |
| `deny` | Tool call is blocked with the policy reason. |
| `ask` | Current Hermes releases show Hermes' native approval and resume the same tool call when approved. Older releases block with an upgrade message. No hidden Rampart approval is created. When Rampart returns an `audit_id`, the prompt message includes it for correlation. |
| Rampart unavailable | Every tool fails closed by default. Advanced operators can explicitly configure selected tools to fail open. |

The default endpoint mode is `preflight`, which calls `POST /v1/preflight/{tool}` with `enforce: true`. This consumes one-time grants and records call-count state at Hermes' actual pre-execution boundary without creating pending Rampart approvals. A current Hermes host owns the approval UI and resumes the same call after approval. Rampart records the evaluation audit ID, and the plugin sends Hermes' top-level `tool_call_id` when Hermes provides one.

For session or `always` choices, the plugin supplies Hermes an opaque, token-keyed
identity of both the original call and its resolved policy paths. This prevents
an approval for one command, URL, content payload, or relative path in one task
directory from applying to another. A Rampart token is therefore required for
native `ask` approval; without one, `ask` fails closed while ordinary allow and
deny decisions continue to work.

For an availability-first deployment, `fail_open_tools` can explicitly list
individual Hermes names such as `web_search`. This weakens the enforcement
boundary and is never enabled by default; credential-bearing reads should stay
fail closed.

Rampart does not request a second hosted approval from its own service. Hermes'
native approval surface is the sole approval owner for this integration.

For experiments that need raw `/v1/tool/{tool}` semantics, set:

```bash
export RAMPART_HERMES_ENDPOINT_MODE=tool
```

Use this only when you understand the approval ownership tradeoff. If a policy returns `ask` in raw tool mode, Rampart may create a Rampart-native pending approval that Hermes cannot resume; keep the default `preflight` mode for normal Hermes testing.

## Verification

Hermes does not yet expose a safe built-in host verifier, so there is no
`rampart verify hermes` command. `rampart verify --all` intentionally skips the
Hermes plugin instead of treating its static configuration as behavioral proof.
Use `rampart doctor` to confirm local installation and service requirements,
then use the isolated compatibility harness for runtime evidence.

Use the isolated latest-Hermes compatibility harness before enabling the plugin on a live gateway:

```bash
python scripts/compat-hermes-latest.py
```

The harness creates a temporary Hermes state, installs the Rampart plugin there, exercises Hermes plugin discovery plus `pre_tool_call` dispatch, and verifies deny, allow, native `ask` approval/denial, and fail-closed behavior without restarting any long-running Hermes gateway.
By default it resolves Hermes' official latest stable GitHub release and uses
an isolated editable checkout of that exact tag, the development install path
Hermes permits. `--package` is an explicit maintainer override; it is not the
definition of the latest supported Hermes release. The check does not use
provider credentials or invoke a model.

!!! warning "Why this remains experimental"
    Hermes currently documents that a plugin callback which fails outside
    Rampart's adapter wrapper can be skipped while agent execution continues.
    Rampart converts ordinary adapter exceptions into explicit blocks, but it
    cannot honestly claim fail-closed behavior after every host-level plugin
    failure. The credential-free compatibility harness proves current-host
    dispatcher behavior, not an authenticated live-agent journey.

## Provider authentication errors

If Hermes reports `Provider authentication failed`, the failure happened before
Hermes attempted a tool call, so it is outside Rampart's policy boundary. From
a terminal on the Hermes host, use `hermes auth status <provider>` to inspect the
selected provider without printing credential values. Run `hermes model` to
renew OAuth or replace an API key, then restart the long-running gateway so it
loads the updated provider state. Do not paste raw gateway logs into a public
issue; they can contain provider details.

For manual verification, use a deny rule for a harmless command and confirm Hermes blocks it before execution:

```bash
rampart serve --addr 127.0.0.1 --port 9090
hermes plugins list
```

Then ask Hermes to run a command that policy denies, such as a harmless unique-marker test pattern. The tool response should include a message beginning with `rampart:` and the command should not execute.

## Uninstall

```bash
hermes plugins disable rampart
rampart setup hermes --remove
```

Restart any long-running Hermes gateway after disabling or removing the plugin.
