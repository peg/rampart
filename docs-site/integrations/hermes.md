---
title: Securing Hermes Agent
description: "Experimental Rampart integration for Hermes Agent using a user plugin and pre_tool_call policy checks."
---

# Hermes Agent

Rampart can protect Hermes Agent through an **experimental user plugin**. The plugin registers a Hermes `pre_tool_call` hook, sends a sanitized policy check to Rampart before selected tools execute, and blocks the tool call when policy denies it.

!!! warning "Experimental integration"
    This integration is intentionally conservative. It does not patch Hermes, does not create a hidden approval queue, and does not resume `ask` decisions automatically. Policies that return `ask` are blocked with an approval-required message until Hermes has a first-class plugin approval/resume flow.

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

Unknown tools are still sent to Rampart using their Hermes tool name with sensitive-looking values redacted.

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
        fail_open_tools:
          - read_file
          - search_files
```

## Decision behavior

| Rampart decision | Hermes behavior |
| --- | --- |
| `allow`, `watch`, `log` | Tool call continues. |
| `deny` | Tool call is blocked with the policy reason. |
| `ask`, `require_approval` | Tool call is blocked with an approval-required message. No hidden Rampart approval is created by default. |
| Rampart unavailable | Mutating/high-risk tools fail closed; configured read-only tools may fail open. |

The default endpoint mode is `preflight`, which calls `POST /v1/preflight/{tool}`. This is deliberate: it avoids creating pending Rampart approvals that Hermes cannot yet resume from a plugin hook.

For experiments that need full `/v1/tool/{tool}` semantics, set:

```bash
export RAMPART_HERMES_ENDPOINT_MODE=tool
```

Use this only when you understand the approval ownership tradeoff.

## Verification

Use a deny rule for a harmless command and confirm Hermes blocks it before execution:

```bash
rampart serve --addr 127.0.0.1 --port 9090
hermes plugins list
```

Then ask Hermes to run a command that policy denies, such as a destructive-command test pattern. The tool response should include a message beginning with `rampart:` and the command should not execute.

## Uninstall

```bash
hermes plugins disable rampart
rampart setup hermes --remove
```

Restart any long-running Hermes gateway after disabling or removing the plugin.
