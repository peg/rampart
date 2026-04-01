---
title: Securing OpenClaw
description: "Native Rampart integration for OpenClaw — policy enforcement via before_tool_call hook. One command, full coverage."
---

# OpenClaw

Rampart integrates natively with OpenClaw via the `before_tool_call` plugin API. Every tool call — exec, read, write, web_fetch, browser, message, and more — is evaluated against your policy before it runs.

!!! info "Version requirements"
    - **OpenClaw >= 2026.3.28**: Native plugin (recommended) — full tool coverage via `before_tool_call` hook
    - **OpenClaw < 2026.3.28**: Legacy shim + bridge — exec-only coverage, requires re-patching after upgrades

    `rampart setup openclaw` auto-detects your version and uses the right method.

## Setup

```bash
rampart setup openclaw
```

That's it. Rampart:

1. Detects your OpenClaw version
2. **If >= 2026.3.28**: Extracts the bundled plugin and installs it via `openclaw plugins install`
3. Configures OpenClaw to route decisions through Rampart (`tools.exec.ask: off`)
4. Copies the `openclaw.yaml` policy profile to `~/.rampart/policies/openclaw.yaml`
5. Starts `rampart serve` as a boot service (if not already running)

No external downloads, no npm install — the plugin is bundled inside the `rampart` binary.

### Force the native plugin

```bash
rampart setup openclaw --plugin
```

### Migrate from the old shim/bridge integration

```bash
rampart setup openclaw --migrate
```

Removes old dist patches and bridge config, installs the native plugin.

## How it works

```
Agent wants to run a tool (exec, read, write, web_fetch, ...)
  └─ OpenClaw fires before_tool_call hook
       └─ Rampart plugin POSTs to localhost:9090/v1/tool/<name>
            └─ Rampart evaluates openclaw.yaml policy
                 ├─ allow  → tool runs
                 ├─ deny   → tool blocked, agent gets error message
                 └─ ask    → Rampart creates approval, notifies you
                              tool waits until you approve or deny
```

## Coverage

With the native plugin, **all tool calls are covered**:

| Tool | Coverage | Notes |
|------|----------|-------|
| `exec` | ✅ Native plugin | All commands evaluated |
| `read` | ✅ Native plugin | Path-based policy matching |
| `write` / `edit` | ✅ Native plugin | Path-based policy matching |
| `web_fetch` | ✅ Native plugin | Domain allowlist/blocklist |
| `web_search` | ✅ Native plugin | Always allowed by default |
| `browser` | ✅ Native plugin | Domain-based rules |
| `message` | ✅ Native plugin | Read actions always allowed; sends to unknown channels require approval |
| `canvas` | ✅ Native plugin | Always allowed (UI only) |
| `sessions_spawn` | ✅ Native plugin | Subagents cannot spawn further agents |

!!! note "Sub-agents"
    The `before_tool_call` hook fires for tool calls from subagents too. The `openclaw.yaml` profile uses `session_matches: ["subagent:*"]` to apply stricter rules to subagent sessions.

## The `openclaw.yaml` profile

The default profile installed by `rampart setup openclaw`. Key behaviors:

- **`default_action: ask`** — any tool call not matched by an explicit rule surfaces for human approval (no silent failures)
- **Safe exec commands allowed** — `go build`, `npm install`, `git commit`, `docker build`, etc.
- **Dangerous exec requires approval** — `sudo`, `docker run --privileged`, `kubectl delete`, force-push blocked
- **Credential reads require approval** — `.env`, `.kube/config`, `.aws/credentials` ask before reading; SSH keys hard-denied
- **External curl/wget blocked** — use `web_fetch` tool instead (which is policy-aware)
- **Subagent depth guard** — subagents cannot spawn further agents

Install manually:

```bash
rampart init --profile openclaw
```

## Always Allow writeback

When you click "Always Allow" in the OpenClaw approval UI, Rampart writes a permanent smart-glob rule to `~/.rampart/policies/user-overrides.yaml` via `POST /v1/rules/learn`. The rule takes effect immediately without restarting serve.

For example, approving `sudo apt-get install nmap` always writes:
```yaml
- name: user-allow-<hash>
  match:
    tool: exec
  rules:
    - when:
        command_matches: ["sudo apt-get install *"]
      action: allow
```

## Verify the integration

```bash
rampart doctor
```

Expected output when fully configured:

```
✓ rampart serve: running (pid 12345)
✓ OpenClaw plugin: installed (before_tool_call hook active)
✓ Policy: openclaw.yaml loaded (N rules, default: ask)
✓ Approval store: persistent (N pending)
```

Or check plugin status directly:

```bash
openclaw plugins list
# rampart  v0.9.12  ✓ active
```

## Troubleshooting

**Plugin not loading after setup:**

```bash
openclaw plugins list   # check rampart is listed
rampart doctor          # shows plugin check status
```

If missing, re-run setup:

```bash
rampart setup openclaw --plugin --force
```

**OpenClaw version too old:**

```bash
npm install -g openclaw@latest
rampart setup openclaw   # auto-detects new version
```

**Checking what's being blocked:**

```bash
rampart log --deny   # recent denials
rampart log --ask    # recent approvals
```

## Legacy: shim + bridge (OpenClaw < 2026.3.28)

If you're on an older OpenClaw version, `rampart setup openclaw` falls back to:

1. Shell shim (exec interception via `SHELL` env override)
2. OpenClaw gateway bridge (WebSocket, exec-only coverage)
3. Dist patches for file tools (fragile, re-run after OpenClaw upgrades)

Upgrade OpenClaw to get the native plugin and avoid the upgrade fragility.

## Uninstall

```bash
rampart uninstall --yes
```

Removes the service, OpenClaw plugin, gateway drop-in, and restores any patched files. Policies and audit logs in `~/.rampart/` are preserved.
