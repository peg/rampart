---
title: Securing OpenClaw
description: "Native Rampart integration for OpenClaw — policy enforcement via before_tool_call hook, with explicit degraded-mode behavior per tool class."
---

# OpenClaw

Rampart integrates with OpenClaw via the native `before_tool_call` plugin API. This is the primary supported path. OpenClaw owns the visible approval UX, while Rampart owns policy evaluation, audit logging, and durable allow-always writeback.

Every tool call — exec, read, write, web_fetch, browser, message, and more — is evaluated against your policy before it runs.

For sensitive tools, the recommended operating assumption is simple: if Rampart policy service is unavailable, treat that as a broken state and fix it before trusting approval-path tests. By default the plugin blocks sensitive tools such as `exec` and `write` when `rampart serve` is unavailable; lower-risk tools (`read`, `web_fetch`, `web_search`, `image`) are explicitly configured fail-open and can be tightened with `plugins.entries.rampart.config.failOpenTools`.

!!! info "Version requirements"
    - **OpenClaw >= 2026.4.29**: Preferred RC baseline. Supports explicit plugin startup activation plus first-class plugin approvals on the shared `/approve` / native approval path.
    - **OpenClaw 2026.4.11 - 2026.4.28**: Recommended and supported for native Discord exec approvals plus native plugin interception.
    - **OpenClaw 2026.3.28 - 2026.4.10**: Native plugin works for tool enforcement, but Rampart's polished Discord exec approval path is supported on newer OpenClaw builds.
    - **OpenClaw < 2026.3.28**: Legacy shim + bridge — exec-only coverage, requires re-patching after upgrades.
    - **Verified on**: OpenClaw 2026.4.29

    `rampart setup openclaw` auto-detects your version and uses the right method.

## Setup

```bash
rampart setup openclaw
```

That's it. Rampart:

1. Detects your OpenClaw version
2. **If >= 2026.3.28**: Extracts the bundled plugin and installs it via `openclaw plugins install`; current plugins declare `activation.onStartup: true` so startup protection does not rely on deprecated implicit loading
3. Adds `rampart` to `plugins.allow` — existing plugins (discord, browser, etc.) are preserved
4. Configures OpenClaw to route decisions through Rampart (`tools.exec.ask: off`)
5. Copies the `openclaw.yaml` policy profile to `~/.rampart/policies/openclaw.yaml`
6. Starts `rampart serve` as a boot service (if not already running)

After setup, verify both services are healthy:

```bash
systemctl --user is-active openclaw-gateway.service
systemctl --user is-active rampart-serve.service
```

Both should return `active`.

No external downloads, no npm install — the plugin is bundled inside the `rampart` binary.

### Security scanner note

During install, OpenClaw may show: **"Plugin 'rampart' has 1 suspicious code pattern(s)"**. This is a false positive — Rampart reads a local token file (`~/.rampart/token`) and talks to `localhost:9090` only. No external network access. The warning does not block installation and can be safely ignored.

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
                 └─ ask    → OpenClaw owns the visible approval UI/state
                              Rampart writes audit, evaluates policy, and persists allow-always rules
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

!!! success "Enforcement verified"
    `before_tool_call` is properly awaited and blocking in OpenClaw 2026.3.28+. Deny decisions are enforced end-to-end, not just logged.

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

When you click "Always Allow" in the OpenClaw approval UI, Rampart writes a durable rule to `~/.rampart/policies/user-overrides.yaml` via `POST /v1/rules/learn`. The rule takes effect immediately without restarting serve.

For example, approving `sudo true` writes an exact rule, while broader commands may be generalized into a smart glob when appropriate.

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
✓ Approval path: native OpenClaw UI active
```

For end-to-end confidence, validate one case in each state:
- learned allow, for example `sudo true`
- fresh ask, for example `sudo id`
- hard deny, for example `rm -rf /tmp`

Or check plugin status directly:

```bash
openclaw plugins list
# rampart  v0.9.18  active
```

## Troubleshooting

**Plugin not loading after setup:**

```bash
openclaw plugins list         # check rampart is listed
rampart doctor                # shows plugin check status
openclaw doctor               # check for plugin warnings
```

If missing, re-run setup:

```bash
rampart setup openclaw
systemctl --user restart openclaw-gateway
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
