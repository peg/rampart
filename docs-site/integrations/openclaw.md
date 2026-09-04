---
title: Securing OpenClaw
description: "Protect OpenClaw in one command with Rampart-managed policy, fail-closed enforcement, and active behavioral verification."
---

# OpenClaw

Rampart integrates with OpenClaw via the native `before_tool_call` plugin API. This is the primary supported path. OpenClaw owns the visible approval UX, while Rampart owns policy evaluation, audit logging, and complete redacted action review.

When `rampart serve` is healthy, every supported tool call — exec, read, write, web_fetch, browser, message, and more — is evaluated against your policy before it runs.

The recommended managed path is fail closed: if the Rampart policy service is unavailable, OpenClaw tools stop instead of silently bypassing policy. Advanced manual setups can configure per-tool degraded behavior, but that is not the zero-configuration default.

!!! info "Version requirements"
    - **OpenClaw >= 2026.5.2**: Recommended current path. Supports explicit plugin startup activation plus first-class plugin approvals on the shared `/approve` / native approval path.
    - **OpenClaw 2026.4.29 - 2026.5.1**: Supported for native plugin startup/interception; plugin approval delivery was not the launch baseline.
    - **OpenClaw 2026.3.28 - 2026.4.28**: Native plugin works for tool enforcement, but Rampart's polished approval path is supported on newer OpenClaw builds.
    - **OpenClaw < 2026.3.28**: Legacy shim + bridge — exec-only coverage, requires re-patching after upgrades.
    - Published support claims are tied to the evidence in Rampart's [integration assurance manifest](https://github.com/peg/rampart/blob/main/assurance/integrations.yaml).

    `rampart protect openclaw` uses the native plugin on current supported OpenClaw versions. `rampart setup openclaw` remains available for advanced and legacy configurations.

## Setup

```bash
rampart protect openclaw
```

That's it. Rampart:

1. Installs managed Guard and OpenClaw policy layers
2. Extracts and enables the bundled native `before_tool_call` plugin
3. Preserves existing unrelated plugins and OpenClaw settings
4. Starts `rampart serve` as a boot service, with a background fallback for headless environments
5. Configures every OpenClaw tool to fail closed if the local policy service is unavailable
6. Restarts the gateway and runs safe behavioral canaries through the live plugin path

On OpenClaw versions that require capability consent for external plugins,
this explicit protect command accepts the exact capability surface OpenClaw
reports for Rampart's bundled plugin. That surface includes the
`before_tool_call` hook used for enforcement. Rampart does not accept
capabilities for any other plugin. Setup, forced reinstall, and `doctor --fix`
also use OpenClaw's consent-aware enable command, so a previously disabled
plugin is not mistaken for a repaired active boundary.

Current OpenClaw versions use `tools.exec.mode` as the canonical exec-policy
setting. Rampart preserves a valid operator-selected mode because OpenClaw's
exec policy remains an additional gate after the Rampart hook; stricter modes
can add an OpenClaw-owned approval or block but cannot bypass Rampart. During
an upgrade, Rampart removes retired `tools.exec.ask` and `tools.exec.security`
siblings only when they are semantically equivalent to `mode`; conflicting or
malformed mixed policies require explicit operator resolution rather than an
automatic weakening. Older supported OpenClaw versions continue to use Rampart's
ownership-tracked `tools.exec.ask = "off"` setting.

After setup, verify both services are healthy:

```bash
systemctl --user is-active openclaw-gateway.service
systemctl --user is-active rampart-serve.service
```

Both should return `active`.

No external downloads, no npm install — the plugin is bundled inside the `rampart` binary.

To use a different local port, start that service first and make the endpoint
explicit:

```bash
rampart serve --addr 127.0.0.1 --port 19090 --background
rampart protect openclaw --serve-url http://127.0.0.1:19090
```

The explicit URL is authoritative for startup checks, plugin configuration,
and verification. The managed OpenClaw path accepts only loopback HTTP(S) URLs
without embedded credentials, paths, queries, or fragments. Rampart will not
silently fall back to port 9090 when an explicit non-default endpoint is
unreachable.

For advanced setups that manage their own policies or require the legacy compatibility path, use `rampart setup openclaw` and configure degraded behavior explicitly.

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
                              Rampart writes audit, evaluates policy, and supplies complete action review
```

## Coverage

With the native plugin, **supported OpenClaw tool calls are intercepted**. Policy depth and degraded behavior still depend on tool class and configuration:

| Tool | Coverage | Notes |
|------|----------|-------|
| `exec` | ✅ Native plugin | All commands evaluated |
| `read` | ✅ Native plugin | Path-based policy matching |
| `write` / `edit` | ✅ Native plugin | Path-based policy matching |
| `apply_patch` | ✅ Native plugin | Maps to `edit`; every represented path is evaluated and deny/ask wins for the batch |
| `grep` / `find` / `ls` | ✅ Native plugin | Maps to the same path-aware `read` policy surface |
| `web_fetch` | ✅ Native plugin | Domain allowlist/blocklist |
| `web_search` | ✅ Native plugin | Always allowed by default |
| `browser` | ✅ Native plugin | Read-only inspection is allowed; navigation uses domain rules; clicks, typing, uploads, and other mutations require approval |
| `message` | ✅ Native plugin | Read actions always allowed; sends to unknown channels require approval |
| `ask_user` | ✅ Native plugin | Structured questions to the originating user are classified as local interaction, not cross-conversation messaging |
| `canvas` | ✅ Native plugin | Always allowed (UI only) |
| `sessions_spawn` | ✅ Native plugin | Subagents cannot spawn further agents |
| `process` / `nodes` / `gateway` / `subagents` | ✅ Native plugin | Known read-only status operations are allowed; mutations require approval |
| `sessions_list` / `sessions_history` / `sessions_send` / `session_status` | ✅ Native plugin | Session metadata/history and cross-session actions are classified explicitly; sensitive or mutating calls require approval |
| `cron` | ✅ Native plugin | Scheduling and job inspection require approval |
| `image_generate` | ✅ Native plugin | Maps to the approval-gated image policy surface |

Unknown OpenClaw, plugin, and MCP tool names are blocked locally before they
can reach the service's permissive generic fallback. New capabilities require
an explicit typed mapping and tests before Rampart allows them.

Other OpenClaw plugins that rewrite tool parameters share the trusted host
boundary. Current OpenClaw hook composition does not give Rampart an
authoritative post-composition view of the final parameters, so do not combine
Rampart with an untrusted parameter-mutating plugin.

Current OpenClaw `before_tool_call` context does not expose the host working
directory. Rampart evaluates each file path and `apply_patch` derived path as
OpenClaw supplies it. Prefer absolute paths or recursive policy patterns such
as `**/.ssh/**` when a rule must also cover relative host paths.

OpenClaw's current `after_tool_call` hook is observational rather than a
blocking result-rewrite boundary. Rampart therefore does not claim that this
plugin can redact a completed tool response before the model receives it.

!!! note "Sub-agents"
    The `before_tool_call` hook fires for tool calls from subagents too. The `openclaw.yaml` profile recognizes current `agent:*:subagent:*` and `agent:*:acp:*` session keys plus their legacy forms to apply stricter rules to child sessions.

!!! success "Enforcement verified"
    `before_tool_call` is properly awaited and blocking in OpenClaw 2026.3.28+. Deny decisions are enforced end-to-end, not just logged.

## The `openclaw.yaml` profile

The default profile installed by `rampart protect openclaw` (and by advanced
manual setup). Key behaviors:

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

## Complete action approval

The native plugin offers `allow-once` and `deny`. It shows the complete
represented arguments, targets and available host context with secrets redacted.
The approval belongs to OpenClaw; Rampart creates no second pending queue.
Timeouts deny the call.

The policy input retains adapter-derived facts used by the Guard rules. Its
`rampart_original_input` field preserves the original tool arguments for review
and action identity, including any caller-supplied names that overlap the
adapter's reserved fields. Those names cannot replace derived policy facts or
host context. Native approval displays this original payload after redaction.

OpenClaw's native hook description is limited to 512 characters and does not
forward a complete-review attachment. If the complete rendered action exceeds
that limit, Rampart blocks it before creating an approval. Split it into smaller
independently reviewable actions or configure an explicit operator-reviewed
policy. An older Rampart service without the complete review response also
blocks asks until upgraded.

Native plugin approvals no longer offer permanent command/path writeback: such
a rule would omit other reviewed parameters, requester and execution context.
Use an explicit policy when you want a persistent allowance. Existing
operator-authored policies are retained.

Other plugins that return parameter rewrites are part of the trusted OpenClaw
configuration. Although the first approval freezes selected parameters, Rampart
receives the original event rather than preceding hooks' returned rewrites.
Its resolution callback cannot inspect or veto the resumed action.

## Verify the integration

```bash
rampart verify openclaw
```

The verification command checks managed configuration and policy canaries,
then calls `rampart.verify` on the running gateway. That plugin method feeds
fixed, non-executing canaries through the same normalization and decision
mapping as `before_tool_call`. It proves the current plugin is loaded and can
reach Rampart; it does not invoke the agent's tool dispatcher or exercise a
native approval's resume path. An authenticated agent turn is separate
evidence and is not run by this command.

Use `rampart doctor` for the broader installation health report. Expected output when fully configured includes:

```
✓ rampart serve: running (pid 12345)
✓ OpenClaw plugin: installed (before_tool_call hook active)
✓ Policy: openclaw.yaml loaded (N rules, default: ask)
✓ Approval path: native OpenClaw UI active
```

See the [support matrix](../getting-started/support-matrix.md#degraded-behavior-notes)
for service failure defaults and the limits of each verification level.

Or check plugin status directly:

```bash
openclaw plugins list
# The rampart plugin should be active. Its component version can differ from
# the Rampart CLI patch version when the embedded plugin did not change.
```

## Troubleshooting

**Plugin not loading after setup:**

```bash
openclaw plugins list         # check rampart is listed
rampart doctor                # shows plugin check status
openclaw doctor               # check for plugin warnings
```

If missing, reinstall the managed guard:

```bash
rampart protect openclaw --reinstall
```

**OpenClaw version too old:**

```bash
npm install -g openclaw@latest
rampart protect openclaw   # installs, restarts, and verifies the managed guard
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
