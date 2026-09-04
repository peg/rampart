---
title: Integration Support Matrix
description: "Supported Rampart integration modes, coverage, approval UX, serve requirements, and legacy compatibility notes."
---

# Integration Support Matrix

Use this page as the canonical support contract for Rampart's main integration surfaces.

Rampart is policy, approval, audit, and proof infrastructure for agents that need real system access. This matrix describes current support evidence, not future-feature commitments. Optional containment, fleet controls, and broader enterprise administration should not be inferred from these support tiers.

Support tiers are tied to Rampart's public
[integration assurance manifest](https://github.com/peg/rampart/blob/main/assurance/integrations.yaml)
and portable evidence from the exact candidate build.

## Verify configured boundaries safely

```bash
rampart verify --all
```

This runs the policy canaries plus every configured integration on the current
platform that has an active behavioral verifier. It does not invoke a model or
execute the represented actions. A target is not promoted merely because its
configuration exists: OpenClaw's live plugin can earn `host_verified`, while
ordinary native-hook checks earn `adapter_verified`.

These labels describe different probes. Native-hook verification inspects
installed settings and invokes Rampart's adapter directly. OpenClaw verification
calls `rampart.verify` on the running gateway plugin, which exercises the same
policy mapping used by its pre-tool hook. Neither probe runs an authenticated
agent turn or demonstrates a tool's execution or approval resume through the
host dispatcher. Package startup and rolling compatibility tests are separate
evidence, not a promotion of adapter checks to host ingestion.

Static-only integrations are excluded from the aggregate rather than reported
as passing. In particular, use `rampart doctor` for Hermes installation status
and the isolated latest-Hermes compatibility check for runtime evidence.

## At a glance

<table class="support-matrix-table">
  <thead>
    <tr>
      <th>Surface</th>
      <th>Best path</th>
      <th>Bare protect</th>
      <th><code>rampart serve</code></th>
      <th>Approval UX</th>
      <th>Support tier</th>
    </tr>
  </thead>
  <tbody>
    <tr class="tier-supported" data-integration="claude-code">
      <td data-label="Surface"><strong>Claude Code</strong></td>
      <td data-label="Best path">Native hooks<br><code>rampart setup claude-code</code></td>
      <td data-label="Bare protect">Yes</td>
      <td data-label="rampart serve">Not required for local enforcement;<br>yes for dashboard/headless approval flows</td>
      <td data-label="Approval UX">Claude native approval prompt</td>
      <td data-label="Support tier"><strong>Supported</strong><br>installed-hook and adapter verification</td>
    </tr>
    <tr class="tier-supported" data-integration="codex">
      <td data-label="Surface"><strong>Codex CLI, IDE, desktop</strong></td>
      <td data-label="Best path">Native lifecycle hooks<br><code>rampart setup codex</code></td>
      <td data-label="Bare protect">Yes</td>
      <td data-label="rampart serve">Not required for local allow/deny;<br>required for approval queue</td>
      <td data-label="Approval UX">External Rampart queue; unavailable approval service denies</td>
      <td data-label="Support tier"><strong>Supported</strong><br>installed-hook and adapter verification</td>
    </tr>
    <tr class="tier-supported" data-integration="cline">
      <td data-label="Surface"><strong>Cline</strong></td>
      <td data-label="Best path">Native hooks<br><code>rampart setup cline</code></td>
      <td data-label="Bare protect">Yes</td>
      <td data-label="rampart serve">Not required for local enforcement</td>
      <td data-label="Approval UX">No native ask UI; approval-required actions cancel with context</td>
      <td data-label="Support tier"><strong>Supported</strong><br>current editor/CLI source contract + adapter/setup tests; no current host proof</td>
    </tr>
    <tr class="tier-experimental" data-integration="gemini">
      <td data-label="Surface"><strong>Gemini CLI (enterprise/API key)</strong></td>
      <td data-label="Best path">Native lifecycle hooks<br><code>rampart setup gemini</code></td>
      <td data-label="Bare protect">No</td>
      <td data-label="rampart serve">Not required for local allow/deny;<br>required for external approvals</td>
      <td data-label="Approval UX">External Rampart queue; unavailable approval service denies</td>
      <td data-label="Support tier"><strong>Experimental</strong><br>adapter-tested; authenticated host proof pending; not Antigravity</td>
    </tr>
    <tr class="tier-supported" data-integration="antigravity">
      <td data-label="Surface"><strong>Antigravity CLI / IDE</strong></td>
      <td data-label="Best path">Shared policy plugin<br><code>rampart setup antigravity</code></td>
      <td data-label="Bare protect">Yes</td>
      <td data-label="rampart serve">Not required for local enforcement</td>
      <td data-label="Approval UX">Native <code>force_ask</code> prompt</td>
      <td data-label="Support tier"><strong>Supported</strong><br>installed-plugin and adapter verification</td>
    </tr>
    <tr class="tier-supported" data-integration="copilot">
      <td data-label="Surface"><strong>GitHub Copilot CLI / VS Code</strong></td>
      <td data-label="Best path">Shared native lifecycle hooks<br><code>rampart setup copilot</code></td>
      <td data-label="Bare protect">Yes</td>
      <td data-label="rampart serve">Not required for local enforcement</td>
      <td data-label="Approval UX">Native Copilot prompt</td>
      <td data-label="Support tier"><strong>Supported</strong> CLI adapter<br>package startup + adapter evidence; authenticated hook ingestion pending; VS Code is contract-tested Preview</td>
    </tr>
    <tr class="tier-recommended" data-integration="openclaw">
      <td data-label="Surface"><strong>OpenClaw &gt;= 2026.5.2</strong></td>
      <td data-label="Best path">Managed native guard<br><code>rampart protect openclaw</code></td>
      <td data-label="Bare protect">Yes</td>
      <td data-label="rampart serve">Required</td>
      <td data-label="Approval UX">First-class plugin approvals / native approval UI</td>
      <td data-label="Support tier"><strong>Verified</strong></td>
    </tr>
    <tr class="tier-experimental" data-integration="hermes">
      <td data-label="Surface"><strong>Hermes Agent</strong></td>
      <td data-label="Best path">Experimental user plugin<br><code>rampart setup hermes</code></td>
      <td data-label="Bare protect">No</td>
      <td data-label="rampart serve">Required</td>
      <td data-label="Approval UX">Compatible Hermes native approval; older or incomplete installs block <code>ask</code></td>
      <td data-label="Support tier"><strong>Experimental</strong><br>credential-free package/runtime gate; authenticated live-host proof pending</td>
    </tr>
    <tr class="tier-supported">
      <td data-label="Surface"><strong>OpenClaw 2026.4.29 - 2026.5.1</strong></td>
      <td data-label="Best path">Native plugin<br><code>rampart setup openclaw</code></td>
      <td data-label="Bare protect">Yes</td>
      <td data-label="rampart serve">Required</td>
      <td data-label="Approval UX">Native plugin startup/interception; approval delivery was not the launch baseline</td>
      <td data-label="Support tier">Supported</td>
    </tr>
    <tr class="tier-supported">
      <td data-label="Surface"><strong>OpenClaw 2026.3.28 - 2026.4.28</strong></td>
      <td data-label="Best path">Native plugin<br><code>rampart setup openclaw</code></td>
      <td data-label="Bare protect">Yes</td>
      <td data-label="rampart serve">Required</td>
      <td data-label="Approval UX">Native enforcement; approval UX less polished than current builds</td>
      <td data-label="Support tier">Supported</td>
    </tr>
    <tr class="tier-legacy">
      <td data-label="Surface"><strong>OpenClaw &lt; 2026.3.28</strong></td>
      <td data-label="Best path">Legacy shim + bridge + patching</td>
      <td data-label="Bare protect">Yes</td>
      <td data-label="rampart serve">Required</td>
      <td data-label="Approval UX">Legacy bridge/shim behavior</td>
      <td data-label="Support tier">Legacy compatibility</td>
    </tr>
    <tr class="tier-supported" data-integration="cursor">
      <td data-label="Surface"><strong>Cursor local Agent / Cmd+K</strong></td>
      <td data-label="Best path">Native hook<br><code>rampart setup cursor</code></td>
      <td data-label="Bare protect">Yes</td>
      <td data-label="rampart serve">Required</td>
      <td data-label="Approval UX">External Rampart queue; Cloud and Tab are separate</td>
      <td data-label="Support tier">Supported</td>
    </tr>
    <tr class="tier-supported">
      <td data-label="Surface"><strong>Claude Desktop / Cursor MCP server</strong></td>
      <td data-label="Best path">MCP proxy<br><code>rampart mcp --</code></td>
      <td data-label="Bare protect">No</td>
      <td data-label="rampart serve">No</td>
      <td data-label="Approval UX">Fails closed when no resolver is available</td>
      <td data-label="Support tier">Supported</td>
    </tr>
    <tr class="tier-supported">
      <td data-label="Surface"><strong>Custom / Python / CI</strong></td>
      <td data-label="Best path">HTTP API</td>
      <td data-label="Bare protect">No</td>
      <td data-label="rampart serve">Required</td>
      <td data-label="Approval UX">Caller-defined</td>
      <td data-label="Support tier">Supported</td>
    </tr>
  </tbody>
</table>

### Best default choices

- **Claude Code** → current documented hook-visible tools are mapped and, in
  enforce mode, unknown future pre-call tools deny; installed configuration and
  adapter behavior have safe verification
- **Codex CLI, IDE, desktop** → native lifecycle hooks cover host-exposed shell, file, MCP, web, and delegated-agent calls
- **Antigravity CLI / IDE** → one shared native plugin gates documented tool
  calls before execution and uses `force_ask` for approvals. Both hosts share
  the reviewed plugin contract and adapter. Current `PostToolUse` does
  not expose results, so response scanning is not claimed
- **GitHub Copilot CLI / VS Code** → one shared user hook covers both hosts;
  latest-package startup and the adapter are tested separately, but authenticated
  hook ingestion is still pending. Copilot CLI also supports a separate
  administrator-owned machine policy hook, while VS Code hooks remain an
  upstream Preview surface covered by contract and adapter tests
- **Cursor local Agent / Cmd+K** → the managed user `preToolUse` hook is
  fail-closed and leaves Cursor's own permission system intact on allow.
  Cloud Agents and Tab use separate configuration and hook surfaces; current
  verification proves configuration and adapter behavior, not host ingestion
- **OpenClaw >= 2026.5.2** → `rampart protect openclaw` installs and verifies
  the managed native guard with fail-closed service behavior and native approval
  UI. An explicit `--serve-url` is used consistently for startup, plugin
  configuration, and verification; it must be loopback, and a non-default
  endpoint must already be reachable
- **Cline** → current editor and CLI payloads plus POSIX and Windows discovery
  artifacts are covered by adapter/setup tests; physical Windows and rolling
  latest-Cline host proof remain pending. Legacy CLI `--yolo` disables hooks,
  and the currently advertised custom `--hooks-dir` override is not consumed
  reliably by upstream file-hook discovery

### Experimental paths

- **Gemini CLI (enterprise/API key)** → experimental native
  `BeforeTool`/`AfterTool` hooks cover documented shell, file, network, MCP,
  memory, and delegated-agent calls; a real authenticated host proof is still
  pending, and this does not cover Antigravity
- **Hermes Agent** → experimental plugin path with isolated latest-runtime
  discovery, dispatch, deny/allow, native approval/resume, and degraded-mode
  checks. Older Hermes releases block `ask` with upgrade guidance. Its built-in
  status check remains static, so it is not included in `rampart verify --all`,
  and authenticated live-host proof remains pending

## Degraded behavior notes

In enforce mode, Rampart returns a denial for malformed tool input, invalid
policy, and other handled decision failures. A host that never starts the hook,
cancels it, or ignores its response owns the resulting behavior. The table
describes the managed integration; monitor mode and explicit fail-open settings
weaken enforcement. A host continuing its permission flow does not mean it will
necessarily execute the tool.

| Integration | `rampart serve` unavailable | Host hook failure or timeout |
| --- | --- | --- |
| [Claude Code](../integrations/claude-code.md) | Local policy and native `ask` remain available. | Command-hook timeout or launch failure supplies no veto; normal Claude permissions apply. A valid denial or blocking exit still blocks. [Upstream contract](https://code.claude.com/docs/en/hooks#timeouts) |
| [Cline](../integrations/cline.md) | Local policy remains available; `ask` cancels with context. | Current CLI continues after pre-hook launch, timeout, or control-parse errors. Post-tool file hooks are observational. |
| [Codex](../integrations/codex-cli.md) | Local allow/deny remains available; external approvals deny when unavailable. | Host-controlled; unexpected crash and timeout behavior is not claimed fail-closed. |
| [Gemini CLI](../integrations/gemini-cli.md) (experimental) | Local allow/deny remains available; external approvals deny when unavailable. | Host-controlled; unexpected crash and timeout behavior is not claimed fail-closed. |
| [Antigravity](../integrations/antigravity.md) | Local policy and native `force_ask` remain available. | Host-controlled; unexpected crash and timeout behavior is not claimed fail-closed. |
| [GitHub Copilot](../integrations/github-copilot.md) | Local policy and native `ask` remain available. | CLI command errors deny, but CLI timeouts continue, including policy hooks. VS Code blocks exit 2 and treats other errors as warnings. |
| [Cursor local Agent](../integrations/cursor.md) | Local allow/deny remains available; external approvals deny when unavailable. | Managed `failClosed: true` requests blocking on crash, timeout, or invalid JSON. Installed configuration and adapter checks do not prove host ingestion. [Upstream contract](https://cursor.com/docs/hooks#per-script-configuration-options) |
| [OpenClaw native plugin](../integrations/openclaw.md) | All tools deny by default, including routine tools. | Rampart catches adapter exceptions and denies on its service request deadline. Failure outside that handler remains host-controlled. |
| [Hermes Agent](../integrations/hermes.md) (experimental) | All tools deny by default. | Rampart catches adapter exceptions and service timeouts; Hermes skips a callback that escapes with an exception. |

OpenClaw and Hermes operators can explicitly opt tools into degraded fail-open
behavior; `rampart protect openclaw` installs an empty opt-out list. OpenClaw's
[native approval limits](../integrations/openclaw.md)
and trusted-plugin composition boundary also apply.

Disabled or undiscovered hooks provide no interception. See each integration's
activation requirements, including Cline's legacy `--yolo` bypass. Legacy
OpenClaw patching requires re-patching after upgrades. Wrapper, preload, and
custom API paths depend on their own configuration and caller behavior.

The machine-readable source for current integration guarantees and evidence is
[`assurance/integrations.yaml`](https://github.com/peg/rampart/blob/main/assurance/integrations.yaml).
Coverage applies only to actions the host exposes through the named boundary.
It does not imply syscall, packet, or arbitrary subprocess inspection.

## Choosing the right path

- Use **native hooks** when the agent supports them.
- Use the **Antigravity shared policy plugin** for Antigravity CLI and IDE.
- Use the **OpenClaw native plugin** on current OpenClaw builds.
- Use the **Hermes Agent plugin** for conservative early Hermes testing.
- Use **wrapper / preload** when the CLI agent has no hook system.
- Use **MCP proxy** or **HTTP API** for clients that integrate through MCP or custom service calls.

## Related guides

- [Quick Start](quickstart.md)
- [Security Assurance](security-assurance.md)
- [How Rampart Works](how-it-works.md)
- [OpenClaw integration](../integrations/openclaw.md)
- [Hermes Agent integration](../integrations/hermes.md)
- [Integration guides](../integrations/index.md)
