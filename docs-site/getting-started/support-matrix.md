---
title: Integration Support Matrix
description: "Supported Rampart integration modes, coverage, approval UX, serve requirements, and legacy compatibility notes."
---

# Integration Support Matrix

Use this page as the canonical support contract for Rampart's main integration surfaces.

Rampart is policy, approval, audit, and proof infrastructure for agents that need real system access. This matrix describes current support evidence, not future-feature commitments. Optional containment, fleet controls, and broader enterprise administration should not be inferred from these support tiers.

For release-candidate validation and latest-agent checks, use the [Release Compatibility Gate](release-compatibility-gate.md). The support tier below should match the most recent evidence from the exact Rampart candidate build and bundled plugin metadata.

## At a glance

<table class="support-matrix-table">
  <thead>
    <tr>
      <th>Surface</th>
      <th>Best path</th>
      <th><code>rampart serve</code></th>
      <th>Approval UX</th>
      <th>Support tier</th>
    </tr>
  </thead>
  <tbody>
    <tr class="tier-supported">
      <td data-label="Surface"><strong>Claude Code</strong></td>
      <td data-label="Best path">Native hooks<br><code>rampart setup claude-code</code></td>
      <td data-label="rampart serve">Not required for local enforcement;<br>yes for dashboard/headless approval flows</td>
      <td data-label="Approval UX">Claude native approval prompt</td>
      <td data-label="Support tier"><strong>Supported</strong><br>2.1.220 mapping review + isolated shell host proof</td>
    </tr>
    <tr class="tier-supported">
      <td data-label="Surface"><strong>Codex CLI, IDE, desktop</strong></td>
      <td data-label="Best path">Native lifecycle hooks<br><code>rampart setup codex</code></td>
      <td data-label="rampart serve">Not required for local allow/deny;<br>required for approval queue</td>
      <td data-label="Approval UX">External Rampart queue; unavailable approval service denies</td>
      <td data-label="Support tier"><strong>Supported</strong><br>opt-in host proof available</td>
    </tr>
    <tr class="tier-supported">
      <td data-label="Surface"><strong>Cline</strong></td>
      <td data-label="Best path">Native hooks<br><code>rampart setup cline</code></td>
      <td data-label="rampart serve">Not required for local enforcement</td>
      <td data-label="Approval UX">No native ask UI; approval-required actions cancel with context</td>
      <td data-label="Support tier"><strong>Supported</strong><br>adapter-tested; no current host proof</td>
    </tr>
    <tr class="tier-experimental">
      <td data-label="Surface"><strong>Gemini CLI (enterprise/API key)</strong></td>
      <td data-label="Best path">Native lifecycle hooks<br><code>rampart setup gemini</code></td>
      <td data-label="rampart serve">Not required for local allow/deny;<br>required for external approvals</td>
      <td data-label="Approval UX">External Rampart queue; unavailable approval service denies</td>
      <td data-label="Support tier"><strong>Experimental</strong><br>adapter-tested; authenticated host proof pending; not Antigravity</td>
    </tr>
    <tr class="tier-supported">
      <td data-label="Surface"><strong>GitHub Copilot CLI / VS Code</strong></td>
      <td data-label="Best path">Shared native lifecycle hooks<br><code>rampart setup copilot</code></td>
      <td data-label="rampart serve">Not required for local enforcement</td>
      <td data-label="Approval UX">Native Copilot prompt</td>
      <td data-label="Support tier"><strong>Supported</strong> for CLI adapter<br>VS Code hook host is upstream Preview</td>
    </tr>
    <tr class="tier-recommended">
      <td data-label="Surface"><strong>OpenClaw &gt;= 2026.5.2</strong></td>
      <td data-label="Best path">Native plugin<br><code>rampart setup openclaw</code></td>
      <td data-label="rampart serve">Required</td>
      <td data-label="Approval UX">First-class plugin approvals / native approval UI</td>
      <td data-label="Support tier"><strong>Verified</strong></td>
    </tr>
    <tr class="tier-supported">
      <td data-label="Surface"><strong>Hermes Agent</strong></td>
      <td data-label="Best path">Experimental user plugin<br><code>rampart setup hermes</code></td>
      <td data-label="rampart serve">Required</td>
      <td data-label="Approval UX"><code>ask</code> blocks until plugin approval/resume support exists</td>
      <td data-label="Support tier">Experimental<br>0.19.0 shell deny/allow host proof</td>
    </tr>
    <tr class="tier-supported">
      <td data-label="Surface"><strong>OpenClaw 2026.4.29 - 2026.5.1</strong></td>
      <td data-label="Best path">Native plugin<br><code>rampart setup openclaw</code></td>
      <td data-label="rampart serve">Required</td>
      <td data-label="Approval UX">Native plugin startup/interception; approval delivery was not the launch baseline</td>
      <td data-label="Support tier">Supported</td>
    </tr>
    <tr class="tier-supported">
      <td data-label="Surface"><strong>OpenClaw 2026.3.28 - 2026.4.28</strong></td>
      <td data-label="Best path">Native plugin<br><code>rampart setup openclaw</code></td>
      <td data-label="rampart serve">Required</td>
      <td data-label="Approval UX">Native enforcement; approval UX less polished than current builds</td>
      <td data-label="Support tier">Supported</td>
    </tr>
    <tr class="tier-legacy">
      <td data-label="Surface"><strong>OpenClaw &lt; 2026.3.28</strong></td>
      <td data-label="Best path">Legacy shim + bridge + patching</td>
      <td data-label="rampart serve">Required</td>
      <td data-label="Approval UX">Legacy bridge/shim behavior</td>
      <td data-label="Support tier">Legacy compatibility</td>
    </tr>
    <tr class="tier-supported">
      <td data-label="Surface"><strong>Cursor / Claude Desktop</strong></td>
      <td data-label="Best path">MCP proxy<br><code>rampart mcp --</code></td>
      <td data-label="rampart serve">Required</td>
      <td data-label="Approval UX">MCP error / proxy-mediated behavior</td>
      <td data-label="Support tier">Supported</td>
    </tr>
    <tr class="tier-supported">
      <td data-label="Surface"><strong>Custom / Python / CI</strong></td>
      <td data-label="Best path">HTTP API</td>
      <td data-label="rampart serve">Required</td>
      <td data-label="Approval UX">Caller-defined</td>
      <td data-label="Support tier">Supported</td>
    </tr>
  </tbody>
</table>

### Best default choices

- **Claude Code** → current documented hook-visible tools are mapped and, in
  enforce mode, unknown future pre-call tools deny; an isolated Claude Code
  2.1.220 shell deny/allow host run is recorded
- **Codex CLI, IDE, desktop** → native lifecycle hooks cover host-exposed shell, file, MCP, web, and delegated-agent calls
- **Gemini CLI (enterprise/API key)** → experimental native
  `BeforeTool`/`AfterTool` hooks cover documented shell, file, network, MCP,
  memory, and delegated-agent calls; a real authenticated host proof is still
  pending, and this does not cover Antigravity
- **GitHub Copilot CLI / VS Code** → one shared user hook covers both hosts;
  Copilot CLI also supports a separate administrator-owned machine policy hook,
  while VS Code hooks remain an upstream Preview surface
- **OpenClaw >= 2026.5.2** → best OpenClaw path; plugin + native approval UI
- **Hermes Agent** → experimental plugin path with a completed isolated
  Hermes 0.19.0 shell deny/allow host run; `ask` decisions block rather than resume
- **Cline** → supported adapter path on Linux/macOS, but without a rolling
  latest-Cline job or completed current-host proof; the installed hook scripts
  require Bash and native Windows behavior is not currently claimed

## Degraded behavior notes

- **Claude Code / Cline / Codex / GitHub Copilot native hooks**, plus the experimental Gemini CLI adapter: local allow/deny policy
  evaluation works when `rampart serve` is down. Rampart-handled parse and
  policy errors deny in enforce mode, but an unexpected hook crash or host
  timeout follows the host's behavior. Dashboard features and external
  approvals need the service; Codex approval-required actions deny when its
  queue is unavailable.
- **GitHub Copilot**: native `ask` does not require the Rampart service. Copilot
  CLI `PreToolUse` command errors deny, but CLI hook timeouts always fail open,
  even for administrator policy hooks. VS Code blocks exit code 2 but treats
  other hook errors as warnings; unexpected crashes are not claimed fail-closed.
- **OpenClaw native plugin**: depends on `rampart serve`; sensitive tools block when the service is unavailable, while configured lower-risk fail-open tools may still proceed.
- **Hermes Agent plugin**: depends on `rampart serve`; mutating/high-risk tools fail closed when unavailable, while explicitly configured read-only tools may fail open.
- **Legacy OpenClaw patching**: compatibility-only path; requires re-patching after upgrades.
- **Wrapper / preload / API paths**: behavior depends on integration settings and fail-open/fail-closed configuration.

The machine-readable source for current integration guarantees and evidence is
[`assurance/integrations.yaml`](https://github.com/peg/rampart/blob/main/assurance/integrations.yaml).
Coverage applies only to actions the host exposes through the named boundary.
It does not imply syscall, packet, or arbitrary subprocess inspection.

## Choosing the right path

- Use **native hooks** when the agent supports them.
- Use the **OpenClaw native plugin** on current OpenClaw builds.
- Use the **Hermes Agent plugin** for conservative early Hermes testing.
- Use **wrapper / preload** when the CLI agent has no hook system.
- Use **MCP proxy** or **HTTP API** for clients that integrate through MCP or custom service calls.

## Related guides

- [Quick Start](quickstart.md)
- [Release Compatibility Gate](release-compatibility-gate.md)
- [Security Assurance](security-assurance.md)
- [How Rampart Works](how-it-works.md)
- [OpenClaw integration](../integrations/openclaw.md)
- [Hermes Agent integration](../integrations/hermes.md)
- [Integration guides](../integrations/index.md)
