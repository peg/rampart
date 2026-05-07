---
title: Integration Support Matrix
description: "Supported Rampart integration modes, coverage, approval UX, serve requirements, and legacy compatibility notes."
---

# Integration Support Matrix

Use this page as the canonical support contract for Rampart's main integration surfaces.

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
    <tr class="tier-recommended">
      <td data-label="Surface"><strong>Claude Code</strong></td>
      <td data-label="Best path">Native hooks<br><code>rampart setup claude-code</code></td>
      <td data-label="rampart serve">Not required for local enforcement;<br>yes for dashboard/headless approval flows</td>
      <td data-label="Approval UX">Claude native approval prompt</td>
      <td data-label="Support tier"><strong>Recommended</strong></td>
    </tr>
    <tr class="tier-recommended">
      <td data-label="Surface"><strong>Codex CLI</strong></td>
      <td data-label="Best path">Preload + wrapper<br><code>rampart setup codex</code></td>
      <td data-label="rampart serve">Typically yes</td>
      <td data-label="Approval UX">Wrapper/preload approval semantics</td>
      <td data-label="Support tier"><strong>Recommended</strong></td>
    </tr>
    <tr class="tier-supported">
      <td data-label="Surface"><strong>Cline</strong></td>
      <td data-label="Best path">Native hooks<br><code>rampart setup cline</code></td>
      <td data-label="rampart serve">Not required for local enforcement</td>
      <td data-label="Approval UX">No native ask UI; approval-required actions cancel with context</td>
      <td data-label="Support tier">Supported</td>
    </tr>
    <tr class="tier-recommended">
      <td data-label="Surface"><strong>OpenClaw &gt;= 2026.5.2</strong></td>
      <td data-label="Best path">Native plugin<br><code>rampart setup openclaw</code></td>
      <td data-label="rampart serve">Required</td>
      <td data-label="Approval UX">First-class plugin approvals / native approval UI</td>
      <td data-label="Support tier"><strong>Recommended</strong></td>
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

- **Claude Code** → best overall native path
- **Codex CLI** → best CLI path when you want strong coverage
- **OpenClaw >= 2026.5.2** → best OpenClaw path for 1.0; plugin + native approval UI
- **Cline** → good supported path, but less polished approval UX than Claude Code

## Degraded behavior notes

- **Claude Code / Cline native hooks**: local policy evaluation still works when `rampart serve` is down, but dashboard features, approval APIs, and external approval state do not.
- **OpenClaw native plugin**: depends on `rampart serve`; sensitive tools block when the service is unavailable, while configured lower-risk fail-open tools may still proceed.
- **Legacy OpenClaw patching**: compatibility-only path; requires re-patching after upgrades.
- **Wrapper / preload / API paths**: behavior depends on integration settings and fail-open/fail-closed configuration.

## Choosing the right path

- Use **native hooks** when the agent supports them.
- Use the **OpenClaw native plugin** on current OpenClaw builds.
- Use **wrapper / preload** when the CLI agent has no hook system.
- Use **MCP proxy** or **HTTP API** for clients that integrate through MCP or custom service calls.

## Related guides

- [Quick Start](quickstart.md)
- [How Rampart Works](how-it-works.md)
- [OpenClaw integration](../integrations/openclaw.md)
- [Integration guides](../integrations/index.md)
