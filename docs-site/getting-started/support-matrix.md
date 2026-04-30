---
title: Integration Support Matrix
description: "Supported Rampart integration modes, coverage, approval UX, serve requirements, and legacy compatibility notes."
---

# Integration Support Matrix

Use this page as the canonical support contract for Rampart's main integration surfaces.

## At a glance

<div class="support-grid">
  <section class="support-card support-card--recommended">
    <h3>Claude Code</h3>
    <ul>
      <li><strong>Integration:</strong> Native hooks (<code>rampart setup claude-code</code>)</li>
      <li><strong><code>rampart serve</code>:</strong> Not required for local hook enforcement; yes for dashboard/headless approval flows</li>
      <li><strong>Approval UX:</strong> Claude native approval prompt</li>
      <li><strong>Coverage:</strong> Direct tool calls protected through <code>PreToolUse</code>; local policy evaluation works without serve</li>
      <li><strong>Support tier:</strong> Recommended</li>
    </ul>
  </section>

  <section class="support-card support-card--recommended">
    <h3>Codex CLI</h3>
    <ul>
      <li><strong>Integration:</strong> Wrapper + preload (<code>rampart setup codex</code>)</li>
      <li><strong><code>rampart serve</code>:</strong> Typically yes for the service-backed evaluation path</li>
      <li><strong>Approval UX:</strong> Wrapper/preload approval semantics</li>
      <li><strong>Coverage:</strong> Strong CLI coverage; depends on preload/wrapper path</li>
      <li><strong>Support tier:</strong> Recommended</li>
    </ul>
  </section>

  <section class="support-card support-card--supported">
    <h3>Cline</h3>
    <ul>
      <li><strong>Integration:</strong> Native hooks (<code>rampart setup cline</code>)</li>
      <li><strong><code>rampart serve</code>:</strong> Not required for local hook enforcement</li>
      <li><strong>Approval UX:</strong> No native ask UI; approval-required actions cancel with context</li>
      <li><strong>Coverage:</strong> Native hook coverage for supported tool lifecycle events</li>
      <li><strong>Support tier:</strong> Supported</li>
    </ul>
  </section>

  <section class="support-card support-card--recommended">
    <h3>OpenClaw &gt;= 2026.4.11</h3>
    <ul>
      <li><strong>Integration:</strong> Native plugin (<code>rampart setup openclaw</code>)</li>
      <li><strong><code>rampart serve</code>:</strong> Required</li>
      <li><strong>Approval UX:</strong> OpenClaw native approval UI</li>
      <li><strong>Coverage:</strong> Full plugin-based tool interception plus current native exec approval behavior</li>
      <li><strong>Support tier:</strong> Recommended</li>
    </ul>
  </section>

  <section class="support-card support-card--supported">
    <h3>OpenClaw 2026.3.28 - 2026.4.10</h3>
    <ul>
      <li><strong>Integration:</strong> Native plugin (<code>rampart setup openclaw</code>)</li>
      <li><strong><code>rampart serve</code>:</strong> Required</li>
      <li><strong>Approval UX:</strong> Native tool enforcement; approval UX is less polished than current builds</li>
      <li><strong>Coverage:</strong> Full plugin-based tool interception on supported builds</li>
      <li><strong>Support tier:</strong> Supported</li>
    </ul>
  </section>

  <section class="support-card support-card--legacy">
    <h3>OpenClaw &lt; 2026.3.28</h3>
    <ul>
      <li><strong>Integration:</strong> Legacy shim + bridge + optional patching</li>
      <li><strong><code>rampart serve</code>:</strong> Required</li>
      <li><strong>Approval UX:</strong> Legacy bridge/shim approval behavior</li>
      <li><strong>Coverage:</strong> Compatibility path only; more fragile and upgrade-sensitive</li>
      <li><strong>Support tier:</strong> Legacy compatibility</li>
    </ul>
  </section>

  <section class="support-card support-card--supported">
    <h3>Cursor / Claude Desktop</h3>
    <ul>
      <li><strong>Integration:</strong> MCP proxy (<code>rampart mcp --</code>)</li>
      <li><strong><code>rampart serve</code>:</strong> Required</li>
      <li><strong>Approval UX:</strong> MCP error / proxy-mediated behavior</li>
      <li><strong>Coverage:</strong> MCP tool coverage only</li>
      <li><strong>Support tier:</strong> Supported</li>
    </ul>
  </section>

  <section class="support-card support-card--supported">
    <h3>Custom / Python / CI</h3>
    <ul>
      <li><strong>Integration:</strong> HTTP API</li>
      <li><strong><code>rampart serve</code>:</strong> Required</li>
      <li><strong>Approval UX:</strong> Caller-defined</li>
      <li><strong>Coverage:</strong> Whatever the caller routes through Rampart</li>
      <li><strong>Support tier:</strong> Supported</li>
    </ul>
  </section>
</div>

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
