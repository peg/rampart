# Rampart + OpenClaw

Rampart protects current OpenClaw releases through the bundled native
`before_tool_call` plugin. The plugin sends supported tool calls to the local
Rampart policy service before OpenClaw executes them.

## Managed setup

```bash
rampart protect openclaw
rampart verify openclaw
```

The managed command installs the OpenClaw and Guard policy layers, installs and
enables the native plugin, starts `rampart serve`, configures the integration to
fail closed when that service is unavailable, restarts the gateway when safe,
and runs behavioral canaries. Existing unrelated OpenClaw settings and plugins
are preserved.

The plugin classifies the supported OpenClaw `before_tool_call` surface,
including command execution, file access and multi-path patches, network tools,
browser automation, messaging, process/device/gateway controls, the current
session and subagent tools, and image generation. Unknown plugin and MCP tool
names fail closed until Rampart has an explicit typed mapping for them.
Every decision that reaches Rampart is written to the audit trail.

Advanced and legacy setups can use:

```bash
rampart setup openclaw
```

The compatibility bridge for older OpenClaw releases runs as part of
`rampart serve`; there is no separate `rampart daemon` command.

See the maintained [OpenClaw integration guide](https://docs.rampart.sh/integrations/openclaw/)
for supported versions, exact coverage, migration, and release-validation steps.
