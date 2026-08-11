---
title: Securing Antigravity CLI and IDE
description: "Protect Antigravity tool calls with Rampart's shared native PreToolUse policy plugin."
---

# Antigravity CLI and IDE

Rampart installs one global plugin in `~/.gemini/config/plugins/rampart` for
both Antigravity surfaces. The CLI and IDE share the reviewed plugin contract,
installed-plugin check, and adapter canaries. No Antigravity project file or
Rampart policy authoring is required for the managed default path.

## Setup

```bash
rampart protect antigravity
```

For explicit setup and verification:

```bash
rampart setup antigravity
rampart verify antigravity
```

Restart active Antigravity CLI or IDE sessions after setup. Removal is scoped
to the structurally validated Rampart-owned plugin:

```bash
rampart setup antigravity --remove
```

## Enforcement behavior

Antigravity sends a proposed tool call to Rampart's `PreToolUse` handler before
execution. Rampart normalizes the documented shell, file, research, browser,
task, subagent, messaging, and permission tools into its policy classes.

| Rampart decision | Antigravity response |
| --- | --- |
| `allow`, `watch`, `log` | `allow`; execution continues |
| `deny` | `deny`; execution stops with the Rampart reason |
| `ask` | `force_ask`; Antigravity prompts even if a permission was cached as Always Allow |
| Unknown future tool | `deny` until Rampart maps its policy surface |

Local allow/deny evaluation does not require `rampart serve`. The service is
still useful for the dashboard and broader behavioral verification.

## Honest boundary

Antigravity's current `PostToolUse` event does not include the completed tool
call or its output. Rampart therefore installs only the meaningful pre-tool
gate and does not claim post-result secret scanning for this integration.

Rampart-handled input and policy errors return a structured denial in enforce
mode. An unexpected hook-process crash or host timeout follows Antigravity's
behavior; Rampart does not claim that those host-level failures are fail-closed.

The same global plugin path is documented for Antigravity CLI and IDE on
Linux, macOS, and Windows. Physical Windows host proof is still pending.

## Verification

`rampart verify antigravity` safely checks that the managed plugin is present,
then invokes the real adapter with a non-executing destructive-command payload
and requires both Antigravity's structured `deny` response and a
conversation-correlated Rampart audit record.

The public [security assurance manifest](../getting-started/security-assurance.md)
records the tested adapter boundary and remaining gaps.
