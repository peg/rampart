---
title: Securing OpenCode
description: "Experimental Rampart policy enforcement for supported OpenCode V1 tool calls on Linux and macOS, including local-model limitations."
---

# OpenCode

Rampart's **experimental OpenCode plugin** checks supported model-dispatched
tool calls before execution. It evaluates local Rampart policy without
requiring `rampart serve`, preserves the host's session and call identity, and
refuses unsupported or approval-required calls.

The initial contract targets OpenCode's V1 dispatcher on Linux and macOS with
a supported POSIX shell. The [support matrix](../getting-started/support-matrix.md)
records adapter and setup evidence; this integration has no active
installed-host verifier.

## Setup

```bash
rampart setup opencode
```

Restart OpenCode after setup. The installer writes only the managed
`plugins/rampart.js` file under `$OPENCODE_CONFIG_DIR`, or
`$XDG_CONFIG_HOME/opencode` when that variable is an absolute path; the default
is `~/.config/opencode`. It preserves unrelated plugins, OpenCode configuration,
and model-provider settings, and refuses to replace an unowned same-name file
or a linked plugin file or directory.

OpenCode [discovers global plugins at startup](https://opencode.ai/docs/plugins/#from-local-files).
Successful setup means the file was installed; it does not prove the host
loaded it. Bare `rampart protect` does not enroll this experimental integration.

After upgrading Rampart, rerun setup and restart OpenCode to update the managed
plugin and the bound Rampart executable. Repeating setup repairs owned file
drift without replacing unrelated settings.

## Supported tool calls

| OpenCode tool | Rampart policy surface | Boundary |
| --- | --- | --- |
| `bash` | `exec` | Original command and working directory; supported POSIX shells only. |
| `read` | `read` | Requested file or directory. |
| `write`, `edit`, `apply_patch` | `write` | Every represented patch target, including moves; the most restrictive decision wins. |
| `webfetch` | `fetch` | Requested URL; no arbitrary network or subprocess inspection. |
| `question`, `plan_exit` | `interact` | Host interaction. |
| `todowrite` | `process` | Host todo state. |

Unmapped tool names, including additional custom and MCP tools, plus `glob`,
`grep`, `task`, `skill`, code-mode `execute`, `lsp`, and `websearch` refuse
execution. Directory search tools remain unavailable until every inspected
file can be evaluated. Delegated agents and MCP execution are also unavailable
through this integration's initial contract.

OpenCode calls its shell tool `bash` even when another shell is selected.
Rampart permits the supported `sh`, `bash`, `zsh`, `dash`, and `ksh` names and
refuses other selections. Windows, PowerShell, and cmd are outside this
integration's platform contract.

## Decisions and failures

| Result | Behavior after the managed callback loads |
| --- | --- |
| Allow | OpenCode continues with the same evaluated arguments; its native permissions still apply. |
| Deny, `ask`, or `require_approval` | Execution is refused. No Rampart approval queue is created. |
| Invalid policy or input, unavailable child, nonzero exit, malformed reply, or deadline | Execution is refused. |

The dependency-free JavaScript bridge starts the installed Rampart executable
directly, without a shell, and bounds evaluation to ten seconds. It sends only
plain JSON arguments, checks they did not change during evaluation, and freezes
the allowed original argument tree before later plugins run. Other plugins
that need to mutate those arguments may fail. Arbitrary plugin composition and
custom tools that replace built-in names remain part of the trusted host
boundary.

Starting `rampart serve` does not add OpenCode approval or resume support. The
managed plugin enforces local policy; it does not implement response scanning
or execution-outcome reporting.

!!! warning "Host-controlled startup"
    OpenCode can continue after plugin load or initialization failure, and
    `OPENCODE_PURE` skips external plugins. The bridge's refusal behavior applies
    after its callback loads; it is not a guarantee for every host crash,
    interruption, or disabled plugin.

## Local and open models

OpenCode supports [Ollama and other local providers](https://opencode.ai/docs/providers/#ollama).
Rampart checks the tool action rather than the inference provider, so a local
or remote model using the same supported dispatcher receives the same Rampart
policy evaluation. Ollama supplies inference; the harness supplies the tool
execution boundary.

Changing models can change which tools OpenCode exposes and how reliably the
model calls them. Rampart maps both `write`/`edit` and `apply_patch`, but this
does not establish compatibility with every provider and model combination.
Validate the chosen combination through its actual supported tool journey;
provider setup, adapter tests, or a simulated provider response alone do not
prove a real model's tool-calling behavior. Rampart does not configure providers,
download models, or claim that inference itself is protected by this plugin.

## Verification and exclusions

```bash
rampart doctor
```

Doctor checks whether the managed plugin file matches the current installation.
It does not launch OpenCode or prove hook ingestion. There is no
`rampart verify opencode` command, and `rampart verify --all` excludes this
static integration from behavioral results.

The V1 pre-tool hook does not cover manual shell commands, PTYs,
command-template shell interpolation, debug tool execution, attached-file or
MCP-resource context ingestion, or experimental V2 execution. OpenCode can
persist arguments, streamed metadata, and output files outside this callback;
the plugin does not claim redaction of those host-owned stores.
Host-added instruction reads and formatter or language-server side effects are
outside the requested action evaluated by this plugin.

The upstream contract is pinned to
[OpenCode v1.18.34](https://github.com/anomalyco/opencode/releases/tag/v1.18.34),
source revision `aec0b9a6d8898f68f923aaf08b7306d931fd9d76`. The relevant source
is the [plugin hook interface](https://github.com/anomalyco/opencode/blob/aec0b9a6d8898f68f923aaf08b7306d931fd9d76/packages/plugin/src/index.ts#L266),
[V1 tool dispatcher](https://github.com/anomalyco/opencode/blob/aec0b9a6d8898f68f923aaf08b7306d931fd9d76/packages/opencode/src/session/tools.ts#L107),
and [shell selection](https://github.com/anomalyco/opencode/blob/aec0b9a6d8898f68f923aaf08b7306d931fd9d76/packages/core/src/shell.ts#L214).
A source pin is a compatibility reference, not an installed-host verification.

## Remove

```bash
rampart setup opencode --remove
```

Restart OpenCode to unload it. Removal deletes only a recognized Rampart-owned
plugin and preserves unrelated configuration.
