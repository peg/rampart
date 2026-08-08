---
title: Securing Cline
description: "Install Rampart's platform-native Cline hooks for editor and CLI tool calls, with honest activation and host-proof limits."
---

# Cline

[Cline](https://github.com/cline/cline) exposes `PreToolUse` and `PostToolUse`
file hooks. Rampart uses those native boundaries to evaluate supported shell,
file, web, agent, and MCP calls before execution and to scan tool results after
execution.

Rampart's adapter and installer are tested on Linux, macOS, and Windows build
targets. A rolling job checks latest Cline package startup, generated hooks,
and adapter denial on Linux and Windows. The Windows `.ps1` contract is also
covered by unit/cross-build tests; authenticated host ingestion and a physical
Windows Cline E2E are still pending.

## Setup

```bash
rampart setup cline
rampart verify cline
```

The default user-level files are direct children of Cline's shared hook
directory:

| Host | Files |
|---|---|
| Linux / macOS | `~/Documents/Cline/Hooks/PreToolUse` and `PostToolUse` |
| Windows | `~/Documents/Cline/Hooks/PreToolUse.ps1` and `PostToolUse.ps1` |

On POSIX systems Rampart makes the files executable, which is how current Cline
marks them enabled. Cline's Hooks UI can disable them by clearing that bit. On
Windows, current Cline activates `.ps1` hooks by file presence, launches them
with PowerShell, and does not currently expose the same enable/disable toggle.

Earlier Rampart releases wrote nested paths such as
`PreToolUse/rampart-policy`. Current Cline does not discover that layout.
Running `rampart setup cline` upgrades an owned legacy layout in place. Rampart
refuses to replace or delete a hook it cannot identify as Rampart-managed, even
with `--force`.

### Workspace and CLI paths

```bash
rampart setup cline --workspace
rampart setup cline --hooks-dir /absolute/path/to/hooks
```

`--workspace` writes `.clinerules/hooks`, which remains a discovery path for
the editor and CLI. Avoid installing the same Rampart pair at both user and
workspace scope unless you intentionally want duplicate hook evaluation.

Current Cline CLI source and its path tests search `~/Documents/Cline/Hooks`,
`~/.cline/hooks`, `.clinerules/hooks`, and `.cline/hooks`. `CLINE_DIR` relocates
the `~/.cline` root. `--data-dir` and `CLINE_DATA_DIR` relocate runtime state
but do **not** relocate hook discovery, despite broader wording in the CLI
README's environment-variable summary. Rampart accepts `--data-dir` for
command-line parity and reports the source-verified behavior.

Cline CLI advertises `--hooks-dir`, but the reviewed loader currently stores
the override without consuming it in file-hook discovery. Rampart can install
an explicit directory, but you must pass the same path to a Cline build that
honors it and confirm host activation; do not treat the artifact alone as proof.

<Warning>
  Do not use Cline CLI's legacy `--yolo` mode when relying on Rampart. Current
  Cline disables runtime hooks in that mode. Ordinary auto-approval settings do
  not imply this legacy mode.
</Warning>

<Warning>
  Current Cline CLI logs and continues when a pre-tool hook times out, fails to
  launch, or emits invalid control JSON. It also runs post-tool file hooks
  asynchronously and ignores their control response. A valid Rampart pre-call
  denial still cancels the call, but the CLI path is not a fail-closed boundary
  for hook infrastructure failure, and post-tool checks provide audit evidence
  rather than blocking the already-completed call or subsequent agent loop.
</Warning>

## What Gets Intercepted

| Tool family | Current examples | Rampart type |
|---|---|---|
| Shell | `run_commands`, `execute_command`, `bash` | `exec` |
| File reads/search | `read_files`, `read_file`, `search_codebase` | `read` |
| File changes | `editor`, `apply_patch`, `replace_in_file`, `write_to_file` | `write` |
| Web | `fetch_web_content`, `web_fetch`, `browser_action` | `fetch` |
| Delegation/teams | `spawn_agent`, `team_run_task`, team lifecycle tools | `agent` |
| MCP | legacy wrappers and current `server__tool` names | shared MCP classifier |

Rampart evaluates every path in current batched reads and patches, and every
command in `run_commands`. Current multi-URL `fetch_web_content` calls are
denied with a request to split the batch, because allowing after evaluating
only one URL would be unsafe. Unknown future pre-call tools fail closed in
enforce mode until Rampart can classify them.

Coverage applies only to calls Cline exposes through these hooks. It is not a
system-wide syscall or network boundary, and custom/plugin tools require a
known mapping before Rampart will allow them in enforce mode.

## How It Works

1. Cline sends a JSON hook payload to `rampart hook --format cline`.
2. Rampart normalizes the editor `PreToolUse`/`PostToolUse` envelope or the
   current CLI `tool_call`/`tool_result` envelope.
3. Rampart evaluates the call against local YAML policies.
4. An allowed call returns `{"cancel":false}`. A denied or approval-required
   call returns `{"cancel":true}` with policy context.
5. In the editor, `PostToolUse` can return the normal Cline cancellation
   response. Current Cline CLI launches post-tool hooks asynchronously and
   ignores that response, so the same hook records the decision but cannot stop
   continuation in the CLI host.

Cline does not provide Rampart with a reliable native ask/resume contract, so
`ask` fails closed as immediate cancellation rather than waiting indefinitely.

`rampart verify cline` checks owned content, the correct platform filename,
the POSIX executable bit where applicable, and a safe adapter denial canary. It
does not claim that a real Cline process invoked the hook; confirm observed
calls with `rampart watch` before relying on a new host/version.

## Troubleshooting

If no calls appear in `rampart watch`:

1. Run `rampart verify cline`.
2. Confirm both Rampart hooks remain enabled in Cline's Hooks UI.
3. Confirm you did not launch Cline CLI with legacy `--yolo`.
4. For a custom directory, confirm that exact Cline build actually honors
   `--hooks-dir`.
5. Rerun `rampart setup cline` after upgrading from an older Rampart layout.

For a hard boundary against host hook failure, add OS/container isolation; a
native in-process hook cannot force Cline CLI itself to fail closed.

## Uninstall

```bash
rampart setup cline --remove
# or match the scope used at install time
rampart setup cline --workspace --remove
rampart setup cline --hooks-dir /absolute/path/to/hooks --remove
```

Only Rampart-owned files are removed. Policies and audit logs under
`~/.rampart/` are preserved.
