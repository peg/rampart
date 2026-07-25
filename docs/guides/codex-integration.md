# Securing Codex with Rampart

Rampart uses [Codex lifecycle hooks](https://developers.openai.com/codex/hooks)
to evaluate local tool calls before they run. One user-level setup covers
Codex CLI, the IDE extension, and the desktop app.

## Setup

```bash
rampart setup codex
```

Rampart adds wildcard `PreToolUse` and `PostToolUse` entries to
`$CODEX_HOME/hooks.json`, or `~/.codex/hooks.json` when `CODEX_HOME` is unset.
Existing unrelated hooks are preserved. If an older Rampart release installed
`~/.local/bin/codex`, setup removes that managed preload wrapper to avoid
evaluating shell commands twice.

Codex treats user hooks as executable configuration. Open `/hooks` in Codex,
review the exact Rampart command, and trust it. A changed hook definition must
be reviewed again.

## What is covered

Codex reports supported local tool calls through the same lifecycle protocol:

- shell and unified execution calls;
- reads, writes, edits, and `apply_patch`;
- MCP tool calls;
- web/browser-style local tools;
- delegated-agent tool calls when the host emits the lifecycle event.

Rampart expands every target in a multi-file `apply_patch` request and applies
deny-wins policy evaluation to each path. An allowed first file cannot conceal
a protected later target.

Hosted tools and specialized execution paths that Codex does not expose to
lifecycle hooks remain outside this boundary. `rampart preload` remains an
optional Unix defense-in-depth mechanism for other processes; it is no longer
the primary Codex integration.

## Decisions and approvals

On allow, Rampart returns an empty hook response. This deliberately preserves
Codex's own sandbox and permission checks. On deny, Rampart returns Codex's
structured `PreToolUse` denial.

Codex does not currently accept an `ask` decision from `PreToolUse`. Policies
that require approval therefore use Rampart's blocking approval queue:

```bash
rampart serve
rampart watch
```

If the approval service is unavailable, Rampart denies the call instead of
silently allowing it. Ordinary local allow/deny policy evaluation does not
require the service.

## Verify

```bash
rampart verify codex
```

Verification checks that both lifecycle hooks are installed and sends a safe,
non-executing destructive-command canary through Rampart's live Codex adapter.
It also runs the standard policy canaries when the Rampart service is
available. This proves the installed configuration and adapter response; the
assurance manifest separately records that a real Codex host-boundary test is
still pending.

You can also inspect overall health:

```bash
rampart doctor
rampart status
```

## Uninstall

```bash
rampart setup codex --remove
```

Only Rampart's Codex hook entries and a recognized legacy Rampart wrapper are
removed. Other user hooks are left untouched.

## Platform support

The native hook setup supports Linux, macOS, and Windows. The generated
configuration includes both POSIX and Windows command forms and uses a
restrictive file mode on Unix. Hook timeout behavior is controlled by Codex;
Rampart does not claim that a host-enforced timeout fails closed.
