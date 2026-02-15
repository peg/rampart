# Claude Code

Claude Code is Rampart's primary integration. One command, native hooks, zero overhead.

## Setup

```bash
rampart setup claude-code
```

That's it. This installs hooks into Claude Code's hook system that intercept every:

- **Bash command** (`exec`)
- **File read** (`read`)
- **File write/edit** (`write`)

## How It Works

Claude Code has a built-in [hook system](https://docs.anthropic.com/en/docs/claude-code/hooks) that allows external tools to evaluate tool calls before they execute. Rampart registers as a hook handler.

```
Claude Code → Tool Call → rampart hook → Policy Engine → Allow/Deny
                                                       → Audit Trail
```

When Claude Code wants to run a command, it sends the tool call to `rampart hook` via stdin. Rampart evaluates it against your policies and returns a JSON response:

```json
// Allowed (permissionDecision omitted when allowed)
{"hookSpecificOutput":{"hookEventName":"PreToolUse"}}

// Denied
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Rampart: Destructive command blocked"}}

// Requires approval (waits for human decision)
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"Rampart: Manual approval required"}}
```

**require_approval behavior:** When a policy action is `require_approval`, the hook blocks and waits for human resolution via `rampart approve <id>` or the API. Once resolved, it returns the final decision to Claude Code.

Denied commands never execute. Claude Code receives the denial reason and can explain it to the user.

## Usage

Just use Claude Code normally:

```bash
claude
```

Rampart is completely transparent. Safe commands pass through in microseconds. You won't notice it's there — until it blocks something dangerous.

## Monitor in Real Time

```bash
rampart watch
```

## Custom Policy

By default, Rampart uses the `standard` profile. To customize:

```bash
# Edit your policy
vim ~/.rampart/policies/standard.yaml

# Changes take effect immediately (hot reload)
```

See [Configuration](../getting-started/configuration.md) for the full policy format.

## Uninstall

```bash
rampart setup claude-code --remove
```

This removes the Rampart hooks from Claude Code's settings. Your policies and audit logs in `~/.rampart/` are preserved.

## Troubleshooting

### Verify hooks are installed

```bash
cat ~/.claude/settings.json
```

You should see Rampart entries for `PreToolUse` hooks.

### Test a decision

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | rampart hook
```

### Check audit log

```bash
rampart audit tail
```
