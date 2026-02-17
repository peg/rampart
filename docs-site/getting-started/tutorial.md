# Protect Your First Agent in 5 Minutes

So you've got an AI agent writing code on your machine. Maybe it's Claude Code, maybe it's Codex, maybe it's something else. Either way, it can run commands, read your files, and — if you're not careful — do things you didn't ask for.

Rampart is a firewall for AI agents. It sits between your agent and your system, checking every action against rules you define. Good commands get through instantly, dangerous ones get stopped at the door.

Let's set it up.

## Prerequisites

You'll need:

- **macOS or Linux** (Windows WSL works too)
- **Homebrew** (recommended) or **Go 1.24+** for building from source
- **An AI agent** — this tutorial uses Claude Code, but Rampart works with [many agents](../integrations/index.md)

## Step 1: Install Rampart

=== "Homebrew (recommended)"

    ```bash
    brew tap peg/rampart && brew install rampart
    ```

=== "Go install"

    ```bash
    go install github.com/peg/rampart/cmd/rampart@latest
    ```

Verify it's working:

```bash
rampart version
```

!!! tip "Don't see it?"
    If you get `command not found`, make sure `$(go env GOPATH)/bin` is in your PATH, or symlink: `sudo ln -sf $(go env GOPATH)/bin/rampart /usr/local/bin/rampart`. See the [troubleshooting guide](troubleshooting.md#rampart-command-not-found) for more.

## Step 2: Set Up for Claude Code

One command:

```bash
rampart setup claude-code
```

That's it. Rampart just:

1. Created a **policy file** with sensible defaults (block destructive commands, log suspicious ones, allow everything else)
2. Installed **hooks** into Claude Code's `~/.claude/settings.json` so every tool call gets checked before it runs

!!! info "What are hooks?"
    Claude Code has a [hook system](https://docs.anthropic.com/en/docs/claude-code/hooks) that lets external tools intercept tool calls. Rampart registers as a `PreToolUse` hook — it sees every command *before* it executes and can block it.

## Step 3: Try It

Start Claude Code normally:

```bash
claude
```

Ask it to do something that should be blocked:

> "Delete everything in the root directory"

Claude Code will try to run `rm -rf /`, and Rampart blocks it:

```
🛡️ Rampart blocked: rm -rf /
   Reason: Destructive command blocked
```

The command never ran. Meanwhile, safe commands work without you noticing:

> "Run the tests"

```bash
npm test  # ✅ Passes through instantly
```

## Step 4: Customize Your Policy

The default `standard` policy is a great start, but your project is unique. Copy an example template and customize it:

```bash
# Copy a template as your starting point
cp $(brew --prefix)/share/rampart/policies/examples/web-developer.yaml ~/.rampart/policy.yaml
```

Or grab one from the repo:

```bash
curl -o ~/.rampart/policy.yaml https://raw.githubusercontent.com/peg/rampart/main/policies/examples/web-developer.yaml
```

Here's what a policy looks like:

```yaml
version: "1"
default_action: allow

policies:
  - name: block-destructive
    match:
      tool: ["exec"]
    rules:
      - action: deny
        when:
          command_matches:
            - "rm -rf /"
            - "rm -rf ~"
            - "dd if=*"
            - "mkfs*"
        message: "Destructive command blocked"

  - name: approve-deploys
    match:
      tool: ["exec"]
    rules:
      - action: require_approval
        when:
          command_matches:
            - "git push *main*"
            - "npm publish*"
            - "docker push *"
        message: "Production deployment — approve?"

  - name: block-credentials
    match:
      tool: ["read"]
    rules:
      - action: deny
        when:
          path_matches:
            - "**/.env"
            - "**/.ssh/id_*"
            - "**/.aws/credentials"
        message: "Credential file access blocked"
```

After editing, validate your changes:

```bash
# Lint for common mistakes
rampart policy lint ~/.rampart/policy.yaml

# Run inline tests if your policy has them
rampart test ~/.rampart/policy.yaml

# Dry-run a specific command
rampart test "rm -rf /"
```

!!! warning "Test before you trust"
    Always run `rampart policy lint` and `rampart test` after editing. A typo in a pattern can block everything — or nothing.

## Step 5: Monitor in Real Time

Open a second terminal and watch decisions as they happen:

```bash
rampart watch
```

Or review the audit log:

```bash
rampart log --tail 20
```

Every decision (allow, deny, log, approval) is written to a hash-chained audit trail at `~/.rampart/audit/`.

## What Just Happened?

Here's the flow, every time your agent tries to use a tool:

```
Agent wants to run "npm test"
        │
        ▼
Claude Code hook fires (PreToolUse)
        │
        ▼
Rampart evaluates against YAML policies (~20μs):
  1. Does "npm test" match block-destructive? No.
  2. Does "npm test" match approve-deploys? No.
  3. No rules matched → default_action: allow
        │
        ▼
✅ Command executes normally
```

The whole evaluation takes **microseconds**. Your agent doesn't slow down. But if it tries `rm -rf /`, it hits the deny rule and stops dead.

## Bonus: Protect MCP Servers Too

If you're using MCP servers (for Claude Desktop, Cursor, or any MCP client), Rampart can proxy those too. This works alongside the Claude Code hooks above — both can run at the same time.

### What's MCP?

[Model Context Protocol (MCP)](https://modelcontextprotocol.io) lets AI agents talk to external tools through a standard interface — file systems, GitHub, Slack, databases, and more. MCP servers expose "tools" that agents can call.

The problem: these servers often have broad access, and there's no built-in way to limit what tools an agent can use.

### Wrap an MCP Server

Instead of pointing your agent directly at an MCP server, put Rampart in front:

```bash
# Before (no guardrails):
npx @modelcontextprotocol/server-filesystem /path/to/project

# After (with Rampart):
rampart mcp -- npx @modelcontextprotocol/server-filesystem /path/to/project
```

In your MCP client config (e.g., `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "rampart",
      "args": ["mcp", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "."]
    }
  }
}
```

### Auto-Generate a Policy from MCP Tools

Don't write rules from scratch — scan what tools the server exposes:

```bash
rampart mcp scan -- npx @modelcontextprotocol/server-filesystem .
```

This generates a deny-by-default policy with a rule for each tool. Review it, tweak it, and you're done.

### What Happens

When the agent calls an MCP tool:

- **Allowed tools** pass through instantly — the server handles them normally
- **Denied tools** get a JSON-RPC error back — the server never sees them
- **Tools with destructive keywords** (delete, destroy, remove) are blocked automatically

```bash
# Watch MCP decisions alongside everything else:
rampart watch
```

For more details, see the [MCP Proxy feature guide](../features/mcp-proxy.md) and the [Claude Desktop integration](../integrations/claude-desktop.md).

## Next Steps

You're protected. Here's where to go from here:

- **[Example Policies](https://github.com/peg/rampart/tree/main/policies/examples)** — Ready-to-use templates for web dev, infrastructure, data science, and lockdown mode
- **[Policy Engine](../features/policy-engine.md)** — Deep dive into matching, rule priority, and condition types
- **[Approval Flow](../features/dashboard.md)** — Set up human-in-the-loop approval for risky commands
- **[Audit Trail](../features/audit-trail.md)** — Ship logs to your SIEM or review them locally
- **[Integration Guides](../integrations/index.md)** — Set up Rampart with Cline, Cursor, Codex, or any agent

!!! tip "Start permissive, tighten later"
    The `standard` profile with `default_action: allow` is the best way to start. Watch the logs for a day, see what your agent actually does, then add deny rules for things that concern you.
