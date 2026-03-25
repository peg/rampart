---
title: Protect Your First Agent in 5 Minutes
description: "Follow Rampart's 5-minute tutorial to secure your first AI coding agent. Block unsafe commands, test policy decisions, and understand approval flow."
---

# Protect Your First Agent in 5 Minutes

So you've got an AI agent writing code on your machine. Maybe it's Claude Code, maybe it's Codex, maybe it's Cline. It can run commands, read your files, and — if you're not careful — do things you didn't ask for.

Rampart sits between your agent and your system, checking every action against rules you define. Safe commands pass through in microseconds. Dangerous ones stop at the door. Risky ones pause for your approval.

Let's set it up.

---

## Prerequisites

- **macOS or Linux** (Windows WSL works too)
- **Go 1.24+** (recommended) or the install script for a no-Go option
- **Claude Code, Codex, or Cline** — this guide uses Claude Code, but Rampart works with [many agents](../integrations/index.md)

---

## Step 1: Install

=== "Go install (recommended)"

    ```bash
    go install github.com/peg/rampart/cmd/rampart@latest
    ```

=== "Script"

    ```bash
    curl -fsSL https://rampart.sh/install | sh
    ```

=== "Homebrew"

    ```bash
    brew tap peg/rampart && brew install rampart
    ```

Verify:

```bash
rampart version
```

!!! tip "Command not found?"
    Make sure `$(go env GOPATH)/bin` is in your `PATH`, or symlink: `sudo ln -sf $(go env GOPATH)/bin/rampart /usr/local/bin/rampart`

---

## Step 2: One Command to Get Protected

```bash
rampart quickstart
```

That's it. This single command:

1. Detects your AI agent (Claude Code, Codex, Cline, etc.)
2. Installs the Rampart service with a secure token
3. Wires up hooks so every tool call is evaluated before it runs
4. Runs `rampart doctor` to verify everything is healthy

```
✓ Detected Claude Code
✓ Rampart service installed and running
✓ Hooks registered in ~/.claude/settings.json
✓ Hook binary path verified
✓ Token auth working
✓ 1 policy loaded

🛡️  Rampart is active. Use Claude Code normally.
```

Now start Claude Code:

```bash
claude
```

Every command Claude attempts runs through Rampart first. Most will pass through instantly — you'll never notice. The dangerous ones stop before they execute.

---

## Step 3: See It in Action

### Blocked commands

Ask Claude to do something destructive:

> "Delete everything in the root directory"

Claude Code will attempt `rm -rf /`. Rampart stops it:

```
🛡️ Rampart blocked: rm -rf /
   Reason: Destructive command blocked
```

The command never ran.

### Approved commands

Safe commands pass through transparently:

> "Run the tests, then commit the result"

```
npm test      ✅ allowed
git add .     ✅ allowed
git commit    ✅ allowed
```

No friction, no delays.

### Commands requiring approval

Some commands are too impactful to auto-allow or auto-deny — they should pause for a human decision. For example, deploying to production:

> "Push this to main and deploy"

```
⏳ Approval required — "git push origin main"
   Approve at: http://localhost:9090/dashboard/
   Approval ID: 01KHT3...
```

Rampart pauses Claude Code and waits. Open the dashboard, review the request, and approve or deny it:

```
open http://localhost:9090/dashboard/
```

![Dashboard approval card showing the pending command with Approve and Deny buttons]

Approve it → Claude continues. Deny it → Claude gets an explanation and tries a different approach.

!!! tip "Working with an agent team?"
    If you run multiple Claude Code sub-agents in the same session, they all share a run ID. The dashboard groups their pending approvals together — one click to **Approve All** for the whole team run.

---

## Step 4: Customize Your Policy

The default policy blocks destructive commands. Your project probably needs more nuance. Open the policy file and edit it:

```bash
$EDITOR ~/.rampart/policy.yaml
```

Here's what a real policy looks like:

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
      - action: ask
        when:
          command_matches:
            - "git push *main*"
            - "npm publish*"
            - "docker push *"
        message: "Production deploy — approve?"

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

After editing, validate before trusting it:

```bash
# Check for syntax errors and common mistakes
rampart policy lint ~/.rampart/policy.yaml

# Test a specific command against your policy
rampart test "git push origin main"
# → ask (approve-deploys)

rampart test "rm -rf /"
# → deny (block-destructive)
```

The dashboard also has a built-in **Policy REPL** — type any command and instantly see what your policy would do.

!!! tip "Start permissive, tighten later"
    Keep `default_action: allow` and use `action: watch` rules to observe what your agent actually does before you start blocking things. Check the audit trail after a day of work, then write deny rules for what concerns you.

---

## Verify Everything Is Healthy

At any point, run:

```bash
rampart doctor
```

```
✓ rampart in PATH
✓ Token configured
✓ Hook binary path verified
✓ Service reachable (localhost:9090)
✓ Token auth working
✓ 4 policies loaded
⚠ 2 pending approvals
```

Green across the board means you're fully protected.

---

## What Happens on Every Tool Call

```
Agent wants to run "npm test"
        │
        ▼
Claude Code PreToolUse hook fires
        │
        ▼
Rampart evaluates against YAML policies (~20μs):
  1. Does "npm test" match block-destructive?  No.
  2. Does "npm test" match approve-deploys?    No.
  3. No rules matched → default_action: allow
        │
        ▼
✅ Command executes normally
```

The evaluation takes **microseconds**. Your agent doesn't slow down.

---

## Next Steps

- **[Example Policies](https://github.com/peg/rampart/tree/main/policies/examples)** — Ready-to-use templates for web dev, infrastructure, data science, and lockdown
- **[Policy Engine →](../features/policy-engine.md)** — Condition types, rule priority, glob patterns
- **[Dashboard →](../features/dashboard.md)** — Approval flow, audit history, policy management
- **[Integration Guides →](../integrations/index.md)** — Cline, Cursor, Codex, MCP servers
- **[Configuration →](configuration.md)** — Advanced options, webhooks, signing
