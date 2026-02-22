---
title: Install Rampart via an AI Agent
description: "Step-by-step instructions for an AI agent to install and configure Rampart. Works with OpenClaw, Claude Code, Cursor, and Cline. One command, fully non-interactive."
---

# Install Rampart via an AI Agent

This guide is written for AI agents executing on behalf of a user who said something like:

> "Install Rampart and protect this machine"  
> "Set up Rampart to secure my Claude Code / OpenClaw agent"  
> "Add safety guardrails to my AI coding environment"

Follow these steps in order. Each step is independently verifiable.

---

## Step 1: Install the Rampart binary

=== "Linux / macOS (curl)"

    ```bash
    curl -fsSL https://rampart.sh/install.sh | sh
    ```

=== "Go install"

    ```bash
    go install github.com/peg/rampart/cmd/rampart@latest
    ```

=== "Homebrew (macOS)"

    ```bash
    brew tap peg/rampart && brew install rampart
    ```

Verify the install:

```bash
rampart --version
```

Expected output: `rampart vX.Y.Z`

---

## Step 2: Run quickstart (non-interactive)

This single command auto-detects the running AI environment, installs the background policy service, wires up hooks, and runs a health check:

```bash
rampart quickstart --yes
```

The `--yes` flag skips any prompts. For **OpenClaw** it also auto-enables `--patch-tools` (full coverage for file reads/writes/edits in addition to shell commands). For all other agents the flag is a safe no-op.

**OpenClaw note:** protection applies to future tool calls, not the current session. Restart the OpenClaw gateway after this step for hooks to take effect.

---

## Step 3: Verify everything is working

```bash
rampart doctor
```

Expected output: all checks pass (✓). If any check fails, follow the hint printed next to it.

Check the service is running and review recent activity:

```bash
rampart status
```

Expected output (example):
```
🛡️ Rampart Status

Protected: openclaw
Mode: enforce (default_action: allow)
Today: 0 allow · 0 deny · 0 log
```

If you see `Protected:` with your agent listed, Rampart is active.

---

## Step 4: Report back to the user

Tell the user:

- Rampart is installed and running (version from `rampart --version`)
- Which environment was auto-detected and configured
- Dashboard URL: `http://localhost:9090/dashboard/` (opens in browser to show live policy activity)
- Token location: `~/.rampart/token` (keep this private)

---

## What Rampart does

Every shell command, file access, and network request your AI agent makes is now evaluated against a policy before it executes.

**Blocked by default** (standard policy):
- `rm -rf /`, `rm -rf ~`, `rm -rf *` — filesystem destruction
- `curl <url> | bash`, `wget <url> | sh` — remote code execution
- `cat ~/.ssh/id_rsa`, `cat ~/.ssh/id_ed25519` — SSH key exfiltration
- `cat .env`, `cat .env.*` — API key / secret access
- `dd if=/dev/urandom of=/dev/sda` — disk destruction
- Prompt injection patterns in tool responses — exfiltration directives, instruction overrides

**Allowed by default**: everything else. The policy engine is deny-on-match, not deny-by-default — it only blocks what the rules explicitly cover.

---

## Customizing protection

To see what policies are active:

```bash
rampart policy explain '<tool_name>'
```

To add your own rules, edit `~/.rampart/policies/standard.yaml`. See [Policy Schema](../reference/policy-schema.md) for the full syntax.

To require human approval before a specific operation runs:

```yaml
policies:
  - name: approve-production-deploys
    match:
      tool: ["exec"]
      command_contains: ["kubectl", "helm", "--namespace prod"]
    rules:
      - action: require_approval
        message: "Production deploy requires human approval"
```

---

## Troubleshooting

**`rampart doctor` shows hook not installed**

Re-run setup for your specific agent:

```bash
rampart setup openclaw --patch-tools   # OpenClaw
rampart setup claude-code              # Claude Code
rampart setup cline                    # Cline
rampart setup cursor                   # Cursor
```

**Service not running**

```bash
rampart serve install   # installs and starts the background service
rampart status          # verify
```

**A legitimate command is being blocked**

```bash
rampart policy explain '<command>'   # see which rule matched
```

Then add an allow rule for your specific use case. See [Securing Claude Code](https://docs.rampart.sh/guides/securing-claude-code/).

`rampart serve` also writes `~/.rampart/ACTIVE_POLICY.md`, a markdown table of active rules that agents can use for self-description.

---

## Reference

| Command | What it does |
|---------|--------------|
| `rampart quickstart --yes` | Full non-interactive setup |
| `rampart doctor` | Health check — hooks, service, permissions |
| `rampart status` | Show protected agents, mode, today's allow/deny counts |
| `rampart watch` | Live audit feed of all tool calls |
| `rampart token` | Print bearer token for the dashboard |
| `rampart policy explain '<tool>'` | Show which policy applies to a tool call |

Docs: <https://docs.rampart.sh>  
Issues: <https://github.com/peg/rampart/issues>
