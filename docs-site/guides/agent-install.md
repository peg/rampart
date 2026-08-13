---
title: Install Rampart via an AI Agent
description: "Step-by-step instructions for an AI agent to install and configure Rampart. Works with OpenClaw, Claude Code, and Cline. One command, fully non-interactive."
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
    curl -fsSL https://rampart.sh/install | sh
    ```

=== "Go install"

    ```bash
    go install github.com/peg/rampart/cmd/rampart@latest
    ```

=== "Homebrew (macOS)"

    ```bash
    brew install peg/tap/rampart
    ```

Verify the install:

```bash
rampart --version
```

Expected output: `rampart vX.Y.Z`

---

## Step 2: Protect detected agents (non-interactive)

This single command auto-detects supported AI tools, starts or verifies the
local policy service, wires up their native boundaries, and runs safe active
verification:

```bash
rampart protect
```

`rampart protect` is non-interactive. It installs the managed Guard policy,
starts or verifies the local policy service, configures every detected supported
native integration, and runs safe active verification without invoking a model.
On Windows, the service helper uses a login-scoped background process rather
than a persistent system service. The deprecated `rampart quickstart --yes`
spelling remains available for existing scripts.

**OpenClaw note:** protection applies to future tool calls, not the current
session. `rampart protect` restarts the OpenClaw gateway automatically; restart
it manually only if you explicitly use `--no-restart`.

**Serve note:** direct Claude Code and Cline native hooks can evaluate policy locally without `rampart serve`, but dashboard views, approval APIs, and OpenClaw plugin evaluation rely on the local service.

---

## Step 3: Verify everything is working

```bash
rampart doctor
```

Review the checks that apply to the detected integrations. A warning or failure
means that boundary needs attention; follow the specific hint printed next to it.

Check the service is running and review recent activity:

```bash
rampart status
```

Expected output (example):
```
🛡️ Rampart Status

Configured: OpenClaw (plugin)
Mode: enforce (default_action: allow)
Today: 0 allow · 0 deny · 0 log

Assurance evidence
  ✓ OpenClaw                     HOST VERIFIED · checked 2m ago
```

`Configured` reports the installed boundary. `Assurance evidence` reports the
strongest recent proof Rampart can support on this machine. Run the suggested
`rampart verify <agent>` command whenever evidence is missing or stale.

---

## Step 4: Report back to the user

Tell the user:

- Rampart is installed and running (version from `rampart --version`)
- Which environment was auto-detected and configured
- Dashboard URL, when the local service is installed:
  `http://localhost:9090/dashboard/`
- Token location, when the local service is installed: `~/.rampart/token`
  (keep this private)

---

## What Rampart does

Rampart evaluates the supported tool calls that each configured host exposes
through its named hook, plugin, proxy, or process boundary. Pre-tool calls at
that boundary are evaluated before the host invokes the tool. Coverage outside
that boundary, including work performed inside an already allowed process, is
not implied. Some integrations also expose tool results for response scanning;
others do not. Check the [support matrix](../getting-started/support-matrix.md)
for the exact boundary and known gaps.

**Examples denied by the standard policy when observed at a supported command
boundary:**

- `rm -rf /`, `rm -rf ~`, `rm -rf *` — filesystem destruction
- `curl <url> | bash`, `wget <url> | sh` — remote code execution
- `cat ~/.ssh/id_rsa`, `cat ~/.ssh/id_ed25519` — SSH key exfiltration
- `cat .env`, `cat .env.*` — API key / secret access
- `dd if=/dev/urandom of=/dev/sda` — disk destruction

On integrations with a blockable post-tool boundary, response rules can also
deny or redact matched credential and prompt-injection patterns before the host
returns that result to the model. Integrations with observational or absent
post-tool results do not provide this guarantee.

Ordinary calls that do not match a restriction follow the active profile's
default action. In the standalone MCP stdio proxy, destructive tools are denied
and dangerous or unclassified tools receive an `ask` decision; because that
proxy cannot resume a held stdio call, it fails the call closed until policy
replaces the decision with an explicit `allow` or `deny`.

---

## Customizing protection

To see what policies are active:

```bash
rampart policy explain '<command>'
```

For common durable exceptions or blocks, use `rampart allow` and
`rampart block`; these write user-owned overrides separately from Rampart's
maintained standard policy. For a custom approval rule, edit
`~/.rampart/policies/custom.yaml`, which setup creates as an upgrade-safe
starter file. Do not customize `standard.yaml`, because Rampart manages that
profile during updates. See [Customizing Policy](customizing-policy.md) and the
[Policy Schema](../reference/policy-schema.md) for details.

To require human approval before a specific operation runs:

```yaml
version: "1"

policies:
  - name: approve-production-deploys
    match:
      tool: ["exec"]
    rules:
      - action: ask
        when:
          command_contains: ["--namespace prod"]
        message: "Production deploy requires human approval"
```

---

## Troubleshooting

**`rampart doctor` shows hook not installed**

Re-run protection or setup for your specific agent:

```bash
rampart protect             # Detect and repair supported integrations
rampart protect openclaw    # OpenClaw managed guard + behavioral verification
rampart protect claude-code # Claude Code native hooks + verification
rampart protect cline       # Cline native hooks + verification
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
| `rampart protect` | Detect, configure, and verify supported integrations |
| `rampart quickstart --yes` | Deprecated compatibility workflow |
| `rampart doctor` | Health check — hooks, service, permissions |
| `rampart status` | Show configured agents, assurance evidence, mode, and today's counts |
| `rampart watch` | Live feed of tool decisions observed by Rampart |
| `rampart token` | Print bearer token for the dashboard |
| `rampart policy explain '<command>'` | Trace how a command is evaluated |

Docs: <https://docs.rampart.sh>  
Issues: <https://github.com/peg/rampart/issues>
