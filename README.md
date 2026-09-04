<div align="center">

# Rampart

**Open-source policy and approval control for AI agents.**

<img src="docs/og-authority-visible.png" alt="Rampart — Let agents move fast. Keep the final say." width="100%">

[![Go](https://img.shields.io/badge/Go-1.26.8+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/peg/rampart/actions/workflows/ci.yml/badge.svg)](https://github.com/peg/rampart/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/peg/rampart?style=flat)](https://github.com/peg/rampart/releases)
[![Docs](https://img.shields.io/badge/Docs-docs.rampart.sh-FF6392?style=flat)](https://docs.rampart.sh)

[Install](#install) · [How it works](#how-it-works) · [Integrations](#integrations) · [Policies](#a-policy-you-can-read) · [Documentation](https://docs.rampart.sh)

</div>

---

AI agents can edit files, run commands, call APIs, and ship code at machine
speed. Their permission systems usually ask a different question: **can this
tool run?**

Rampart asks: **should this action run?**

It sits at supported hooks, plugins, proxies, and process boundaries; evaluates
the action against local policy; and returns `allow`, `ask`, or `deny` before the
host executes it. Decisions are visible, approvals stay human-owned, and the
result becomes part of a hash-chained audit trail.

```text
Agent proposes an action
          │
          ▼
   ┌─────────────┐
   │   Rampart   │  policy · approval · audit
   └──────┬──────┘
          │
      allow / ask / deny
          │
          ▼
Host executes — or does not
```

Rampart is a security boundary, **not a sandbox**. It sees actions exposed by
the configured integration; it does not see arbitrary syscalls or network
traffic inside a process you already allowed. Start with the
[threat model](docs/THREAT-MODEL.md) when deciding where to rely on it.

## Install

```bash
brew install peg/tap/rampart

rampart protect
rampart verify --all
rampart watch
```

That is the normal path:

1. `protect` detects supported installed agents and configures their managed
   boundaries.
2. `verify --all` runs fixed, non-executing canaries without invoking a model.
3. `watch` shows decisions as they happen.

<details>
<summary><strong>Other installation methods</strong></summary>

**macOS and Linux installer**

```bash
curl -fsSL https://rampart.sh/install | bash
```

**Windows PowerShell**

```powershell
irm https://rampart.sh/install.ps1 | iex
```

**Go**

```bash
go install github.com/peg/rampart/cmd/rampart@latest
```

Source builds require Go 1.26.8 or newer. Windows upgrades use the PowerShell
installer; binary self-upgrade is intentionally disabled there.

</details>

## Why Rampart

| | What you get |
| --- | --- |
| **Policy before execution** | Match shell, file, network, MCP, messaging, and other host-exposed actions before they run. |
| **Selective approval** | Routine work stays quiet. Sensitive actions can use the host's native approval UI where the integration supports it. |
| **Fail-closed ownership** | When Rampart owns a decision and cannot safely classify or persist it, the action does not silently proceed. |
| **Auditable evidence** | Inspect live decisions, verify installed boundaries, and validate a hash-chained local audit trail. |
| **Local and model-free by default** | The policy engine is a Go binary. Core enforcement and verification do not require an LLM or provider traffic. |

## How it works

<img src="docs/architecture.svg" alt="Rampart architecture" width="100%">

Every integration has a concrete observation boundary. Rampart normalizes the
action visible there. When a supported adapter receives multiple represented
targets, it evaluates each one and lets the most restrictive decision win.

```text
ALLOW  exec  npm test                         [allow-dev]
DENY   read  ~/.ssh/id_ed25519                [block-credentials]
ASK    exec  kubectl apply -f production.yaml [approve-production]
DENY   resp  tool output contained a secret   [scan-response]
```

`rampart status` separates configuration from evidence:

- `HOST VERIFIED` means an active safe verifier reached the installed host
  boundary.
- `ADAPTER VERIFIED` means Rampart proved its installed configuration and
  adapter behavior, not authenticated host ingestion.
- Experimental and static-only integrations stay labeled as such.

Verification receipts contain outcomes and fingerprints—not prompts, commands,
credentials, host output, or agent memory.

## Integrations

| Integration | Boundary | Current assurance |
| --- | --- | --- |
| **OpenClaw** | Native `before_tool_call` plugin | Live host verifier; managed fail-closed defaults and native approval cards |
| **Claude Code** | Native pre/post tool hooks | Installed configuration and adapter verification |
| **Codex** | User-level lifecycle hooks for CLI, IDE, and desktop | Installed configuration and adapter verification |
| **Cline** | Editor and CLI hook files | Package startup, hook shape, and adapter tested; host limitations documented |
| **Antigravity** | Shared CLI/IDE `PreToolUse` plugin | Installed plugin and adapter verification |
| **GitHub Copilot** | CLI adapter and VS Code Preview hooks | Package/adapter and contract testing; authenticated ingestion pending |
| **Cursor** | Local Agent and Cmd+K `preToolUse` hook | Installed fail-closed configuration and adapter verification; Cloud/Tab separate |
| **Hermes Agent** | Experimental `pre_tool_call` user plugin | Compatible hosts can use native approval; no safe live host verifier yet |
| **Gemini CLI** | Experimental `BeforeTool`/`AfterTool` hooks | Enterprise/API-key path; authenticated host proof pending |
| **MCP servers** | JSON-RPC stdio proxy | Correlated request/response policy and identity enforcement |
| **Other agents** | Cooperative shell wrapper or compatible process preload | Explicitly limited; prefer a native integration when available |

```bash
rampart protect openclaw
rampart setup claude-code
rampart setup codex
rampart setup cline
rampart setup antigravity
rampart setup copilot
rampart setup cursor
```

Experimental integrations are explicit opt-ins and stay outside bare
`rampart protect` auto-detection:

```bash
rampart setup hermes
rampart setup gemini
```

See the [support matrix](https://docs.rampart.sh/getting-started/support-matrix/)
for platform coverage, verifier strength, and known host-owned limitations.

## A policy you can read

Rampart policies are YAML, local, and hot-reloaded:

```yaml
version: "1"
default_action: allow

policies:
  - name: block-credential-reads
    match:
      tool: [read]
    rules:
      - action: deny
        when:
          path_matches:
            - "**/.ssh/id_*"
            - "**/.aws/credentials"
            - "**/.env"
        message: "Credential access blocked"

  - name: approve-production
    match:
      tool: [exec]
    rules:
      - action: ask
        when:
          command_matches:
            - "kubectl apply *"
            - "terraform apply *"
        message: "Production change requires approval"
```

For common cases, you do not need to edit YAML:

```bash
rampart allow "npm install *"
rampart block "curl * | bash"
rampart rules
rampart test "rm -rf /"
```

Project-specific policy can live with the code:

```bash
rampart init --project
```

That creates `.rampart/policy.yaml`. Set `RAMPART_NO_PROJECT_POLICY=1` when
working in a repository whose policy you do not trust.

[Policy guide →](https://docs.rampart.sh/features/policy-engine/) ·
[Policy schema →](https://docs.rampart.sh/reference/policy-schema/) ·
[Community policies →](https://docs.rampart.sh/community-policies/)

## Approvals without prompt fatigue

An `ask` rule escalates only the action that matched. Depending on the
integration, approval appears in the agent's native UI or in Rampart's CLI and
dashboard.

```bash
rampart pending
rampart approve <id>
rampart deny <id>
```

OpenClaw can offer `allow-once`, `allow-always`, and `deny` on the original tool
call. Compatible Hermes installations pause and resume that same call. Other
integrations expose only the approval behavior their host can safely support;
Rampart does not invent a second approval owner and call it equivalent.

## Watch, verify, and audit

<div align="center">
<img src="docs/watch.png" alt="Rampart live decision view" width="720">
</div>

```bash
rampart status
rampart doctor
rampart verify --all
rampart audit tail --follow
rampart audit verify
```

Audit records are hash-chained and redact common credential shapes before
normal persistence and display boundaries. They still contain operational
metadata and command structure, so treat the owner-only audit directory as
sensitive authorization state.

## MCP and non-native agents

Proxy a command-launched MCP server:

```bash
rampart mcp -- npx @modelcontextprotocol/server-filesystem /path
rampart init --profile mcp-server
```

For an agent without native hooks:

```bash
rampart wrap -- your-agent
rampart preload -- your-agent
```

`wrap` is a cooperative `$SHELL` boundary and cannot intercept absolute shell
paths or direct process APIs. `preload` covers compatible dynamically linked
exec/spawn calls on Linux and non-SIP-protected macOS processes; static,
setuid, direct-syscall, and SIP-protected paths remain outside that boundary.

[MCP proxy →](https://docs.rampart.sh/features/mcp-proxy/) ·
[Any CLI agent →](https://docs.rampart.sh/integrations/any-cli-agent/) ·
[Threat model →](docs/THREAT-MODEL.md)

## What changed in 1.7

Rampart 1.7 binds approval state to the requesting credential, hardens MCP
correlation and destructive-command matching, unifies managed onboarding,
repairs owned service state safely, adds compatible Hermes native approval,
and reduces duplicated repository and CI maintenance surface.

Read the [changelog](CHANGELOG.md) for the full release notes.

## Documentation

- [Install and quick start](https://docs.rampart.sh/getting-started/quickstart/)
- [Integration support matrix](https://docs.rampart.sh/getting-started/support-matrix/)
- [Security assurance model](https://docs.rampart.sh/getting-started/security-assurance/)
- [Configuration](https://docs.rampart.sh/getting-started/configuration/)
- [CLI reference](https://docs.rampart.sh/reference/cli-commands/)
- [API reference](https://docs.rampart.sh/reference/api-reference/)
- [Threat model](docs/THREAT-MODEL.md)
- [Upgrade guide](https://docs.rampart.sh/getting-started/upgrade/)

## Contributing

Focused fixes, integration compatibility work, documentation improvements, and
security hardening are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md).

Please report suspected vulnerabilities privately through
[SECURITY.md](SECURITY.md), not a public issue.

## Companion project

[Snare](https://snare.sh) adds detective controls with canary credentials and
paths. Rampart blocks; Snare catches.

## License

[Apache 2.0](LICENSE)
