---
title: Securing Claude Code — Complete Safety Guide
description: "Step-by-step guide to securing Claude Code with Rampart. Block dangerous commands, restrict file access, detect prompt injection, and keep audits."
---

# Securing Claude Code — Complete Safety Guide

Claude Code is a powerful AI coding agent, but `--dangerously-skip-permissions` mode — the mode most people use for autonomous work — gives it unrestricted shell access. This guide walks through securing Claude Code with Rampart so you get the productivity benefits without the risk.

## The Risk

Claude Code can execute shell commands, read files, and modify code across your workspace. In unrestricted mode, there is no built-in policy layer deciding whether an action is safe for your environment. If the model hallucinates or misinterprets context, harmful commands can run immediately.

Prompt injection is another practical risk. When Claude reads web pages or external tool output, malicious text can try to override the original task with instructions like exfiltrating secrets or running remote scripts. The agent cannot always distinguish trusted instructions from hostile content.

Accidental credential access is common in real repositories. Files such as `.env`, cloud credential files, and SSH keys may be reachable from normal tool calls. Without explicit policy, sensitive reads and follow-on network actions are easy to miss.

The goal is not to disable Claude Code automation. The goal is to add guardrails so dangerous actions are blocked, risky actions require review, and all activity is auditable.

## Quick Setup (2 minutes)

1. Install Rampart.

```bash
brew tap peg/rampart && brew install rampart
```

2. Wire Rampart into Claude Code.

```bash
rampart setup claude-code
```

3. Verify health and policy status.

```bash
rampart doctor
```

## What Gets Protected

| Tool type | Example | Policy coverage |
|-----------|---------|-----------------|
| `exec` | `rm -rf /`, `curl ... | bash` | Block destructive and remote execution patterns, allow safe commands, or require approval |
| `read` | `cat ~/.ssh/id_rsa`, `cat .env` | Deny sensitive paths and secret files, log policy matches |
| `write` | Editing `/etc/*` or production config | Enforce path rules, require approval for high-risk targets |
| `fetch` | Web content, API responses, MCP output | Monitor for prompt injection and suspicious exfiltration directives |

## Understanding the Standard Policy

Rampart's standard policy lives at `~/.rampart/policies/standard.yaml`. It includes high-signal deny rules for destructive commands and credential access, with monitoring rules for suspicious content patterns.

Policies are evaluated quickly and consistently on every tool call. You can inspect why a command was allowed or denied with:

```bash
rampart policy explain --tool exec --input 'rm -rf /'
```

Use `default_action` and explicit rule ordering to control strictness. In higher-security environments, set `default_action: deny` and add narrow allow rules.

## Customizing for Your Workflow

If a legitimate command gets blocked, add a targeted `allow` rule that is as specific as possible. Match by command prefix, working path, or repository scope instead of broad wildcards.

For operations that are valid but risky, use `require_approval` instead of unconditional allow. This keeps velocity while preserving human control over sensitive actions.

```yaml
- name: deploy-prod
  action: require_approval
  tool: exec
  match:
    command: kubectl apply -f prod/*.yaml
```

## Prompt Injection Protection

Rampart includes a `watch-prompt-injection` policy in the standard profile. It monitors tool responses for instruction-override patterns, exfiltration directives, and role-hijack attempts.

This matters for Claude Code because prompts are not the only input channel. Web pages, fetched docs, and MCP tool output can all carry hidden or explicit instructions intended to redirect the agent.

The default action is `watch` so you can see detections without breaking normal browsing and research workflows.

## Verifying It Works

Run these checks after setup:

```bash
rampart doctor
rampart watch
rampart test
```

Then trigger a known blocked command from Claude Code, such as `rm -rf /` in a test environment. Confirm you see a deny event and reason in `rampart watch` and the audit log.

## Common Questions

**Q: Will Rampart slow down Claude Code?**  
A: Policy evaluation takes under 10 microseconds. You will not notice it.

**Q: What if a legitimate command gets blocked?**  
A: Add an allow rule to your policy, or use require_approval so you decide per-instance.

**Q: Does this work with --dangerously-skip-permissions?**  
A: Yes — Rampart hooks into Claude Code's hook system, which operates independently of the permissions mode.

**Q: What if Rampart's service goes down?**  
A: Claude Code will warn that Rampart serve is unreachable. The hook currently falls back to asking Claude Code's native permission system.
