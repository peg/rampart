---
title: Local Models
description: Start Claude Code, Codex or OpenCode on a local Ollama model with Rampart protection verified first.
---

# Local Models

Local models are more easily steered by prompt injection and more likely to
emit surprising tool calls than hosted models with built-in safety
classifiers. `rampart launch` gives you one command to a protected local-model
agent:

```bash
rampart launch claude --model qwen3-coder
rampart launch codex --model gpt-oss:20b
rampart launch opencode --model qwen3-coder
rampart launch claude --model qwen3-coder -- -p "explain this repo"   # args after -- go to the agent
```

Supported agents: `claude` (Claude Code), `codex`, and `opencode` (Linux and
macOS; see [OpenCode](opencode.md) for its limits).

## What it does

1. **Protects the agent.** If Rampart's hooks are not installed for the agent,
   launch installs the managed Guard policy and the agent's native hooks, the
   same as `rampart protect <agent>`.
2. **Verifies, fail closed.** It starts the local policy service if needed and
   runs the same safe canaries as `rampart verify <agent>`. No action is
   executed and no model is invoked. If any check fails or cannot be verified,
   the agent is **not** started and launch exits with status 1.
3. **Starts the agent.** With [Ollama](https://ollama.com) on `PATH`, launch
   runs `ollama launch <agent> [--model <name>] [-- args]`, which points the
   agent at your local Ollama server. Without Ollama, Codex falls back to
   `codex --oss [-m <name>]`; Claude Code and OpenCode require Ollama.

The agent's exit status becomes `rampart launch`'s exit status.

## Limits

- Verification proves the hooks are configured and the Rampart adapter
  answers correctly. It cannot see whether the running agent loaded them.
  Codex additionally requires you to trust the hook once in `/hooks`; see
  [Codex](codex-cli.md).
- Rampart enforces policy on tool calls; it does not inspect model output or
  filter prompts.
- Models with a `:cloud` suffix run on Ollama's servers, not locally.

Try the canary after starting: ask the agent to run `echo rampart-canary`.
Rampart denies it. If it just prints `rampart-canary`, the hook is not active.
