---
title: Local Models
description: Start Claude Code, Codex or OpenCode on a local model (Ollama, llama.cpp, LM Studio) with Rampart protection verified first.
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

## llama.cpp, LM Studio, and other servers

Pass the server's URL with `--base-url` to skip Ollama:

```bash
# llama.cpp: llama-server --jinja -m model.gguf --port 8080
rampart launch claude --base-url http://127.0.0.1:8080 --model local
rampart launch codex --base-url http://127.0.0.1:8080 --model local

# LM Studio's local server
rampart launch codex --base-url http://127.0.0.1:1234 --model qwen3-coder
```

- Claude Code needs a server that speaks the Anthropic Messages API
  (`/v1/messages`), as llama.cpp's `llama-server` does. Check that your
  server offers it.
  Launch sets `ANTHROPIC_BASE_URL` and a placeholder token, and clears
  `ANTHROPIC_API_KEY` for the agent so a real key is never sent to the
  local server.
- Codex needs the OpenAI Responses API (`/v1/responses`). Launch adds a
  `local` model provider for this run only, with `-c` flags, and leaves your
  `config.toml` unchanged.
- llama.cpp needs `--jinja` for tool calls. Some models' chat templates reject
  Codex's second system message; use the model's tool-calling template if you
  see an HTTP 500.
- OpenCode reads its provider from `opencode.json`, so `--base-url` is not
  supported there. Add an OpenAI-compatible provider in OpenCode, then run
  `opencode` as usual.

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
   `codex --oss [-m <name>]`. With `--base-url`, launch starts the agent
   directly against that server.

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
