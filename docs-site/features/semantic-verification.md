---
title: Semantic Verification
description: "Rampart adds optional LLM semantic verification for ambiguous AI agent commands. Combine fast rule matching with intent checks for safer automation."
---

# Semantic Verification

Pattern matching handles 95%+ of decisions instantly. For the ambiguous rest, Rampart supports LLM-based intent classification via the optional **rampart-verify** sidecar.

## The Problem

Pattern matching is fast and reliable for known-dangerous commands. But some commands are ambiguous:

- `python3 -c "import os; os.system('...')"` — dangerous or benign?
- `curl https://internal-api.company.com/admin` — legitimate or exfiltration?
- `find / -name "*.pem" -exec cat {} \;` — auditing or credential theft?

Static rules can't distinguish intent. An LLM can.

## Two-Layer Defense

| Layer | Speed | Cost | Handles |
|-------|-------|------|---------|
| Pattern matching | ~5μs | Free | Known patterns — destructive commands, credential paths, exfil domains |
| Semantic verification | ~500ms | ~$0.0001/call | Ambiguous commands — obfuscated payloads, encoded scripts, context-dependent intent |

Pattern matching fires first. If a command matches a `webhook` rule, it's forwarded to the sidecar. The LLM classifies intent and returns allow or deny. Everything else never touches the LLM.

## rampart-verify

[**rampart-verify**](https://github.com/peg/rampart-verify) is a standalone Python sidecar (FastAPI) that classifies commands using LLMs. It integrates with Rampart via the [`action: webhook`](webhooks.md) policy action.

### Features

- **Secret redaction** — API keys, tokens, passwords, and credentials are stripped before commands reach the LLM (13 pattern categories including AWS, Stripe, GitHub, OpenAI, bearer tokens, basic auth URLs)
- **Rate limiting** — Token bucket limiter, configurable via `VERIFY_RATE_LIMIT` (default: 60 req/min)
- **Decision logging** — Every classification logged to `~/.rampart/verify/decisions.jsonl` (append-only)
- **Health check** — `GET /health` pings the LLM provider and reports latency
- **Metrics** — `GET /metrics` returns request counts, allow/deny totals, average latency, uptime
- **Provider fallback** — If no API key is set for the requested model, falls back to Ollama (local, free)
- **Configurable prompt** — Override via `VERIFY_SYSTEM_PROMPT` or extend with `VERIFY_EXTRA_RULES`
- **Fail-open** — If the LLM is down or times out, commands are allowed (configurable)

### Supported Models

| Tier | Model | Latency | Cost |
|------|-------|---------|------|
| Free | `qwen2.5-coder:1.5b` (Ollama) | ~100-600ms | $0 |
| Budget | `gpt-4o-mini` (OpenAI) | ~400ms | ~$0.0001/call |
| Balanced | Claude Haiku (Anthropic) | ~500ms | ~$0.0003/call |

Any OpenAI-compatible API works (Together, Groq, local vLLM) via `OPENAI_BASE_URL`.

## Setup

### Install

```bash
git clone https://github.com/peg/rampart-verify.git
cd rampart-verify
pip install -r requirements.txt
```

### Configure Provider

**OpenAI (recommended):**

```bash
export VERIFY_PROVIDER=openai
export VERIFY_MODEL=gpt-4o-mini
export OPENAI_API_KEY=sk-...
```

**Fully offline with Ollama:**

```bash
export VERIFY_PROVIDER=ollama
export VERIFY_MODEL=qwen2.5-coder:1.5b
# Requires Ollama running locally: ollama serve
```

**Anthropic:**

```bash
export VERIFY_PROVIDER=anthropic
export VERIFY_MODEL=claude-3-haiku-20240307
export ANTHROPIC_API_KEY=sk-ant-...
```

### Start the Sidecar

```bash
python server.py --port 8090
```

Or with Docker Compose:

```bash
docker compose up -d
```

### Configure Rampart

Add a webhook rule to route ambiguous commands to the sidecar:

```yaml
policies:
  - name: semantic-verify
    match:
      tool: ["exec"]
    rules:
      - action: webhook
        when:
          command_matches:
            - "python3 -c *"
            - "python3 -m *"
            - "node -e *"
            - "eval *"
            - "base64 *"
        webhook:
          url: "http://localhost:8090/verify"
          timeout: 5s
          fail_open: true
```

## How It Works

```d2
direction: right

agent: "AI Agent" {shape: oval}
rampart: "Rampart
Policy Engine" {
  style.fill: "#1d3320"; style.stroke: "#2ea043"; style.font-color: "#3fb950"; style.border-radius: 8
}

allow: "Execute" {
  style.fill: "#1d3320"; style.stroke: "#2ea043"; style.font-color: "#3fb950"; style.border-radius: 6
}
deny: "Blocked" {
  style.fill: "#2d1b1b"; style.stroke: "#da3633"; style.font-color: "#f85149"; style.border-radius: 6
}

verify: {
  label: "rampart-verify sidecar"
  style.stroke-dash: 4
  style.border-radius: 8

  redact: "Redact secrets
from command" {style.border-radius: 6}
  llm: "LLM
(gpt-4o-mini / Haiku / Ollama)" {style.border-radius: 6}

  redact -> llm: "sanitized command"
}

approval: "Human Approval" {
  style.fill: "#2d2508"; style.stroke: "#d29922"; style.font-color: "#d29922"; style.border-radius: 6
}

audit: "Audit Trail" {shape: cylinder}

agent -> rampart: "tool call"
rampart -> allow: "clear allow"
rampart -> deny: "clear deny"
rampart -> verify.redact: "ambiguous / webhook"

verify.llm -> allow: "ALLOW"
verify.llm -> deny: "DENY"
verify.llm -> approval: "ESCALATE"

rampart -> audit
allow -> audit
deny -> audit
approval -> audit
```

1. Agent executes a command → Rampart evaluates policies
2. If a `webhook` rule matches → command is forwarded to rampart-verify
3. rampart-verify **redacts secrets** from the command
4. The redacted command is sent to the configured LLM
5. LLM classifies intent → returns ALLOW or DENY with reason
6. rampart-verify returns the decision to Rampart
7. The full (unredacted) command and decision are logged to Rampart's audit trail

## Secret Redaction

Commands are sanitized before reaching the LLM. The sidecar strips:

- AWS access keys and secrets
- Stripe live/test keys
- OpenAI, Anthropic, and generic API keys
- GitHub personal access tokens
- Bearer and Authorization headers
- Basic auth credentials in URLs
- Hex tokens (40+ characters)
- Base64 blobs in header values

Example:

```
Input:  curl -H "Authorization: Bearer sk-proj-abc123..." https://api.example.com
Sent:   curl -H "Authorization: Bearer [REDACTED]" https://api.example.com
```

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/verify` | POST | Main classification endpoint (called by Rampart webhook) |
| `/health` | GET | Health check — pings LLM provider, reports latency |
| `/metrics` | GET | Request counts, allow/deny totals, avg latency, uptime |
| `/` | GET | Service info and configured model |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VERIFY_MODEL` | `gpt-4o-mini` | LLM model to use |
| `VERIFY_PORT` | `8090` | Server port |
| `VERIFY_HOST` | `127.0.0.1` | Bind address |
| `VERIFY_RATE_LIMIT` | `60` | Max requests per minute |
| `VERIFY_LOG_DIR` | `~/.rampart/verify` | Log and decision file directory |
| `VERIFY_SYSTEM_PROMPT` | (built-in) | Override the entire system prompt |
| `VERIFY_EXTRA_RULES` | (none) | Append additional rules to the default prompt |
| `OPENAI_API_KEY` | — | OpenAI API key |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | Custom OpenAI-compatible endpoint |
| `ANTHROPIC_API_KEY` | — | Anthropic API key |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama server URL |

## Running as a Service

### systemd (Linux)

```bash
cat > ~/.config/systemd/user/rampart-verify.service << 'EOF'
[Unit]
Description=Rampart Verify Sidecar
After=network.target

[Service]
WorkingDirectory=/path/to/rampart-verify
ExecStart=/usr/bin/python3 server.py
Restart=on-failure
EnvironmentFile=%h/.rampart-verify.env

[Install]
WantedBy=default.target
EOF

systemctl --user enable --now rampart-verify
```

Store your API key in `~/.rampart-verify.env`:

```
VERIFY_MODEL=gpt-4o-mini
OPENAI_API_KEY=sk-...
```

!!! warning "Permissions"
    Set `chmod 600 ~/.rampart-verify.env` — this file contains your API key.

## Security Notes

- The sidecar binds to `127.0.0.1` by default — not accessible from the network
- There is no authentication on sidecar endpoints. On shared machines, use a firewall or bind to a Unix socket
- Secret redaction is best-effort — custom secret formats may not be caught. Add patterns via `VERIFY_EXTRA_RULES` or contribute to `redact.py`
- The LLM never sees actual secret values, only the command structure
