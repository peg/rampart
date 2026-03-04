# OWASP Agentic Top 10 Mapping

This page maps Rampart's capabilities to the [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), the industry framework for autonomous AI agent security risks.

!!! note "Two different OWASP frameworks"
    OWASP maintains separate Top 10 lists for **LLM Applications** (2023-24) and **Agentic Applications** (2026). Rampart is a tool-call policy engine — the Agentic Applications list is the relevant framework. The LLM list covers model-level risks (training data poisoning, model theft, etc.) that are outside Rampart's scope.

## Coverage Matrix

| # | OWASP Agentic Risk | Rampart | Coverage |
|---|-------------------|---------|----------|
| ASI01 | **Agent Goal Hijack** | `watch-prompt-injection` policy monitors tool responses for injection patterns. Blocks injected commands via pattern matching. Does not prevent prompt-level goal manipulation. | ⚠️ Partial |
| ASI02 | **Tool Misuse & Exploitation** | Every tool call (exec, read, write, MCP) is evaluated against YAML policies before execution. `default_action: deny` enforces least-privilege. This is Rampart's core function. | ✅ Covered |
| ASI03 | **Identity & Privilege Abuse** | Self-modification protection blocks agents from running `rampart allow`/`rampart block`. Does not manage agent credentials, OAuth tokens, or delegated permissions. | ⚠️ Partial |
| ASI04 | **Agentic Supply Chain** | MCP proxy (`rampart mcp`) evaluates MCP tool calls against policies. Project-local policies enforce deny-wins. Does not verify tool provenance or integrity. | ⚠️ Partial |
| ASI05 | **Unexpected Code Execution** | Exec policy evaluation catches injected code before it runs. Pattern matching blocks destructive commands, obfuscated payloads (with [known limitations](threat-model.md)). | ✅ Covered |
| ASI06 | **Memory & Context Poisoning** | Response scanning (`response_matches`) blocks credentials and known-bad patterns in tool responses before they enter the agent's context window. Does not protect persistent memory stores, RAG databases, or conversation history. | ⚠️ Partial |
| ASI07 | **Insecure Inter-Agent Communication** | Not addressed. Rampart sits between an agent and the OS/tools, not between agents. | ❌ Not covered |
| ASI08 | **Cascading Failures** | Fail-open design prevents Rampart from becoming a single point of failure. Does not prevent agent-to-agent cascade in multi-agent systems. | ⚠️ Partial |
| ASI09 | **Human-Agent Trust Exploitation** | `require_approval` adds human-in-the-loop gates for sensitive operations. Does not detect persuasion attempts or over-reliance on agent output. | ⚠️ Partial |
| ASI10 | **Rogue Agents** | Self-modification protection prevents agents from weakening their own policy constraints. Does not detect agent misalignment or goal divergence. | ⚠️ Partial |

**Summary: 2 fully covered, 6 partially mitigated, 2 not addressed.**

Rampart directly addresses the two risks most relevant to tool-call security (ASI02, ASI05) and partially mitigates six others. The two gaps — identity/credential management (ASI03) and inter-agent communication (ASI07) — are architecturally outside Rampart's scope as a tool-call policy engine.

## What Rampart Does Well

### ASI02: Tool Misuse & Exploitation

This is Rampart's core purpose. Every tool invocation passes through the policy engine:

```yaml
# Allowlist mode — only explicitly permitted commands run
version: "1"
default_action: deny

policies:
  - name: allow-dev-tools
    match:
      tool: [exec]
    rules:
      - action: allow
        when:
          command_matches: "npm *"
      - action: allow
        when:
          command_matches: "go test *"
      # Everything else: denied by default
```

### ASI05: Unexpected Code Execution

Pattern matching catches common injection vectors before execution:

- Direct destructive commands (`rm -rf`, `mkfs`, `dd if=`)
- Exfiltration attempts (`curl -X POST`, `wget --post-data`)
- Credential access (`cat ~/.ssh/*`, `cat .env`)
- Shell wrapper bypasses (quoted strings, compound commands, `eval`)

See [Threat Model — Known Gaps](threat-model.md) for evasion techniques that pattern matching cannot catch (variable expansion, base64 payloads).

## Response Scanning — ASI06

Most security tools focus on blocking dangerous *commands*. Rampart also scans tool *responses*:

1. Agent runs `cat config.yaml` — a legitimate read
2. The file contains `AWS_SECRET_ACCESS_KEY=AKIA...`
3. Without response scanning: the secret enters the agent's context window
4. With Rampart: the response is blocked before the agent ever sees it

```yaml
- name: block-credential-leak
  match:
    tool: [read, exec]
  rules:
    - action: deny
      when:
        response_matches: "AWS_SECRET_ACCESS_KEY|PRIVATE KEY|ghp_"
```

This is a partial mitigation for ASI06 (Memory & Context Poisoning) — it prevents known-bad patterns from entering context, but cannot protect against novel poisoning vectors or persistent memory corruption.

## What Rampart Does Not Do

**ASI03 — Identity & Privilege Abuse:** Rampart does not manage agent credentials. If an agent holds an over-scoped API key, Rampart cannot restrict which endpoints that key can access. Tools like [Astrix](https://astrix.security/) or cloud IAM policies are better suited for this.

**ASI07 — Insecure Inter-Agent Communication:** Rampart operates at the agent-to-OS boundary. It has no visibility into messages passed between agents in a multi-agent system. Frameworks that provide agent-to-agent authentication and message signing are needed here.

## Further Reading

- [Threat Model](threat-model.md) — complete security analysis including known gaps and evasion techniques
- [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) — the official framework
- [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/) — the separate LLM-focused framework (covers model-level risks outside Rampart's scope)
