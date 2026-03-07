# OWASP Agentic Top 10 Mapping

This page maps Rampart's capabilities to the [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), the industry framework for autonomous AI agent security risks.

!!! note "Two different OWASP frameworks"
    OWASP maintains separate Top 10 lists for **LLM Applications** (2023-24) and **Agentic Applications** (2026). Rampart is a tool-call policy engine — the Agentic Applications list is the relevant framework. The LLM list covers model-level risks (training data poisoning, model theft, etc.) that are outside Rampart's scope.

## Coverage Matrix

| # | OWASP Agentic Risk | Rampart | Coverage |
|---|-------------------|---------|----------|
| ASI01 | **Agent Goal Hijack** | `watch-prompt-injection` policy monitors tool responses for injection patterns. Blocks injected commands via pattern matching. Does not prevent prompt-level goal manipulation — if an agent's goals are altered, Rampart limits what the hijacked agent can *do* but cannot detect the hijack itself. | ⚠️ Partial |
| ASI02 | **Tool Misuse and Exploitation** | Every tool call (exec, read, write, fetch, MCP) is evaluated against YAML policies before execution. `default_action: deny` enforces least-privilege. Parameter validation, command pattern matching, and approval workflows for sensitive operations. This is Rampart's core function. | ✅ Covered |
| ASI03 | **Identity and Privilege Abuse** | `agent_depth` conditions limit sub-agent privilege escalation. Self-modification protection blocks agents from running `rampart allow`/`rampart block`. User separation prevents agents from accessing policies/audit. Does not manage agent credentials, OAuth tokens, or delegated permissions — over-scoped keys are outside Rampart's scope. | ⚠️ Partial |
| ASI04 | **Agentic Supply Chain Vulnerabilities** | Community policy SHA-256 verification detects tampering after registry publication. `rampart mcp scan` auto-generates policy from MCP server tool definitions. Project-local policies enforce deny-wins (cannot weaken global policy). Does not verify tool provenance at source or provide SBOM/AIBOM. | ⚠️ Partial |
| ASI05 | **Unexpected Code Execution (RCE)** | Shell command normalization, interpreter one-liner blocking (`python3 -c`, `node -e`, `perl -e`), LD_PRELOAD cascade for subprocess interception, and pattern matching catch injected code before it runs. Optional LLM verification ([rampart-verify](https://github.com/peg/rampart-verify)) classifies ambiguous commands. | ✅ Covered |
| ASI06 | **Memory & Context Poisoning** | Response scanning (`response_matches`) blocks credentials and known-bad patterns in tool responses before they enter the agent's context window. Does not protect persistent memory stores, RAG databases, embeddings, or conversation history — Rampart operates at the tool call layer, not the memory layer. | ⚠️ Partial |
| ASI07 | **Insecure Inter-Agent Communication** | Not addressed. Rampart operates at the agent-to-OS boundary; it has no visibility into messages passed between agents in a multi-agent system. Does not provide mutual authentication, message signing, anti-replay, or encryption for agent-to-agent channels. Note: *tool calls* from sub-agents are evaluated by the same policy engine, and `agent_depth` conditions limit sub-agent nesting depth — but these address sub-agent containment, not communication security. | ❌ Not covered |
| ASI08 | **Cascading Failures** | Fail-open design prevents Rampart from becoming a single point of failure (a crashed Rampart doesn't lock out the system). `call_count` rate limiting throttles runaway agents. Webhook notifications alert on anomalies in real time. Does not prevent agent-to-agent cascade in multi-agent systems. | ⚠️ Partial |
| ASI09 | **Human-Agent Trust Exploitation** | `require_approval` and `ask` actions enforce human-in-the-loop gates for sensitive operations. HMAC-signed approval URLs provide authenticity. Full hash-chained audit trail enables post-hoc accountability. Does not detect persuasion attempts directed at the human approver or protect against over-reliance on agent output. | ⚠️ Partial |
| ASI10 | **Rogue Agents** | Self-modification protection prevents agents from weakening their own policy constraints (blocks `rampart allow`, `rampart block`, writes to `.rampart/`). Hash-chained audit trail makes rogue behavior detectable and verifiable. Response scanning catches credential exfiltration attempts. Does not detect agent misalignment, goal divergence, or colluding agents. | ⚠️ Partial |

**Summary: 2 fully covered, 7 partially mitigated, 1 not addressed.**

Rampart directly addresses the two risks most relevant to tool-call security (ASI02, ASI05) and partially mitigates seven others. The one architectural gap — inter-agent communication security (ASI07) — requires frameworks that provide agent-to-agent authentication and message signing, which is outside Rampart's scope as a tool-call policy engine.

## What Rampart Does Well

### ASI02: Tool Misuse and Exploitation

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

### ASI05: Unexpected Code Execution (RCE)

Pattern matching catches common injection vectors before execution:

- Direct destructive commands (`rm -rf`, `mkfs`, `dd if=`)
- Exfiltration attempts (`curl -X POST`, `wget --post-data`)
- Credential access (`cat ~/.ssh/*`, `cat .env`)
- Shell wrapper bypasses (quoted strings, compound commands, `eval`)
- Interpreter one-liners (`python3 -c`, `node -e`, `ruby -e`, `perl -e`)

LD_PRELOAD cascade (wrap/preload modes) intercepts subprocesses spawned by allowed commands. The optional [rampart-verify](https://github.com/peg/rampart-verify) sidecar adds LLM-based intent classification for ambiguous commands pattern matching can't catch.

See [Threat Model — Known Gaps](threat-model.md) for evasion techniques that pattern matching cannot catch (variable expansion, base64 payloads, native file I/O in subprocesses).

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

This is a partial mitigation for ASI06 (Memory & Context Poisoning) — it prevents known-bad patterns from entering context, but cannot protect against novel poisoning vectors, RAG corruption, or persistent memory stores that Rampart has no visibility into.

## What Rampart Does Not Do

**ASI03 — Identity and Privilege Abuse:** Rampart does not manage agent credentials. If an agent holds an over-scoped API key, Rampart cannot restrict which endpoints that key can access. Tools like [Astrix](https://astrix.security/) or cloud IAM policies are better suited for credential scoping and lifecycle management.

**ASI07 — Insecure Inter-Agent Communication:** Rampart operates at the agent-to-OS boundary. It has no visibility into messages passed between agents in a multi-agent system. Frameworks that provide agent-to-agent authentication, message signing, and replay protection are needed here. This is an architectural gap, not a missing feature — it would require Rampart to become a network-level proxy between agents rather than an OS-level policy engine.

## Further Reading

- [Threat Model](threat-model.md) — complete security analysis including known gaps and evasion techniques
- [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) — the official framework
- [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/) — the separate LLM-focused framework (covers model-level risks outside Rampart's scope)
