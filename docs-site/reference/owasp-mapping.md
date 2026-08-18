# OWASP Agentic Top 10 Mapping

This page maps Rampart's capabilities to the [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), the industry framework for autonomous AI agent security risks.

!!! note "Two different OWASP frameworks"
    OWASP maintains separate Top 10 lists for **LLM Applications** (2023-24) and **Agentic Applications** (2026). Rampart is a tool-call policy engine — the Agentic Applications list is the relevant framework. The LLM list covers model-level risks (training data poisoning, model theft, etc.) that are outside Rampart's scope.

## Coverage Matrix

| # | OWASP Agentic Risk | Rampart | Coverage |
|---|-------------------|---------|----------|
| ASI01 | **Agent Goal Hijack** | `watch-prompt-injection` policy monitors tool responses for injection patterns. Blocks injected commands via pattern matching. Does not prevent prompt-level goal manipulation — if an agent's goals are altered, Rampart limits what the hijacked agent can *do* but cannot detect the hijack itself. | ⚠️ Partial |
| ASI02 | **Tool Misuse and Exploitation** | Host-exposed calls on supported integrations are evaluated against YAML policies before execution. `default_action: deny`, parameter matching, and approval workflows support least privilege. Calls omitted by the host and behavior inside allowed processes are outside this boundary. | ⚠️ Partial |
| ASI03 | **Identity and Privilege Abuse** | `agent_depth` conditions can limit delegated calls observed by Rampart. The standard policy matches known Rampart mutation commands, and optional OS-user separation can keep policy/audit files outside the agent account. Rampart does not manage agent credentials, OAuth tokens, or delegated permissions. | ⚠️ Partial |
| ASI04 | **Agentic Supply Chain Vulnerabilities** | Community policy SHA-256 verification detects tampering after registry publication. Project-local policies enforce deny-wins (a project policy can tighten but not loosen global policy). Does not inspect MCP server tool definitions, verify tool provenance at source, inspect dependency trees, or provide SBOM/AIBOM. | ⚠️ Partial |
| ASI05 | **Unexpected Code Execution (RCE)** | Shell command normalization, interpreter one-liner blocking (`python3 -c`, `node -e`, `perl -e`), LD_PRELOAD cascade for subprocess interception, and pattern matching catch common injected code patterns before they run. Does not inspect code executed inside allowed interpreters (e.g., `python3 script.py`), cannot handle all obfuscation variants, and LD_PRELOAD cascade does not apply in native-hook mode (Claude Code, Cline, Codex, Cursor, experimental Gemini CLI, GitHub Copilot CLI / VS Code). See [Threat Model — Known Gaps](threat-model.md). | ⚠️ Partial |
| ASI06 | **Memory & Context Poisoning** | On supported post-tool boundaries, response scanning (`response_matches`) replaces matched string content before the next model turn. It does not protect persistent memory stores, RAG databases, embeddings, conversation history, unsupported response shapes, or tools without response hooks. | ⚠️ Partial |
| ASI07 | **Insecure Inter-Agent Communication** | Not addressed. Rampart operates at the agent-to-OS boundary; it has no visibility into messages passed between agents in a multi-agent system. Does not provide mutual authentication, message signing, anti-replay, or encryption for agent-to-agent channels. Note: *tool calls* from sub-agents are evaluated by the same policy engine, and `agent_depth` conditions limit sub-agent nesting depth — but these address sub-agent containment, not communication security. | ❌ Not covered |
| ASI08 | **Cascading Failures** | `call_count` rules can throttle observed repeated calls, and webhook notifications can report anomalies. Degraded behavior is integration- and configuration-specific: some sensitive paths deny, while configured lower-risk paths or host failures may proceed. Rampart does not prevent agent-to-agent cascades. | ⚠️ Partial |
| ASI09 | **Human-Agent Trust Exploitation** | `ask` actions enforce human-in-the-loop gates for sensitive operations where the active integration provides a safe approval boundary. HMAC-signed approval URLs provide authenticity. Full hash-chained audit trail enables post-hoc accountability. Does not detect persuasion attempts directed at the human approver or protect against over-reliance on agent output. | ⚠️ Partial |
| ASI10 | **Rogue Agents** | The standard policy matches known Rampart mutation commands and paths; hash chaining detects partial audit-log edits, and response scanning can catch configured patterns on supported hooks. Strong protection requires OS-user separation because an agent sharing the Rampart account may find unobserved mutation paths. Rampart does not detect misalignment, goal divergence, or collusion. | ⚠️ Partial |

**Summary: 9 partially mitigated, 1 not addressed.**

Tool misuse (ASI02) is Rampart's primary focus, but its coverage remains partial
because enforcement depends on the host exposing the action at a supported
boundary. Inter-agent communication security (ASI07) is not addressed.

## What Rampart Does Well

### ASI02: Tool Misuse and Exploitation (Partial)

This is Rampart's core purpose. Tool invocations exposed by a configured,
supported integration pass through the policy engine:

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

### ASI05: Unexpected Code Execution (RCE) (Partial)

Pattern matching catches common injection vectors before execution:

- Direct destructive commands (`rm -rf`, `mkfs`, `dd if=`)
- Exfiltration attempts (`curl -X POST`, `wget --post-data`)
- Credential access (`cat ~/.ssh/*`, `cat .env`)
- Shell wrapper bypasses (quoted strings, compound commands, `eval`)
- Interpreter one-liners (`python3 -c`, `node -e`, `ruby -e`, `perl -e`)

LD_PRELOAD cascade (preload mode) covers supported exec-family calls made
through the dynamic loader, but not static binaries or direct syscalls. The
[rampart-verify](https://github.com/peg/rampart-verify) project provides
experimental LLM-based intent classification for ambiguous commands — it is a
separate tool and not integrated into the standard Rampart distribution.

See [Threat Model — Known Gaps](threat-model.md) for evasion techniques that pattern matching cannot catch (variable expansion, base64 payloads, native file I/O in subprocesses).

## Response Scanning — ASI06

Most security tools focus on blocking dangerous *commands*. Rampart also scans tool *responses*:

1. Agent runs `cat config.yaml` — a legitimate read
2. The file contains `AWS_SECRET_ACCESS_KEY=AKIA...`
3. Without response scanning: the secret enters the agent's context window
4. With a supported post-tool hook and matching rule: Rampart replaces the
   matched response strings before the next model turn

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
