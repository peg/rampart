# OWASP Top 10 for Agentic AI

Rampart maps directly to the [OWASP Top 10 Risks for LLM-Powered Autonomous Agents](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/), published by the OWASP GenAI Security Project.

## Coverage Matrix

| # | OWASP Risk | Rampart Coverage | Status |
|---|-----------|-----------------|--------|
| 1 | **Excessive Agency** | Policy engine enforces least-privilege per tool call. `default_action: deny` restricts agents to only explicitly permitted operations. | ✅ Covered |
| 2 | **Unauthorized Tool Use** | Every tool call (exec, read, write, MCP) is evaluated against YAML policies before execution. Unknown tools are blocked by default in deny mode. | ✅ Covered |
| 3 | **Insecure Tool Implementation** | Response scanning (`response_matches`) blocks credential leaks in tool output before they reach the agent's context window. | ✅ Covered |
| 4 | **Prompt Injection → Tool Abuse** | Pattern matching catches injected commands. The `watch-prompt-injection` policy monitors tool responses for injection patterns and logs them for review. | ✅ Covered |
| 5 | **Insufficient Audit Trail** | Hash-chained JSONL audit logs — each entry cryptographically linked to the previous one. Tamper with any record and `rampart audit verify` detects it. Export to any SIEM via syslog (RFC 5424) or CEF. | ✅ Covered |
| 6 | **Data Exfiltration** | Domain blocking (`command_matches: "curl *evil*"`), credential pattern detection in commands and responses, and network logging policies. | ✅ Covered |
| 7 | **Uncontrolled Autonomy** | `require_approval` pauses agent execution and notifies humans via webhook (Discord, Slack). Commands stay blocked until explicitly approved or denied. | ✅ Covered |
| 8 | **Privilege Escalation** | Self-modification protection blocks agents from running `rampart allow`, `rampart block`, or modifying policy files. Agents cannot whitelist themselves. | ✅ Covered |
| 9 | **Supply Chain Compromise** | MCP proxy (`rampart mcp`) evaluates MCP tool calls against the same policy engine. Project-local policies (`.rampart/policy.yaml`) enforce deny-wins over global config. | ⚠️ Partial |
| 10 | **Cascading Failures** | Fail-open design prevents Rampart from becoming a single point of failure. If the policy engine is unreachable, agent operations continue normally. Configurable per deployment. | ⚠️ Partial |

## Response Scanning — OWASP Risk #3

Most security tools focus on blocking dangerous *commands*. Rampart also scans tool *responses* — this matters because:

1. Your agent runs `cat config.yaml` — a legitimate read
2. The file happens to contain `AWS_SECRET_ACCESS_KEY=AKIA...`
3. Without response scanning: the secret enters the agent's context window, available for exfiltration in a later turn
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

This is particularly important for [Prompt Injection](../guides/prompt-injection.md) scenarios where an attacker embeds instructions in a file that cause the agent to exfiltrate credentials it reads from other files.

## Self-Modification Protection — OWASP Risk #8

Rampart blocks agents from modifying their own constraints:

- `rampart allow` / `rampart block` — blocked when run by an agent
- `rampart serve stop` — blocked
- Direct policy file writes — blocked via file path policies
- `kill` / `pkill rampart` — blocked via command patterns

See the [Threat Model](threat-model.md#self-modification-protection) for details on how this is enforced and its limitations.

## Further Reading

- [Threat Model](threat-model.md) — complete security analysis including known gaps
- [Securing Claude Code](../guides/securing-claude-code.md) — hardening guide for `--dangerously-skip-permissions` mode
- [Prompt Injection Protection](../guides/prompt-injection.md) — detection and mitigation
- [Policy Engine](../features/policy-engine.md) — writing effective security policies
