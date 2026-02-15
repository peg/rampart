# Rampart Roadmap to v1.0

## Current: v0.2.23 (6.5/10 completeness)

---

## Phase 1: Developer Experience (v0.3.x) — "Make it easy"
**Goal:** Lower friction for new users. Ship what makes people stay.
**Agent team:** 2-3 agents, ~1 session

### 1.1 Policy Test Framework
`rampart test my-policy.yaml` — write test cases inline or in a separate file:
```yaml
tests:
  - name: "blocks rm -rf"
    command: "rm -rf /"
    expect: deny
  - name: "allows git push"
    command: "git push origin main"
    expect: allow
  - name: "requires approval for deploy"
    command: "kubectl apply -f prod.yaml"
    expect: require_approval
```
**Files:** New `cmd/rampart/cli/test.go`, `internal/engine/testrunner.go`
**Effort:** Medium (1-2 agents, ~2h)

### 1.2 goreleaser → Homebrew Auto-Update
Add `brews:` section to `.goreleaser.yml` so every tagged release auto-pushes to `peg/homebrew-rampart`.
**Files:** `.goreleaser.yml`
**Effort:** Small (config change)

### 1.3 Metrics Endpoint
`GET /metrics` — Prometheus-compatible. Decisions/sec, latency histograms, deny/allow/approval counts, active approvals.
**Files:** `internal/proxy/metrics.go`, update `server.go`
**Effort:** Medium (1 agent)

### 1.4 Policy Linting
`rampart policy lint` — warn about:
- Unreachable rules (shadowed by earlier denies)
- Overly broad patterns (`**`)
- Missing `default_action`
- Glob patterns that could be evaded by shell metacharacters
**Files:** `internal/engine/lint.go`, `cmd/rampart/cli/policy.go`
**Effort:** Medium (1 agent)

---

## Phase 2: Security Hardening (v0.4.x) — "Close the gaps"
**Goal:** Address the known evasion vectors. Move from "good enough" to "serious."
**Agent team:** 2-3 agents

### 2.1 Shell-Aware Command Parsing
Replace raw glob matching with a shell tokenizer for `command_matches`:
- Parse quotes, escapes, variable references, pipes, subshells
- Match against normalized/tokenized command, not raw string
- Keep glob matching for backward compat, add `command_parsed_matches` for strict mode
**Files:** `internal/engine/shellparse.go`, `internal/engine/matcher.go`
**Effort:** High (1-2 agents, needs thorough testing)

### 2.2 Response-Side Scanning
Wire up response evaluation in Claude Code hooks (PostToolUse):
- Scan command output for secrets, credentials, sensitive data
- Block responses containing AWS keys, private keys, passwords
- Ship default response patterns in standard policy
**Files:** `cmd/rampart/cli/hook.go` (PostToolUse handler), policy templates
**Effort:** Medium (1 agent)

### 2.3 Single-Use Approval URLs
Track used HMAC signatures — once a signed URL resolves an approval, invalidate the signature.
**Files:** `internal/approval/store.go`, `internal/signing/`
**Effort:** Small (1 agent)

---

## Phase 3: Ecosystem (v0.5.x) — "Works everywhere"
**Goal:** Expand beyond the current integration surface.

### 3.1 Windows Support
- PowerShell shim for `rampart setup openclaw` on Windows
- Test hooks on Windows Claude Code
- CI: add windows to test matrix
**Effort:** High (needs Windows test environment)

### 3.2 MCP Agent Identity
Allow MCP clients to declare agent identity via headers or handshake. Validate against allowlist.
**Files:** `internal/mcp/proxy.go`
**Effort:** Small

### 3.3 Fleet Policy Server
Central HTTP endpoint that serves policies to multiple Rampart instances. `rampart serve --policy-url https://policies.internal/`.
**Files:** New `internal/policy/remote.go`
**Effort:** Medium

### 3.4 Webhook-Based Approval (Full Loop)
Discord/Slack bots that can approve/deny directly from message buttons. Cuts the AI out of the approval loop entirely.
**Files:** `internal/notify/discord_bot.go`, `internal/notify/slack_bot.go`
**Effort:** High

---

## Phase 4: Scale (v0.8.x → v1.0) — "Production-grade"

### 4.1 Policy Marketplace / Registry
`rampart policy install kubernetes` — pull community policies from a registry.
**Effort:** High (needs infrastructure)

### 4.2 Dashboard v2
Real-time web UI: decision stream, policy editor, approval queue, audit search.
**Effort:** High

### 4.3 Multi-Tenant
Per-user policies, RBAC, team management.
**Effort:** Very High

---

## Execution Priority (Next 2 Weeks)

### This week:
1. **Policy test framework** (highest impact for adoption — users need to validate their policies)
2. **goreleaser Homebrew auto-update** (5 min fix, saves manual work every release)
3. **Demo video** (marketing — biggest ROI right now)

### Next week:
4. **Shell-aware command parsing** (biggest security gap)
5. **Response-side scanning** (completes the story)
6. **Metrics endpoint** (needed before anyone runs this in prod)
7. **Policy linting** (quality of life)

### Agent Execution Plan:
Each item above maps to 1-3 sub-agents:
- **Policy test framework:** architect (design schema) + implementer (write code) + tester (write tests)
- **Shell parsing:** researcher (survey shell tokenizer libs in Go) + implementer + fuzzer
- **Response scanning:** implementer (hook wiring) + policy-writer (default patterns)
- **Metrics:** single agent (straightforward Prometheus handler)
- **Homebrew:** single agent (goreleaser config)
- **Linting:** single agent

Total: ~10-12 agent runs to ship Phase 1 + Phase 2 core items.
