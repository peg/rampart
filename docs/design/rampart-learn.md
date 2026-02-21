# Design: `rampart learn` — Policy Discovery from Observed Agent Behavior

**Status:** Proposal  
**Target release:** v0.5.x  
**Author:** Clap (subagent research)

---

## Problem

The #1 adoption friction for Rampart is the blank-page policy problem: users don't know what glob patterns to write. They copy `standard.yaml`, maybe trim a few rules, and ship it — leaving gaps that block legitimate agent behavior or over-permitting things they'd want to watch.

**Solution:** Watch what the agent actually does. Suggest the allow-rules it needs.

```bash
rampart learn -- claude        # runs claude, observes, outputs suggested YAML
rampart learn -- codex exec 'fix the bug in auth.py'
```

---

## Approach Evaluation

### Option A: strace/syscall tracing

Run the agent under `strace -f` (Linux) or `dtrace` (macOS), capture every `open(2)`, `execve(2)`, `connect(2)` syscall.

**Pros:**
- Complete visibility — nothing the agent does can hide from the kernel
- Catches behavior that bypasses Rampart's intercept layer

**Cons:**
- Requires platform-specific tools (`strace` not on macOS without SIP disabled)
- Enormously noisy — thousands of libc/runtime syscalls per agent call
- Hard to map syscalls → Rampart's policy schema (`exec`, `read`, `write`, `fetch`)
- Architecturally inconsistent: Rampart protects at the tool-call level; learn should match that abstraction
- No precedent in the codebase; would require significant new infrastructure

**Verdict: Skip.** The signal-to-noise ratio is terrible, and we'd be building a tool that observes at a different layer than what we enforce.

### Option B: Audit-log analysis (recommended)

Run the agent through the existing `wrap` infrastructure in `monitor` mode (allow-all, full audit logging), then analyze the resulting `audit.Event` JSONL stream to generate policy suggestions.

**Pros:**
- Reuses existing `wrap` + `proxy` + audit infrastructure entirely
- Events are already structured: tool type, command, path, URL, agent, session
- Stays at exactly the right abstraction level (same events the policy engine evaluates)
- Cross-platform — works on Linux, macOS, Windows
- Zero new external dependencies

**Cons:**
- Can only see what Rampart intercepts (tool calls). Won't catch activity that bypasses the shim. Acceptable for the use case.
- Requires the agent session to actually exercise the code paths you care about. Incomplete sessions give incomplete suggestions.

**Verdict: This is the right approach.**

### Does `action: log` already exist?

Yes, as a deprecated alias. `engine/policy.go: ParseAction()`:
```go
case "watch", "log": // "log" kept as deprecated alias
    return ActionWatch, nil
```

`ActionWatch` allows the call but surfaces it in the dashboard. For `learn` mode we need something different: **all policies are suspended** (or a fully permissive policy is loaded), and all events are logged. The `wrap --mode=monitor` flag already does exactly this — it evaluates policies but doesn't enforce denials. We'll build `learn` on top of it.

---

## Architecture

### Command flow

```
rampart learn -- claude
       │
       ▼
1. LearnCmd bootstraps:
   - Temp audit dir: /tmp/rampart-learn-<ulid>/
   - Load embedded yolo.yaml (allow-everything policy)
   - Spin up proxy in monitor mode (from wrap infrastructure)
   - Set RAMPART_LEARN=1 in child env
       │
       ▼  
2. Run agent (args[0]...) as child process
   - Same env injection as wrap: SHELL=shim, PATH=shimdir:..., RAMPART_PROXY=...
   - All exec/read/write/fetch calls flow through proxy → audit JSONL
       │
       ▼
3. Agent exits (or user hits Ctrl+C)
   - Flush audit sink
   - Display progress: "Observed N tool calls. Analyzing..."
       │
       ▼
4. internal/learn.Analyzer{}.Analyze(events []audit.Event)
   - Group events by tool type
   - Extract patterns per tool
   - Deduplicate + generalize
   - Flag sensitive accesses (warn, don't suggest allowing)
   - Score/rank suggestions by frequency
       │
       ▼
5. Format suggestions as valid rampart.yaml policies
   - Print to stdout with commentary
   - Write to ./rampart-learn.yaml (mergeable fragment)
   - Print apply instructions
```

### Key source locations (by analogy)

| File | Role |
|------|------|
| `cmd/rampart/cli/wrap.go` | **Template** — learn reuses ~80% of this setup |
| `cmd/rampart/cli/learn.go` | **New** — cobra command wiring, ~150 lines |
| `internal/learn/analyzer.go` | **New** — core analysis logic, ~350 lines |
| `internal/learn/patterns.go` | **New** — pattern extraction + generalization, ~200 lines |
| `internal/learn/formatter.go` | **New** — YAML output, ~120 lines |
| `internal/audit/reader.go` | **Existing** — `ReadEventsFromOffset` reads the JSONL stream |
| `internal/audit/event.go` | **Existing** — `audit.Event` is the input to analysis |
| `policies/yolo.yaml` | **Existing** — loaded as the no-enforcement policy |

### `internal/learn/analyzer.go`

```go
package learn

import (
    "github.com/peg/rampart/internal/audit"
    "github.com/peg/rampart/internal/engine"
)

// Analyzer processes audit events from a learn session and produces
// suggested policy additions.
type Analyzer struct {
    // MinFrequency is the minimum number of times a pattern must appear
    // before it's suggested. Default: 1.
    MinFrequency int
    
    // SensitivePaths is a list of glob patterns. Events matching these
    // paths are flagged as warnings rather than suggested as allows.
    // Populated from standard.yaml block-credential-access paths.
    SensitivePaths []string
    
    // Generalize controls whether paths/commands are abstracted into globs.
    // Default: true.
    Generalize bool
}

// Suggestions is the output of Analyze().
type Suggestions struct {
    ExecPatterns    []PatternEntry // suggested command_matches globs
    ReadPatterns    []PatternEntry // suggested path_matches globs for "read"
    WritePatterns   []PatternEntry // suggested path_matches globs for "write", "edit"
    FetchPatterns   []PatternEntry // suggested domain_matches globs for "fetch"
    Warnings        []Warning      // sensitive paths accessed — don't auto-allow
    Stats           SessionStats
}

type PatternEntry struct {
    Pattern   string
    Count     int     // times observed
    Examples  []string // up to 3 raw values that matched
}

type Warning struct {
    Tool    string
    Raw     string  // the actual path/command seen
    Reason  string  // e.g. "matches credential path pattern"
}

type SessionStats struct {
    TotalEvents   int
    ByTool        map[string]int
    Duration      time.Duration
    Agent         string
    Session       string
}

func (a *Analyzer) Analyze(events []audit.Event) *Suggestions { ... }
```

### `internal/learn/patterns.go` — Pattern extraction logic

**Exec commands:**
1. Extract binary (first token): `git`, `npm`, `python3`, `curl`
2. Generate glob: `git *`, `npm *`, `python3 *`
3. For known-safe no-arg commands (`pwd`, `echo`, `true`, `false`), add exact match
4. Collapse: if `git status`, `git diff`, `git log` all appear → suggest `git *`
5. Skip: `rm`, `curl *|*`, `sudo *` — these are covered by standard.yaml deny rules; flag as "standard.yaml already handles this"

**Read/Write paths:**
1. Check against sensitive path list → emit Warning instead of PatternEntry
2. Generalize by extension: `/home/user/project/src/auth.py` → `**/*.py`
3. Keep project-relative patterns: `src/**`, `tests/**` (detect common prefixes)
4. Special cases: `package.json`, `pyproject.toml` → exact name match pattern `**/package.json`
5. Deduplicate: if 50 different `.py` files → single `**/*.py` entry

**Fetch domains:**
1. Extract domain from URL
2. Generalize subdomains: `api.github.com`, `raw.githubusercontent.com` → `*.github.com` + `*.githubusercontent.com`
3. Flag known public services (pypi.org, npmjs.com, github.com) with a note: "standard allow-list rule may already cover this"

### Deduplication/filtering rules

```
FILTER OUT (don't suggest allowing):
  - Commands matching existing standard.yaml deny rules
  - Paths matching standard.yaml block-credential-access paths
  - Domains matching block-exfil-domains patterns
  
COLLAPSE:
  - Same binary, different args → `binary *`
  - Same extension, different directories → `**/*.ext`
  - Same parent directory, many files → `parent-dir/**`
  
EMIT AS-IS (no generalization):
  - Exact short commands: `pwd`, `echo`, `ls`
  - Config file names: `package.json`, `tsconfig.json`
  
WARN (don't suggest, but report):
  - Any access to ~/.ssh/**, ~/.aws/**, ~/.env, ~/.kube/config, etc.
  - Any exec matching reverse-shell patterns
  - Any fetch to exfil domains (already blocked, but notable)
```

---

## UX Design

### Terminal output

```
$ rampart learn -- claude

🎓  rampart learn: Starting observation session
    Policy: allow-all (monitor mode — nothing will be blocked)
    Audit:  /tmp/rampart-learn-01JNXYZ/audit.jsonl

[claude runs normally — all output passes through]

^C   (or agent exits naturally)

📊  Analyzing 47 tool calls over 3m 12s...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  rampart learn — Suggested policy additions
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  📂 exec   23 commands → 6 patterns
  📄 read   18 paths    → 4 patterns
  ✏️  write   6 paths    → 2 patterns
  🌐 fetch   3 URLs     → 2 domains

  ⚠️  2 WARNINGS (sensitive paths accessed — review before allowing):
    • read ~/.env         (matches credential pattern — use require_approval instead?)
    • read ~/.ssh/id_rsa  (blocked by standard.yaml — investigate why agent needed this)

Written to: ./rampart-learn.yaml

To apply:
  cp rampart.yaml rampart.yaml.bak
  cat rampart-learn.yaml >> rampart.yaml
  rampart test
  rampart lint

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Generated `rampart-learn.yaml`

```yaml
# Generated by: rampart learn -- claude
# Generated at: 2026-02-21T06:07:00Z
# Session duration: 3m 12s  |  Tool calls: 47
#
# REVIEW BEFORE APPLYING:
#   - Remove patterns you don't want to allow
#   - Sensitive path warnings are NOT included (see terminal output)
#   - Run `rampart test` after merging to validate
#
# To merge:  cat rampart-learn.yaml >> rampart.yaml

  - name: learned-exec
    priority: 50          # higher priority than standard.yaml (default 100)
    match:
      tool: ["exec"]
    rules:
      - action: allow
        when:
          command_matches:
            - "git *"               # 8 observed (git status, git diff, git commit...)
            - "npm *"               # 6 observed (npm install, npm run build...)
            - "python3 *"           # 5 observed
            - "node *"              # 2 observed
            - "ls *"                # 2 observed
        message: "Learned from agent session (rampart learn)"

  - name: learned-read
    priority: 50
    match:
      tool: ["read"]
    rules:
      - action: allow
        when:
          path_matches:
            - "**/*.py"             # 9 observed
            - "**/*.js"             # 5 observed
            - "**/*.json"           # 3 observed (package.json, tsconfig.json...)
            - "**/*.md"             # 1 observed
        message: "Learned from agent session (rampart learn)"

  - name: learned-write
    priority: 50
    match:
      tool: ["write", "edit"]
    rules:
      - action: allow
        when:
          path_matches:
            - "**/*.py"             # 4 observed
            - "**/*.js"             # 2 observed
        message: "Learned from agent session (rampart learn)"

  - name: learned-fetch
    priority: 50
    match:
      tool: ["fetch"]
    rules:
      - action: allow
        when:
          domain_matches:
            - "*.github.com"        # 2 observed
            - "pypi.org"            # 1 observed
        message: "Learned from agent session (rampart learn)"

# ──────────────────────────────────────────────────────────────────────
# WARNINGS — These were observed but NOT added to the allow list.
# Review these manually:
#
#   read ~/.env          → 1 observed
#     Reason: matches credential path (standard.yaml blocks this by default)
#     Consider: action: require_approval with appropriate message
#
#   read ~/.ssh/id_rsa   → 1 observed
#     Reason: matches SSH key pattern (standard.yaml blocks this by default)
#     Consider: investigating why the agent needed this
# ──────────────────────────────────────────────────────────────────────
```

---

## Command flags

```
rampart learn [flags] -- <command> [args...]

Flags:
  --output string       Output file for policy fragment (default: ./rampart-learn.yaml)
  --min-frequency int   Minimum observations before suggesting (default: 1)
  --no-generalize       Emit exact patterns, don't generalize to globs
  --audit-dir string    Directory for raw audit log (default: temp dir, deleted after)
  --keep-audit          Don't delete audit log after analysis
  --format text|yaml    Output format (default: text with embedded yaml)
  --agent string        Agent identity label (default: "learned")
  --append              Append to existing --output file instead of overwriting
```

---

## Integration with existing `wrap` infrastructure

`learn` is implemented as a thin wrapper around `wrap`:

1. **Policy override**: Before starting, write a temp `rampart-yolo.yaml` (allow-all) and pass `--config` pointing to it. This ensures all events are logged without any denials.

2. **Mode**: Always `--mode=monitor`. Even if the yolo policy somehow matched a deny, monitor mode prevents enforcement.

3. **Audit dir**: Temp dir created by `learn`, deleted after analysis (unless `--keep-audit`).

4. **Child process**: Identical to `wrap` — injects shim, sets env vars.

5. **Post-exit hook**: `learn` calls `analyzer.Analyze()` on the accumulated events, then formats and writes the output. The wrap infrastructure's exit flow already handles summary printing; `learn` replaces that with the analysis output.

The key change is that wrap's `decisionCounterSink` gets wrapped by a `learningCollectorSink` that accumulates all events in memory for post-run analysis.

```go
// In learn.go RunE:
collectSink := &learn.CollectorSink{}  // wraps the JSONL sink
// ... (rest of wrap setup) ...
// After child.Wait():
events := collectSink.Events()
suggestions := analyzer.Analyze(events)
formatter.Write(cmd.OutOrStdout(), suggestions)
```

---

## What we can't learn (known gaps)

| Gap | Reason | Mitigation |
|-----|--------|-----------|
| MCP tool parameters beyond what the proxy sees | MCP proxy logs tool name + params, should be fine | Already in audit.Event.Request |
| Node.js FS calls via preload hook | `preload` uses a JS hook, not the shim | Note in output: "run with `rampart preload` if using MCP" |
| Agent behavior in future sessions | Session coverage depends on what the user exercises | Suggest running a representative task |
| Adversarial agent behavior | Learn from the "good path"; attacker can still deviate | This is by design — learn is for legit policy, not security |

---

## Complexity estimate

| Component | Complexity | LOC estimate |
|-----------|------------|-------------|
| `cmd/rampart/cli/learn.go` | Low — thin over wrap | ~200 |
| `internal/learn/analyzer.go` | Medium — grouping + filtering logic | ~350 |
| `internal/learn/patterns.go` | Medium — glob generalization heuristics | ~250 |
| `internal/learn/formatter.go` | Low — YAML template rendering | ~150 |
| Tests | Medium | ~400 |
| **Total** | **Medium** | **~1350** |

**Time estimate:** 2 sprints (3–4 weeks) for a solid shippable feature.
- Sprint 1: Core infrastructure (CollectorSink, Analyzer, basic patterns)
- Sprint 2: Heuristics, formatter, UX polish, tests

---

## Phasing — what's buildable near-term

### v0.5.0 (MVP, 2-3 weeks)
- Core learn command wiring (wrap infrastructure reuse)
- Binary-based exec pattern extraction (`git *`, `npm *`)
- Extension-based path pattern extraction (`**/*.py`)
- Domain extraction for fetch calls
- Basic deduplication
- Sensitive-path warning system (cross-reference standard.yaml patterns)
- Simple YAML output to file

### v0.5.x (follow-up)
- Smarter glob generalization (project-relative paths, common prefix detection)
- `--append` mode: merge learned rules into an existing `rampart.yaml`
- Integration with `rampart test`: run test cases against learned policy to verify it doesn't over-allow
- `rampart learn --analyze <audit-file>`: analyze an existing audit log without running a new session (useful for CI analysis of recorded sessions)

### Deferred
- Interactive TUI: show each suggested rule, approve/reject individually
- Policy diffing: compare learned patterns against current policy to find gaps
- Periodic learning: auto-run `learn` in CI and open a PR with policy updates

---

## Security considerations

1. **Learn mode is not security**: The output of `rampart learn` is an allowlist that will **reduce** enforcement. Users must understand they're creating a whitelist, not a blacklist. The output should prominently say "REVIEW BEFORE APPLYING."

2. **Sensitive path warnings**: Before emitting any `path_matches` rule, cross-reference against the `block-credential-access` pattern list from `standard.yaml`. Never auto-suggest allowing credentials.

3. **The learned policy is not your security policy**: It's a convenience tool for bootstrapping. For production, users should layer `standard.yaml` on top of learned rules (standard.yaml denial rules have priority=100, learned rules at priority=50 are evaluated first — if learn says allow but standard says deny, deny wins because deny-wins semantics apply across all matched policies).

4. **Audit log sensitivity**: The raw audit log written during learning may contain paths, commands, or URL parameters. Temp dir is deleted by default; `--keep-audit` requires explicit opt-in with a warning.
