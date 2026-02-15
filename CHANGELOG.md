# Changelog

All notable changes to Rampart are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Fixed

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

[Unreleased]: https://github.com/peg/rampart/compare/v0.2.0...HEAD
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
