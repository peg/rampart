# Changelog

All notable changes to Rampart are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0-rc.2] - 2026-05-04

### Fixed

- **Doctor no longer suggests downgrading prerelease builds** — `rampart doctor` now uses SemVer-aware prerelease comparison for update hints, so `v1.0.0-rc.1`/`v1.0.0-rc.2` do not report stable `v0.9.22` as an available upgrade.

### Changed

- **OpenClaw plugin metadata now matches the RC.2 release** — The embedded plugin manifest, runtime export, and package metadata are versioned as `1.0.0-rc.2`.

## [1.0.0-rc.1] - 2026-05-03

### Added

- **OpenClaw 2026.5.2 release-candidate baseline** — Native OpenClaw plugin approvals are now the supported RC path: OpenClaw owns visible approval UI/state, while Rampart owns policy evaluation, audit, and durable allow-always persistence.
- **OpenClaw plugin contract regression coverage** — The embedded plugin now has tests for manifest activation metadata, package install metadata, gateway status response shape, approval behavior, degraded-mode behavior, and version coherence.
- **RC readiness documentation for public support boundaries** — The support matrix and OpenClaw integration docs now distinguish recommended, supported, and legacy OpenClaw versions without overclaiming approval delivery on older builds.

### Changed

- **Degraded-mode behavior is explicit and configurable** — Sensitive OpenClaw tools fail closed when `rampart serve` is unavailable or errors; only configured lower-risk `failOpenTools` fail open by default.
- **`rampart setup openclaw` is more resilient** — Setup can fall back to a background `rampart serve` start when service installation does not become reachable quickly, improving headless/fresh-install flows.
- **`rampart doctor` is stricter but less noisy** — Doctor now recognizes native plugin approval health, validates OpenClaw hardening state more accurately, and avoids false plugin-version mismatch warnings on development, staging, git-describe, and Go pseudo-version builds.

### Fixed

- **OpenClaw plugin metadata now matches the RC release** — The embedded plugin manifest, runtime export, and package metadata are versioned as `1.0.0-rc.1`, avoiding post-tag doctor mismatch warnings.
- **OpenClaw plugin gateway status uses the current response contract** — `rampart.status` now resolves through OpenClaw's current `respond(true, payload)` gateway method shape.
- **Policy matching hardening** — Shell-wrapper, path-normalization, and URL/domain matching regressions found during the RC pass now have explicit coverage.

## [0.9.22] - 2026-04-29

### Fixed

- **Config resolution is stricter and more trustworthy** — CLI flows that depend on Rampart control-plane endpoints now surface malformed `~/.rampart/config.yaml` instead of silently falling back to defaults, reducing the chance of acting against the wrong endpoint during approval, reload, watch, preload, and hook-driven operations.
- **Ask-flow failure handling preserves approval integrity** — `PostToolUseFailure` no longer infers a denial or resolves mirrored approvals as denied based only on an ambiguous hook failure event, preventing approved tool calls that later fail from being mislabeled as user denials.
- **Endpoint resolution is more consistent across commands** — `preload` and related CLI paths now honor the same `url` / `serve_url` / `api` precedence model as the rest of Rampart, including compatibility alias support and auto-discovered state fallback.

### Changed

- **Workflow and release hardening for current GitHub Actions runtimes** — CI/docs/release workflows now use Node 24-safe action versions, and Docker prerelease tagging avoids publishing prereleases as `latest`.

### Docs

- **Config semantics are clearer for users and contributors** — README and help text now spell out the intended roles of `url`, `serve_url`, and `api`, including the distinction between API base URLs used by client commands and API listen addresses used by daemon/server commands.

## [0.9.21] - 2026-04-29

### Changed

- **Phase 1 docs/UX coherence pass** — Rampart now presents a cleaner, more truthful integration story across README, quickstart, CLI help, status/doctor messaging, and docs-site reference pages. The goal is simple: users should not have to reverse-engineer which integration path they are actually on.
- **OpenClaw setup is framed around the real default path** — `rampart setup openclaw` is now the canonical command in user-facing docs and hints, while explicit `--plugin` and `--patch-tools` references are reserved for advanced or legacy cases.
- **Serve requirements are explained per integration** — Claude Code and Cline native hooks are now documented as capable of local policy evaluation without `rampart serve` for direct hook decisions, while OpenClaw plugin and other service-backed paths clearly call out their dependency on the local service.

### Fixed

- **`rampart status` no longer conflates hook-only and service-backed protection** — hook-only setups can report serve as optional, while OpenClaw plugin setups are no longer misclassified as hook-only when the service is down.
- **Quickstart OpenClaw detection matches the native plugin story** — quickstart and related tests now recognize the native OpenClaw plugin as an installed protected path instead of only checking legacy shim artifacts.
- **CLI/docs wording drift removed** — stale claims that `rampart quickstart --yes` auto-enables OpenClaw `--patch-tools` have been removed, and doctor/help hints now point users at the canonical OpenClaw command.
- **Doctor version output cleaned up** — service version reporting no longer renders malformed strings like `serve vv0.9.20`.
- **Self-modification policy false positives reduced** — built-in policies now block actual Rampart mutation/setup invocations without denying harmless PR bodies or docs text that merely mention commands like `rampart setup openclaw`.

### Docs

- **Added a canonical integration support matrix** — new docs spell out support tier, serve requirements, approval UX, and degraded behavior per surface so the product story has one source of truth.
- **Architecture/tutorial/homepage language now distinguishes hooks, plugins, wrapper/preload, and MCP paths** — especially for OpenClaw, where earlier docs mixed the native plugin story with older shim-era language.

## [0.9.20] - 2026-04-26

### Fixed

- **Built-in policy upgrades are safer** — `rampart doctor` now distinguishes stock built-in profiles from customized ones, warns clearly on stale or unstamped stock profiles, stamps policies written by setup for future drift detection, and preserves modified built-in profiles during upgrade instead of clobbering them.
- **OpenClaw approval fallback is fail-closed and more truthful** — approval timeout/fallback behavior is hardened, async completion wording no longer implies prior user approval, Rampart aligns the plugin approval timeout to `120000ms`, and `rampart doctor` / `rampart doctor --fix` can detect and repair approval-hardening drift on supported OpenClaw bundle shapes.
- **Approval-path tests are more reliable across hosts** — proxy tests isolate HOME state by default, and durable allow-always writeback is more robust on Windows.

### Docs

- **README and landing-page voice tightened** — public copy is cleaner, more consistent, and keeps the deployed landing page aligned with the current product story.

## [0.9.19] - 2026-04-24

### Fixed

- **Codex setup is safer and idempotent** — `rampart setup codex` now refuses to install a wrapper when the preload library is missing, preserves the real Codex binary when `~/.local/bin` is first in `PATH`, and avoids self-recursive wrappers on repeated setup. `rampart setup codex --remove` no longer depends on Codex or the preload library being present.
- **Claude Code hook failures are stderr-clean** — invalid or stale policy configurations now fail closed through Claude Code's hook protocol instead of surfacing scary shell-hook stderr noise.
- **OpenClaw degraded-mode behavior is regression-tested** — sensitive tools block when `rampart serve` is unavailable or errors, while explicitly configured lower-risk `failOpenTools` remain fail-open.
- **Integration docs now match platform behavior** — Codex, OpenClaw, Windows, source-build preload-library requirements, and current `action: ask` terminology are aligned across README and docs.

## [0.9.18] - 2026-04-24

### Added

- **`rampart policy explain` now shows why decisions won** — matching policies include source files, agent/session/tool scope, explicit `[WINNER]` marking, winning-rule rationale, and clearer messaging when a policy matched scope but no rule matched the command. New `--session` support makes session-scoped policy debugging faithful to engine behavior; docs now show the upgraded examples.
- **Durable overrides are visible in explain output** — learned `Allow Always` rules from `user-overrides.yaml` are labeled as durable user overrides in both matching-policy details and the final decision summary.
- **`rampart doctor` now includes OpenClaw readiness** — a concise readiness signal confirms the native plugin is active, `rampart serve` is reachable, and approval-learning prerequisites are present.

### Fixed

- **Release hygiene tightened** — OpenClaw plugin metadata is bumped with the release, and the changelog now has explicit `0.9.17` and `0.9.18` sections instead of leaving shipped changes under `Unreleased`.

## [0.9.17] - 2026-04-23

### Fixed

- **OpenClaw native approval path now has a proven end-to-end acceptance bar** — validated live with native Discord approval UI across the three critical states: learned allow (`sudo true`), fresh ask (`sudo id`), and hard deny (`rm -rf /tmp`).
- **`Allow Always` writeback path verified on true plugin-originated approvals** — Rampart's native OpenClaw plugin now proves `onResolution("allow-always")` triggers `/v1/rules/learn` and persists durable rules to `~/.rampart/policies/user-overrides.yaml`.
- **Sensitive-tool degraded mode hardened** — when Rampart serve is unavailable, sensitive OpenClaw tools now fail explicitly instead of silently failing open. Lower-risk tools can remain configured fail-open.
- **OpenClaw docs/checklists corrected** — verification guidance now points at `user-overrides.yaml`, includes `rampart-serve.service` health checks, and documents the recommended learned-allow / ask / deny validation set.

## [0.9.16] - 2026-04-15

### Fixed

- **Durable global exec overrides now work correctly** — `rampart allow --global --tool exec ...` writes to `~/.rampart/policies/user-overrides.yaml`, and the proxy now honors those durable user carve-outs before broad deny resolution.
- **Sensitive agent-state defaults polished** — `standard.yaml` now denies real credential stores by default and uses `ask` for sensitive agent session/history/runtime/config artifacts across Claude Code, Codex, and OpenClaw.
- **OpenClaw plugin approval path kept native** — Rampart `ask` decisions for `exec` continue through native OpenClaw approval cards by reissuing only matched commands with `ask: "always"`, while keeping global `tools.exec.ask` off.
- **Docs aligned with current behavior** — user-facing docs now reflect `action: ask`, durable `user-overrides.yaml` behavior, and the current standard-vs-product-profile split.

## [0.9.15] - 2026-04-06

### Added

- **`rampart doctor`: OpenClaw-only coverage warning** — new `doctorCoverage()` check (step 17a) warns when OpenClaw is in the protected agents list but native hooks are not installed. Prevents false confidence where only the OpenClaw plugin path is covered while native `claude` CLI calls go unprotected.
- **`rampart status` hint: coverage gap warning** — `printStatusHints()` now appends a warning when agents are protected via OpenClaw plugin but no native hooks are present, prompting users to run `rampart setup` for full coverage.
- **`rampart convert`: `allowedTools` / `disabledTools` support** — the settings migration command now reads both the legacy `permissions.*` format and the newer flat arrays (`allowedTools`, `disabledTools`, `disallowedTools`) introduced in Claude Code 1.x. Duplicate patterns across both formats are deduplicated automatically.
- **`internal/policy` test coverage: 60.3% → 83.1%** — added 8 new test cases covering previously untested functions: `DetectTool`, `FlattenRules`, `HasPattern`, `RemoveRuleAt` (including last-rule and invalid-index cases), and `AddRuleTemporal` (expiration and once-only variants).

### Fixed

- **`rampart doctor`: hooks check triggers without `~/.claude/`** — `doctorHooks()` now fires whenever the `claude` binary is found in PATH, regardless of whether `~/.claude/` exists (e.g. fresh installs or non-default config paths).

## [0.9.14] - 2026-04-02

### Fixed

- **OpenClaw 2026.4.1 plugin install breakage** — OpenClaw 2026.4.1 introduced `validateHookDir()` requiring a `HOOK.md` file when the hook-pack install path is used. Removed `openclaw.hooks` from `package.json`; plugin now correctly installs via the `openclaw.extensions` path which has no `HOOK.md` requirement.
- **`rampart status` shows `OpenClaw (plugin)`** — previously showed `OpenClaw (bridge)` even when the native plugin was active. Status now checks for `~/.openclaw/extensions/rampart` first.
- **Setup explains scanner false positive** — `rampart setup openclaw --plugin` now prints a note explaining that OpenClaw's security scanner warning is a false positive (localhost-only token auth).
