# Changelog

All notable changes to Rampart are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **One safe verification command for configured boundaries** —
  `rampart verify --all` runs the policy canaries plus every configured
  integration with an active behavioral verifier, without invoking a model or
  executing the represented actions. Machine-readable output uses
  `rampart.verify-all.v1`, retains per-target reports, and distinguishes failed
  targets from incomplete or unreachable checks.
- **OpenClaw prerelease warning gate** — Scheduled compatibility CI keeps the
  latest stable OpenClaw path blocking while checking the beta package as a
  non-blocking advisory, so upstream contract changes are visible before they
  reach stable without overstating prerelease support.

### Changed

- **Explicit service endpoints are lifecycle-wide** —
  `rampart protect --serve-url` now selects the endpoint used for service health, host
  configuration, and behavioral verification. Non-default endpoints must
  already be reachable, and OpenClaw accepts only a local loopback service
  without credentials or URL suffixes.
- **OpenClaw approvals use the current ownership contract** — Approval cards
  identify Rampart as their owner, advertise `allow-once`, `allow-always`, and
  `deny`, explain timeout denial, and persist policy only for `allow-always`.
  OpenClaw's local `ask_user` interaction is classified separately from an
  outbound or cross-conversation message.

### Security

- **Background service identity survives legitimate binary names safely** — A
  private, bounded `serve.state` records the executable that launched the
  service, allowing renamed Rampart binaries to be authenticated by exact path
  while malformed, permissive, stale, or symlinked state falls back to the
  stricter legacy process-name check.

## [1.5.0] - 2026-07-29

### Added

- **Zero-configuration protection across supported local agents** —
  `rampart protect` now detects installed integrations through a shared driver
  contract, installs the strongest supported boundary, and runs the matching
  active verifier without requiring users to choose an adapter manually.
- **Antigravity shared policy plugin** — `rampart setup antigravity` installs
  one `PreToolUse` integration for the CLI and IDE, including native
  `force_ask` approvals. Antigravity CLI 1.1.7 has completed host proof; the IDE
  shares the tested contract, but a separate physical editor run is pending.
- **GitHub Copilot CLI adapter and VS Code Preview hooks** — `rampart setup copilot`
  installs one cross-platform `PreToolUse`/`PostToolUse` user hook shared by
  Copilot CLI and VS Code agent sessions. Copilot CLI administrators can also
  install a machine-owned policy hook with `--policy`. Latest-package startup
  and the adapter are tested separately; authenticated hook ingestion is
  pending, and VS Code coverage remains an upstream Preview contract.
- **Exact one-shot approval resume** — Individually approved `/v1/tool/*`
  requests can resume once when the host supplies stable run and tool-call
  identifiers. The grant is short-lived, bound to the complete call payload,
  durable across restarts, and atomically consumed across processes.

### Experimental

- **Gemini CLI lifecycle-hook adapter** — `rampart setup gemini` installs
  managed `BeforeTool` and `AfterTool` hooks for the enterprise/API-key Gemini
  CLI path, preserves unrelated settings, and provides non-executing adapter
  verification plus a rolling latest-package startup gate. It is excluded from
  bare `rampart protect`; authenticated host hook ingestion remains unproven,
  and this integration does not cover Antigravity.

### Changed

- **Upgrade guidance refreshes managed integrations safely** — Existing hooks,
  policies, audit logs, and credentials remain in place when the binary is
  replaced. After upgrading, one idempotent `rampart protect` run adopts newer
  native hook schemas, migrates recognized legacy integrations, and verifies
  detected agent boundaries without requiring manual configuration.
- **Integration status and setup use one source of truth** — Aliases,
  installation detection, setup, verification, interactive setup, and protected
  status reporting now resolve through the same integration-driver registry.
- **Public support guidance includes editor boundaries** — The support matrix,
  quickstart, architecture, threat model, landing page, and integration guides
  distinguish CLI, editor, Preview, service-dependent, and administrator-owned
  enforcement paths.
- **Stateful policy limits now work across Rampart processes** — One-time grants
  and call-count rules use locked, durable state so parallel hooks, plugins, and
  proxy requests cannot each consume the same allowance independently.
- **Managed uninstall is integration-aware and idempotent** — `rampart uninstall`
  removes only Rampart-owned Claude Code, Cline, Codex, Copilot, Antigravity,
  Gemini CLI, Hermes, and OpenClaw configuration while preserving unrelated host
  settings, histories, memories, sessions, and credentials.
- **Release gates exercise the supported operating-system boundaries** — CI now
  checks formatting, module tidiness, static analysis, race behavior, Linux and
  Windows builds, installers, preload contracts, Python SDK compatibility,
  Docker packaging, and release snapshots before a release can proceed.
- **Native hook latency avoids redundant process and policy work** — Repository
  identity is resolved directly from the host-reported working directory with
  one Git invocation on normal repositories, and webhook delivery reuses the
  validated policy snapshot that produced the decision instead of reparsing
  policy files.

### Fixed

- **Policy benchmarks score the declared behavior again** — Version 2 corpora
  preserve `allow`, `watch`, `ask`, and `deny` expectations, benign controls no
  longer count as security gaps, and over-blocking can no longer improve the
  score. Non-strict runs still accept `ask` for a case that expects `deny`.
- **Command policy behavior is shell-aware across operating systems** — Bash,
  `cmd.exe`, and PowerShell wrappers are parsed by command dialect rather than
  by the OS running Rampart. Restrictive rules also evaluate ambiguous native
  Windows forms, including caret and PowerShell backtick escapes, while those
  alternate interpretations can never broaden an allow rule.
- **Windows hook upgrades recover legacy data-directory permissions first** —
  Native hooks repair the locked `~\.rampart` layout left by affected older
  installers before other command work and still return protocol-shaped,
  fail-closed responses if recovery is not possible.
- **Windows background service lifecycle is reliable** — Detached serving uses
  the Windows process model, records the child PID, and can be stopped or
  restarted without relying on Unix process-group behavior.
- **Concurrent session and token updates no longer overwrite each other** —
  Stores use cross-process locking, bounded reads, durable replacement, and
  stricter identifier validation, including Windows-safe file replacement.
- **Installer and container validation match published artifacts** — Installers
  fail closed on checksum mismatches, Homebrew resolves the exact stable
  version, and the Docker build context excludes development and test output.
- **Policy explanations match enforcement semantics** — `policy explain` now
  respects rule actions and ANDed fields, and environment-variable assignment
  names are folded only on Windows rather than on macOS shells.

### Security

- **Required audit records are durable enforcement state** — Policy decisions
  fail closed when their audit record cannot be persisted; response decisions
  are separately correlated, recovery links survive rotation, and verification
  detects truncated, reordered, or broken audit chains.
- **Native adapters fail closed on unclassified or malformed actions** —
  OpenClaw, Hermes, MCP, Copilot, Gemini CLI, and Antigravity adapters validate
  structured input, evaluate every path in batched changes, and deny ambiguous
  future tool surfaces in enforce mode.
- **The preload boundary has bounded, structural response parsing** — The native
  library rejects oversized or malformed policy responses, covers spawned
  processes consistently, and never treats HTTP 4xx policy errors as an
  availability failure eligible for fail-open behavior.
- **HTTP and webhook boundaries are more defensive** — The server rejects
  trailing JSON documents, limits headers, restricts query-string bearer tokens
  to SSE connections, keeps global metrics administrator-only, and sends
  signed webhooks with bounded requests and redacted error handling.
- **Windows system dependency is on the patched release** — Updated
  `golang.org/x/sys` to remove GO-2026-5024 from Rampart's module graph, even
  though the vulnerable symbol was not reachable from Rampart.
- **Gemini and Copilot adapters deny unknown future pre-call tools** — New tool
  names cannot silently bypass classification in enforce mode. Allowed calls
  still pass through each host's native permission and sandbox checks, and
  multi-file edits evaluate every reported path with deny-wins behavior.
- **Platform-aware zero-configuration detection** — `rampart protect` skips
  integrations that are not supported on the current operating system and no
  longer mistakes Antigravity's shared `~/.gemini` state for Gemini CLI.
- **Copilot disabled-hook detection** — Verification reports when Copilot CLI's
  `disableAllHooks` setting prevents the user-level Rampart boundary from
  loading in the current repository.
- **Rolling compatibility gates track upstream Gemini and Copilot releases** —
  Disposable homes confirm the latest published packages start, then separately
  validate generated hook configuration and destructive-call denial adapters
  without touching normal user state or claiming host hook ingestion or
  authenticated execution.
- **Hermes latest-version gate rejects silent dependency fallback** — The
  disposable Hermes harness now compares the installed distribution with
  PyPI's current release and fails when an unsupported Python version causes
  pip to select an older Hermes build.

### Removed

- **Unused legacy enforcement paths** — Removed the unreferenced daemon and
  intercept packages, the brittle OpenClaw source-patching scripts, and the old
  fail-open Node filesystem preload hook. Supported integrations now use the
  maintained native hook, plugin, proxy, wrapper, or preload boundaries.

## [1.4.1] - 2026-07-28

### Security

- **Execution grants require a whole-call command match** — An allow, watch, or
  webhook rule can no longer authorize a compound command merely because one
  sibling segment or nested substitution matches. Restrictive rules continue
  inspecting every executable segment and subcommand with deny-wins behavior.

## [1.4.0] - 2026-07-25

### Added

- **Native Codex lifecycle-hook integration** — `rampart setup codex` now
  installs user-level `PreToolUse` and `PostToolUse` hooks shared by Codex CLI,
  the IDE extension, and the desktop app. The adapter covers host-exposed
  shell, file, patch, MCP, web, and delegated-agent calls, evaluates every
  target in multi-file patches, and denies unknown pre-call tools in enforce
  mode until they are classified.
- **Isolated host compatibility harnesses** — Opt-in Codex, Claude Code, and
  Hermes harnesses exercise harmless allow/deny canaries through real agent
  processes without loading normal configuration, memories, rules, or
  persistent sessions. Sanitized completed-run evidence records the reviewed
  Codex, Claude Code, and Hermes host proofs.
- **Executable security-assurance gate** — A machine-readable integration
  manifest, shared adversarial policy corpus, and one-command Go, OpenClaw, and
  Hermes regression suite now run in Linux CI.

### Changed

- **Integration guarantees are evidence-based** — Public support guidance now
  distinguishes verified host boundaries from tested, limited, and
  experimental paths, and explicitly limits coverage to actions each host
  exposes through the named hook, plugin, proxy, or process boundary.
- **Claude Code hooks track the current native tool surface** — Wildcard
  `PreToolUse`, `PostToolUse`, and `PostToolUseFailure` handlers classify the
  documented Claude Code 2.1.220 hook-visible shell, file, web, MCP,
  delegation, message, scheduling, and task tools. Unknown future pre-call
  tools deny in enforce mode instead of silently falling through.
- **Codex setup migrates away from the managed preload wrapper** — Existing
  unrelated hooks remain intact while recognized legacy Rampart wrappers are
  removed, avoiding duplicate evaluation and making native lifecycle hooks the
  primary cross-platform Codex path.

### Fixed

- **Hermes batched tool updates use deny-wins evaluation** — Rampart evaluates
  every action represented by a Hermes patch batch and blocks the entire call
  when any path is denied, rather than depending on only one update.

### Security

- **Approvals are bound to the exact execution context** — Retry
  deduplication now requires an identical host-provided tool-call ID, agent,
  session, run, tool, and action payload. Calls without stable host identity
  receive independent approvals, preventing one approved session from
  releasing an identical action in another session.

## [1.3.0] - 2026-07-24

> **Windows upgrade guidance:** If you installed Rampart 1.2.x on Windows, rerun the official PowerShell installer:
> `irm https://rampart.sh/install.ps1 | iex`. The installer repairs the affected legacy `~\.rampart` ACL before replacing the binary. Do not rely on `rampart upgrade` if Windows cannot execute `rampart.exe` from the locked directory.

### Added

- **Zero-configuration OpenClaw protection** — `rampart protect openclaw` installs managed Guard and OpenClaw policies, enables the bundled native plugin, starts the local policy service, configures fail-closed degraded behavior, restarts the gateway, and verifies the boundary with safe behavioral canaries.
- **Active behavioral verification** — `rampart verify openclaw` checks routine work, destructive actions, credential access, external network commands, publishing, opaque execution, and cross-conversation messaging without executing the canary actions or writing verification events to the audit log.
- **Immutable Linux lab evidence** — The lab runner accepts an exact commit SHA, validates it in a detached worktree, and retains structured logs, environment metadata, summaries, and checksums outside the checkout.

### Changed

- **Release and source-build toolchains use Go 1.25.12** — The module baseline, CI, GoReleaser, Docker, and upstream compatibility workflows now use the patched Go release required for a clean reachable-vulnerability scan.
- **OpenClaw defaults are consequence-oriented and safer** — Read-only work stays available while package publishing, interpreter and package-runner execution, privileged or external changes, and cross-conversation messaging require approval; credential reads, destructive commands, and direct external curl/wget are denied.
- **Bundled integration metadata targets v1.3.0** — OpenClaw and experimental Hermes manifests and runtime exports are aligned for the next minor release.

### Fixed

- **Windows token hardening cannot lock domain or AzureAD users out of Rampart** — Token ACLs now use the current process SID through native Windows security APIs, protect only the token file, and fail setup safely if hardening cannot be applied.
- **OpenClaw 2026.7 migration notices no longer break protection detection or verification** — Rampart extracts the real config path and JSON gateway payload when OpenClaw prints state-migration notices first, so existing upgraded installations continue to detect their native plugin and pass live canaries.
- **Modern OpenClaw never falls into legacy bundle patching after a detection error** — Setup and `doctor --fix` refuse the legacy dist-patch fallback on native-plugin-capable OpenClaw releases.
- **The live OpenClaw release gate proves successful approval resume** — The isolated regression now requires a native plugin approval, `allow-once`, exact tool-call resume, successful execution, and correlated trajectory/audit evidence; its documented invocation matches the isolation guard.
- **OpenClaw policy responses fail closed** — Malformed, empty, array, or unknown policy responses block the tool call instead of silently becoming an allow decision.
- **Rampart tokens stay on the loopback trust boundary** — Managed OpenClaw configuration forces the local policy URL, and the plugin refuses to send its admin token to non-loopback endpoints.
- **Managed policies are loaded before enforcement and hot-reload correctly** — Fresh protection no longer starts with only one managed layer, and `rampart serve` now reloads YAML files created, replaced, renamed, or removed in the policy directory.
- **Headless installs and cleanup include the fallback daemon** — Zero-config protection falls back to `rampart serve --background` when system service installation is unavailable, and `rampart serve uninstall` stops that fallback as well as removing service files.
- **Plugin verification checks installed code integrity** — Verification rejects a plugin whose runtime file differs from the version bundled in the Rampart binary and validates every expected canary result rather than trusting an `ok` field alone.
- **Existing OpenClaw agent identities remain compatible** — Native agent IDs are preserved instead of being rewritten with an integration prefix that could bypass exact-match user policies.

## [1.2.0] - 2026-05-28

### Added

- **Hosted approval API foundation for host-owned approval flows** — Rampart can return hosted approval metadata without creating a hidden Rampart pending queue item, preserving the single approval-owner boundary for hosts such as Hermes.
- **Hermes audit/tool-call correlation** — The experimental Hermes policy gate passes Hermes tool-call metadata through Rampart so audit entries can be correlated with the originating Hermes tool call.

### Changed

- **Bundled plugin metadata is aligned for v1.2.0** — The OpenClaw and experimental Hermes plugin manifests, runtime exports, and public examples now report `1.2.0` with the Rampart release.
- **Release-facing docs and install examples now point at v1.2.0** — Current-version markers, troubleshooting examples, and container tag examples are refreshed for the release.

### Fixed

- **Audit chain recovery now resumes from the latest valid JSONL event** — Startup reconstruction recovers both the event count and chain head from existing audit logs instead of trusting absent, stale, or tampered anchors as the next `prev_hash` source.
- **Partial audit verification is safer** — `rampart audit verify --since` accepts intentionally truncated history while continuing to verify the included hash chain and anchor data that is present in the selected window.
- **Release builds use Go 1.25.11**: CI, release, Docker, and upstream compatibility gates now use the Go patch release that resolves the called standard-library vulnerabilities reported against Go 1.25.10.

## [1.1.1] - 2026-05-26

### Added

- **Experimental Hermes Agent policy gate** — `rampart setup hermes` installs a user plugin that evaluates Hermes `pre_tool_call` events through Rampart without patching Hermes itself.

### Changed

- **Bundled OpenClaw plugin metadata is aligned for v1.1.1** — The package manifest, OpenClaw manifest, runtime export, and user-facing examples now report `1.1.1`.

### Fixed

- **Serve tokens stay out of non-interactive logs** — `rampart serve` redacts full tokens when output may be captured by service logs while preserving local token persistence.
- **Policy polish for agent integration maintenance** — Standard policy now allows safe setup help and hook inspection forms while continuing to deny setup execution, hook mutation, compound inspection-plus-mutation commands, and high-risk environment assignments.
- **Filtered audit views include sidecar files** — `rampart log --deny` searches all audit JSONL files before filtering so deny events are not hidden by later-sorting sidecar logs.

## [1.1.0] - 2026-05-24

### Added

- **Machine-readable diagnostics for automation** — `rampart status --json`, `rampart doctor --json`, and `rampart inventory --json` expose structured runtime, policy, and integration state for scripts and CI systems.
- **Enterprise observability foundation** — Runtime status now includes schema-versioned health and integration details that downstream dashboards can consume without parsing human output.
- **OpenClaw/Codex native audit regression coverage** — The release gate now includes an opt-in live regression that verifies Codex native shell calls are correlated with Rampart audit events.

### Changed

- **OpenClaw gateway protocol v4 is the bundled baseline** — The embedded plugin now speaks the current gateway/status response contract while preserving Rampart's native approval and audit ownership.
- **Bundled OpenClaw plugin metadata is aligned for v1.1.0** — The plugin package manifest, OpenClaw manifest, runtime export, and user-facing examples now report `1.1.0`.
- **Release builds use Go 1.25.10** — CI, release, and Docker builds now use the patched Go toolchain that resolves the called standard-library vulnerabilities reported against Go 1.25.9.

### Fixed

- **Codex native shell calls stay visible in Rampart audit** — OpenClaw tool-alias handling now preserves canonical `exec` audit correlation for Codex app-server native shell sessions.

## [1.0.0] - 2026-05-06

### Fixed

- **Docker images now boot and report release metadata** — The Dockerfile uses the current `serve --addr/--port` flags, injects version/commit/date ldflags, aligns its Go toolchain with the release workflow, and sets a writable runtime home for the nonroot distroless container.
- **Installer surfaces are canonical again** — `install.sh`, `docs/install`, `docs/install.sh`, and `scripts/install.sh` are byte-for-byte synced, with CI checks to prevent future drift.

### Changed

- **1.0 launch metadata is aligned** — The embedded OpenClaw plugin manifest, runtime export, package metadata, landing structured data, docs homepage, support matrix, and roadmap now use final `1.0.0` launch language instead of stale RC labels.
- **Release docs point at the live package channels** — Homebrew examples use `peg/tap/rampart`, binary download docs describe the actual archive formats, and Docker docs describe stable/minor/prerelease tags accurately.

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
