# Rampart Security Assurance

This directory turns Rampart's security claims into reviewable data and
executable evidence.

- `integrations.yaml` uses each canonical runtime target as its id and records
  bare `rampart protect` eligibility, boundary, coverage, degraded behavior,
  approval behavior,
  verification level, evidence, and limitations of each agent-harness
  integration. Its current schema is `rampart.assurance.v2`; tests keep its
  runtime and public support claims synchronized.
- `corpus.yaml` is the shared adversarial decision corpus. The assurance tests
  run every case through the real policy engine and bundled policy profiles.

## Evidence vocabulary

- **tested** — Rampart's adapter or mapping is exercised in isolation.
- **verified** — a completed live host-boundary run is recorded, or the
  installed integration provides an active safe verifier for that boundary.
- **live harness** — an executable opt-in check is available; this is not a
  completed result.
- **live evidence** — a reviewed JSON summary records a completed host run.
- **partial** — some routes are covered, but the surface has known exclusions.
- **not_covered** — the integration does not intercept the surface.
- **unknown** — no reliable claim is made until evidence is added.

Support tiers are intentionally separate from feature breadth:

- **verified** — Rampart has an active host-boundary verification path.
- **supported** — maintained and tested, but the installed host boundary is not
  yet actively proven.
- **experimental** — useful for testing, with a material upstream or workflow
  limitation.
- **limited** — retained as defense in depth or compatibility, without broad
  tool-call coverage.

## Running the gate

To check an installed environment without invoking a model or executing the
represented actions:

```bash
rampart verify --all
rampart verify --all --json
```

The aggregate includes the policy path and configured integrations with active
safe verifiers. Static-only integrations such as Hermes are intentionally
excluded; inspect them with `rampart doctor` and use the isolated host harness
when runtime evidence is required.

```bash
make security-assurance
```

The gate validates the manifest, confirms every evidence path exists, runs the
adversarial corpus, exercises the Go test suite's fuzz seed corpora, and runs
the bundled OpenClaw and Hermes adapter regressions. It never executes any
command contained in `corpus.yaml`; cases are policy evaluations only.

Manifest entries use `live_harness` for an executable check and `live` only for
a completed JSON summary. A harness is not by itself evidence that a run
passed. Sanitized completed-run summaries live
under `assurance/evidence/` when a coverage claim depends on a maintainer host
run. The summaries omit credentials, raw model output, hostnames, and temporary
paths. They are reviewable maintainer attestations tied to a candidate commit,
not cryptographic signatures or substitutes for rerunning the harness.

The public corpus contains mitigated regression cases only. Report suspected
or unpatched bypasses privately through [`SECURITY.md`](../SECURITY.md);
regression cases are published after a fix is available.

## Release candidate bar

A support claim may ship only when the exact candidate commit has green CI,
passes `make security-assurance`, and has current evidence for every boundary
described as verified. Latest-stable compatibility jobs establish the package
baseline; opt-in host harnesses are required only where the advertised tier
depends on a real host run. Update `integrations.yaml`, the support matrix, and
sanitized evidence together whenever the proven boundary or limitation changes.

OpenClaw's exact container and credentialed native-runtime procedure is kept in
one place: the
[OpenClaw release acceptance checklist](../docs/design/openclaw-approval-acceptance-checklist.md).
The reusable Linux runner is documented in
[`docs/LINUX-E2E-LAB.md`](../docs/LINUX-E2E-LAB.md).

Real Codex host verification is intentionally opt-in because it uses the
maintainer's configured model:

```bash
scripts/compat-codex-host.sh --yes --rampart-bin ./rampart
```

The harness copies only Codex authentication into a disposable home, ignores
user configuration, persists no session, and deletes the credential copy on
every exit. Its offline test double runs as part of the lab-runner contract;
ordinary CI does not make a model call.

The equivalent opt-in host harnesses for Claude Code and Hermes Agent are:

```bash
scripts/compat-claude-host.sh --yes --rampart-bin ./rampart
scripts/compat-hermes-host.sh --yes --rampart-bin ./rampart
```

Add `--gateway` to send both Hermes canaries through a disposable localhost
OpenAI-compatible API gateway. The isolated profile enables no messaging
platforms and does not load source memories, sessions, rules, or workspaces.

The completed Codex CLI 0.145.0 and Claude Code 2.1.220 macOS runs prove shell
deny, allowed execution, and pre/post identity correlation through isolated
real host processes. On macOS the disposable Claude HOME cannot use the
account's Keychain login, so an ephemeral `CLAUDE_CODE_OAUTH_TOKEN` is required
when re-running that proof; subprocess scrubbing prevents the harness from
passing it to the Bash canary. The Codex, Claude, and Hermes completed-run
summaries record the exact reviewed upstream versions and behavioral checks.
