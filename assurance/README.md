# Rampart Security Assurance

This directory turns Rampart's security claims into reviewable data and
executable evidence.

- `integrations.yaml` records the current boundary, coverage, degraded behavior,
  approval behavior, verification level, evidence, and limitations of each
  agent-harness integration.
- `corpus.yaml` is the shared adversarial decision corpus. The assurance tests
  run every case through the real policy engine and bundled policy profiles.

## Evidence vocabulary

- **tested** — Rampart's adapter or mapping is exercised in isolation.
- **verified** — a live host integration is exercised with safe behavioral
  canaries before the action would execute.
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

```bash
make security-assurance
```

The gate validates the manifest, confirms every evidence path exists, runs the
adversarial corpus, exercises the Go test suite's fuzz seed corpora, and runs
the bundled OpenClaw and Hermes adapter regressions. It never executes any
command contained in `corpus.yaml`; cases are policy evaluations only.
