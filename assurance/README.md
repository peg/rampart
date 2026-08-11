# Rampart Security Assurance

This directory keeps Rampart's public security claims tied to portable,
reviewable checks.

- `integrations.yaml` records each supported integration's boundary, coverage,
  degraded behavior, verification level, limitations, and source evidence.
- `corpus.yaml` is a shared adversarial decision corpus evaluated by the real
  policy engine. Its represented commands are data and are never executed.

## Evidence vocabulary

- **verified** — the installed integration exposes an active, safe verifier for
  the claimed host boundary.
- **tested** — Rampart's adapter or mapping is exercised in isolation.
- **partial** — some routes are covered, with documented exclusions.
- **not_covered** — the integration does not intercept the surface.

Support tiers remain separate from feature breadth: a supported integration can
have a verified shell boundary and narrower file or network coverage.

## Run the checks

To check an installed environment without invoking a model or executing the
represented actions:

```bash
rampart verify --all
rampart verify --all --json
```

Static-only integrations such as Hermes are intentionally omitted from the
aggregate. Use `rampart doctor` for installation state; the portable
`scripts/compat-hermes-latest.py` check exercises Hermes plugin discovery and
dispatch against isolated state without provider credentials.

From a source checkout:

```bash
make security-assurance
```

The gate validates the manifest, evaluates the adversarial corpus, exercises
fuzz seed corpora, and runs portable OpenClaw and Hermes compatibility checks.

The public corpus contains fixed regression cases only. Report suspected or
unpatched bypasses privately through [`SECURITY.md`](../SECURITY.md); regression
cases are published after a fix is available.

## Release bar

A support claim may ship only when the exact candidate commit has green CI,
passes `make security-assurance`, and its installed verifier proves every
boundary described as verified. Keep `integrations.yaml` and the public support
matrix synchronized whenever a boundary or limitation changes.
