# Contributing to Rampart

Thanks for helping make AI tools safer. Contributions do not need to be large:
clear bug reports, documentation fixes, platform compatibility improvements,
and focused regression tests are all valuable.

Rampart is a security boundary, so changes are reviewed carefully. The goal is
not ceremony or maximum test count; it is code and documentation that are easy
to understand, verify, and maintain.

## Before you start

- Report suspected vulnerabilities privately using [SECURITY.md](SECURITY.md).
  Do not open a public issue for an unpatched bypass or credential exposure.
- Small, self-contained fixes can go directly to a pull request.
- For a new integration, major behavior change, or architectural rewrite, open
  an issue first so we can agree on the boundary and avoid wasted work.
- Search existing issues and pull requests before starting.

Useful contribution areas include:

- reproducing and fixing cross-platform bugs;
- keeping supported integrations compatible with current upstream releases;
- simplifying integration lifecycle and CLI code;
- improving user documentation and error messages;
- adding a focused regression for a demonstrated security boundary; and
- measuring and improving real tool-call latency or allocations.

## Development setup

Rampart requires the Go version declared in [`go.mod`](go.mod). Clone the
repository, then run:

```bash
go test ./...
go vet ./...
make security-assurance
```

Documentation work additionally uses the Python packages in
[`docs-requirements.txt`](docs-requirements.txt). Some integration checks need
Node.js or Python; install those only when working on the affected integration.

## Repository workflow

1. Create a focused branch from current `staging`.
2. Make the smallest coherent change that solves the problem.
3. Add or update only the tests and documentation needed for that behavior.
4. Run checks proportional to the change, followed by the full source checks
   before requesting review.
5. Open the pull request against `staging` and explain the user-visible result,
   security impact, limitations, and validation performed.

The `main` branch represents published releases. Release merges and tags are
maintainer-managed.

## Design principles

- Prefer the standard library and existing shared helpers.
- Keep CLI commands focused on parsing and orchestration; reusable behavior
  belongs in an appropriate `internal/` package.
- Preserve command, path, tool, and request identity across enforcement,
  approval, and audit paths.
- Evaluate every target in compound actions and let the most restrictive
  decision win.
- Fail closed when Rampart owns a decision and cannot safely classify, parse,
  validate, or persist it.
- Preserve unrelated user configuration and refuse ambiguous ownership when
  installing, repairing, or removing integrations.
- Avoid broad refactors in security fixes. Prefer readable, bounded patches.
- Every production file, test, fixture, script, and document should protect a
  distinct behavior or serve a durable public purpose.

Comments should explain why a constraint exists rather than restating the code.
Return and wrap errors instead of swallowing them or matching their text. Do not
panic in library code.

## Testing and performance

Behavior changes should have focused regression coverage. Security-sensitive
changes should include adversarial and failure-path cases. Do not add tests for
trivial wiring or duplicate the same assertion across several layers.

At minimum, substantive changes should pass:

```bash
go test ./...
go vet ./...
make security-assurance
git diff --check
```

Also run the affected script, documentation build, package build, race test, or
integration adapter when relevant. CI supplies Linux, macOS, Windows, packaging,
container, documentation, and policy checks.

Rampart runs in the tool-call path. For matcher, parser, proxy, hook, or audit
hot-path changes, measure a representative before/after benchmark with
allocations. A synthetic microbenchmark is useful only when it represents the
shipped policy and actual path being changed.

## Security review questions

For security-relevant work, describe the answers in the pull request:

- Can alternate casing, quoting, wrappers, symlinks, hard links, or path forms
  change what Rampart evaluates?
- Can a compound or multi-target action hide a more dangerous component?
- Does an error, timeout, malformed message, or persistence failure fail safely?
- Is the exact approved identity the identity that will execute?
- Could secrets or terminal controls reach logs, audit storage, APIs, SSE,
  dashboards, notifications, or errors?
- Does an upgrade preserve user state and repair only Rampart-owned state?

Never include credentials, personal host details, provider output, agent
memories, sessions, workspaces, or private test-lab evidence in a pull request.

## Integration contributions

Integration support must be described conservatively. Use current primary
upstream documentation or source, preserve unrelated host configuration, and
document host-owned timeout or crash behavior.

An adapter or generated configuration proves that Rampart's side works; it does
not prove that an authenticated host loaded the integration. Keep
[`assurance/integrations.yaml`](assurance/integrations.yaml), the support matrix,
integration guide, and verifier behavior synchronized.

Do not add credential-aware host runners or private environment details to this
repository. Public compatibility checks must be credential-free and
reproducible.

## Documentation sites

This repository owns two public sites:

- `rampart.sh` is served from `docs/` on `main`. Its landing page has one
  canonical source: [`docs/index.html`](docs/index.html).
- `docs.rampart.sh` is built by MkDocs from `docs-site/` and deployed by
  [`.github/workflows/docs.yml`](.github/workflows/docs.yml).

The MkDocs homepage is [`docs-site/index.md`](docs-site/index.md); it is not a
copy of the standalone landing page. User guides live in `docs-site/`. Small
files under `docs/guides/` and `docs/migration/` preserve old public URLs and
should remain redirects rather than duplicate guides.

The API reference, architecture, and threat model are canonical under `docs/`;
their MkDocs pages include those sources rather than copying them.

To build the documentation locally:

```bash
python -m pip install -r docs-requirements.txt
mkdocs build --strict
```

## Dependencies

Prefer the standard library. A new direct dependency needs maintainer agreement
and a pull-request explanation covering necessity, maintenance health, license,
binary impact, and security surface. Do not add a framework when a focused
existing package or standard-library solution is sufficient.

## Commit and pull-request guidance

Use a conventional prefix such as `feat:`, `fix:`, `docs:`, `test:`,
`refactor:`, `security:`, `ci:`, or `chore:`. Keep each commit and pull request
to one reviewable purpose.

A useful pull-request description answers:

- What changes for users?
- Why is this the smallest durable solution?
- What security or compatibility boundary is affected?
- What remains intentionally unsupported?
- Which exact checks were run?
- Did latency, allocations, binary size, or repository footprint change?

## Project layout

```text
cmd/rampart/cli/   CLI commands and integration orchestration
internal/engine/   Policy evaluation and matching
internal/proxy/    HTTP service, approvals, and API boundaries
internal/audit/    Hash-chained audit storage and exporters
internal/approval/ Approval state and replay handling
internal/mcp/      MCP JSON-RPC proxy
internal/bridge/   Host compatibility bridges
internal/plugin/   Embedded native integration plugins
pkg/sdk/           Public Go SDK
policies/          Shipped policy profiles
docs-site/         User documentation
assurance/         Public claim and regression manifests
```

The deny-wins rule is a core invariant: if any applicable policy denies an
action, the final decision is deny.

## License

By contributing, you agree that your contribution is provided under the
project's [Apache 2.0 license](LICENSE).
