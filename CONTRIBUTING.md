# Contributing to Rampart

Thanks for helping make AI agents safer. Small contributions are welcome:
a clear bug report, a docs fix, a platform fix, or one focused regression test.

Rampart is a security boundary, so we review carefully. What we look for is
code that is short, easy to read and easy to verify. A change that deletes
code and keeps behavior is often the best kind.

## Quick start

You need the Go version in [`go.mod`](go.mod).

```bash
git clone https://github.com/peg/rampart && cd rampart
git checkout staging
go build -o rampart ./cmd/rampart
go test ./...
```

Before you open a pull request, also run:

```bash
go vet ./...
make security-assurance
git diff --check
```

CI covers Linux, macOS, Windows, packaging, the container and the docs.

## Good places to start

- **Try Rampart with a local model** (Ollama, LM Studio, llama.cpp) and report
  what the model tried and what Rampart decided. Start with
  [Local models](docs-site/integrations/local-models.md).
- **Keep an integration working** with the latest release of its agent
  (Claude Code, Codex, OpenCode, Cline and others).
- **Fix a cross-platform bug**, especially on Windows.
- **Simplify**: remove duplication or dead paths without changing behavior.
- **Docs and error messages** that confused you are worth fixing.

## Before you start

- **Security bugs go to [SECURITY.md](SECURITY.md), never a public issue.**
  That includes bypasses, policy evasion and credential exposure.
- Small fixes can go straight to a pull request.
- For a new integration, a big behavior change or a rewrite, open an issue
  first so we agree on the approach before you spend time on it.

## Workflow

1. Branch from `staging` and open your pull request against `staging`.
   `main` holds releases and is maintainer-managed.
2. Keep one purpose per pull request. Use a conventional prefix such as
   `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `security:` or `chore:`.
3. Open it as a draft while iterating. Drafts get a fast Linux check; marking
   it ready runs the full matrix.
4. Fill in the pull request template: what changes for users, what you ran,
   and what it does not cover.

## How we write code

- Prefer the standard library and existing helpers. A new dependency needs a
  reason (necessity, license, maintenance, binary size).
- Fail closed: when Rampart owns a decision and cannot parse, classify or
  persist it, the answer is deny.
- Deny wins. Every target in a compound action is evaluated, and the most
  restrictive decision applies.
- Preserve the user's other configuration when installing or removing an
  integration.
- Comments explain why, not what. Wrap and return errors; do not panic in
  library code.
- Add a focused regression test for behavior changes. Security changes need
  adversarial and failure cases. Skip tests for trivial wiring.
- For hot-path changes (matcher, parser, hook, proxy, audit), include a
  before-and-after benchmark with allocations.

### Security changes

Answer these in the pull request:

- Can casing, quoting, wrappers, symlinks or other path forms change what
  Rampart evaluates?
- Can a compound action hide a more dangerous part?
- Does an error, timeout or malformed message fail safely?
- Is the approved action exactly the one that runs?
- Could secrets reach logs, audit records, the API or notifications?

### Integrations

Describe support conservatively and base it on the agent's current docs or
source. A working adapter proves Rampart's side, not that the agent loaded it.
Keep [`assurance/integrations.yaml`](assurance/integrations.yaml), the docs
page and `rampart verify` in sync. Compatibility checks must not need
credentials.

## Docs

User docs live in `docs-site/` and build with MkDocs. The build also needs
[D2](https://d2lang.com) on your `PATH` for the architecture diagram; use the
version pinned in [`.github/workflows/docs.yml`](.github/workflows/docs.yml).

```bash
python -m pip install -r docs-requirements.txt
mkdocs build --strict
```

The landing page at rampart.sh is `docs/index.html`. The API reference,
architecture and threat model live in `docs/` and are included by the docs site.

## Project layout

```text
cmd/rampart/cli/   CLI commands and integration setup
internal/engine/   Policy evaluation and matching
internal/proxy/    HTTP service and approvals API
internal/audit/    Hash-chained audit log
internal/approval/ Approval state
internal/mcp/      MCP proxy
internal/plugin/   Embedded agent plugins
pkg/sdk/           Public Go SDK
policies/          Built-in policy profiles
docs-site/         User documentation
assurance/         Integration claims and their evidence
```

## Privacy

Never include credentials, real hostnames, personal paths, agent sessions,
prompts or memories in issues, pull requests or test fixtures. Use synthetic
values.

## License

By contributing, you agree that your contribution is licensed under the
project's [Apache 2.0 license](LICENSE).
