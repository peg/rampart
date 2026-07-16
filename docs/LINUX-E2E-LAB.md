# Linux E2E Lab

The Linux lab turns a Rampart commit into repeatable test evidence. The lab
runner accepts only an immutable 40-character commit SHA, creates a detached
worktree, runs the selected suite, and retains logs and metadata outside the
checkout.

## VM prerequisites

- A dedicated, snapshotted Linux VM or test account
- `git`, Go, Python 3, Node.js, a C compiler, `curl`, and development libcurl
- Installed OpenClaw and Hermes runtimes for their live suites
- A clean clone of `https://github.com/peg/rampart.git`

Do not register a persistent lab containing credentials as an unrestricted
self-hosted runner for a public repository. Invoke the lab through a controlled
SSH account or a protected workflow.

## Run a commit

From the controller clone on the VM:

```bash
scripts/lab/run-e2e.sh \
  --sha 0123456789abcdef0123456789abcdef01234567 \
  --suite e2e
```

Suites are cumulative only where stated:

| Suite | Coverage |
| --- | --- |
| `core` | Go tests/vet/build, policy validation, Hermes plugin unit tests, OpenClaw plugin regressions |
| `runtime` | Approval API flow and enforced Linux preload behavior, without repeating `core` |
| `e2e` | `core`, approval API flow, and enforced Linux preload behavior |
| `hermes-runtime` | Installed or latest Hermes compatibility without repeating `core` |
| `hermes` | `core` plus latest-Hermes compatibility, or an installed environment supplied with `--hermes-python` |
| `openclaw-runtime` | Reserved for the isolated installed OpenClaw/Codex runtime regression |
| `openclaw` | Reserved for `core` plus isolated OpenClaw coverage |
| `full` | Reserved for all coverage after isolated OpenClaw support lands |

The OpenClaw runtime suites currently fail closed. The older regression edited
the primary config, wrote a primary-agent session, and restarted user services;
that is not acceptable on a working agent. Before these suites are enabled, the
runner must create a disposable OpenClaw state tree and workspace beneath the
run root, disable memory/session hooks there, perform a local agent turn, and
prove that the primary state tree was unchanged. Installed binaries and
read-only credential material may be reused, but primary memories, sessions,
workspaces, databases, configuration, and services must never be modified.

To validate the VM's installed Hermes environment instead of downloading the
latest package into a temporary virtual environment, provide its interpreter
and optional CLI path:

```bash
scripts/lab/run-e2e.sh \
  --sha <sha> \
  --suite hermes \
  --hermes-python /path/to/hermes/venv/bin/python \
  --hermes-bin /path/to/hermes/venv/bin/hermes
```

By default, results are stored under:

```text
~/.local/state/rampart-lab/runs/<run-id>/artifacts/
```

Each result contains `summary.json`, `environment.json`, `events.jsonl`, one
log per step, audit records produced by the preload check, and SHA-256 checksums.
The runner returns a nonzero status if any required step fails.

## Invoke over SSH

After configuring a local SSH alias such as `rampart-lab`:

```bash
ssh rampart-lab \
  '~/rampart/source/scripts/lab/run-e2e.sh --sha <sha> --suite e2e'
```

The first VM session should be a read-only inventory. Confirm actual executable
paths, user-service names, agent state locations, and whether the installed
Hermes runtime uses a dedicated Python environment before enabling live suites.
