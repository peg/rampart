# Linux E2E Lab

The Linux lab turns a Rampart commit into repeatable test evidence. The lab
runner accepts only an immutable 40-character commit SHA, creates a detached
worktree, runs the selected suite, and retains logs and metadata outside the
checkout.

## VM prerequisites

- A dedicated, snapshotted Linux VM or test account
- `git`, Go, Python 3, Node.js, a C compiler, `curl`, and development libcurl
- Docker for the isolated OpenClaw suite and an installed Hermes runtime for installed-Hermes validation
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
| `openclaw-runtime` | Disposable official OpenClaw container, exact zero-config install, 12 safe canaries, and idempotency proof |
| `openclaw` | `core` plus the disposable OpenClaw container acceptance test |
| `full` | Core, runtime, Hermes, and disposable OpenClaw coverage |

The OpenClaw runtime suites run the official OpenClaw image in a new disposable
container. Only the candidate Rampart binary is mounted read-only. The state,
workspace, plugin, policies, Rampart token, gateway, and policy service all live
inside the container and are deleted after evidence is collected. No host
OpenClaw configuration, credentials, memories, sessions, databases, workspaces,
or user services are read or modified.

The acceptance step records the OpenClaw image metadata and digest, the first
zero-config installation log, a machine-readable 12-canary report, a second
idempotency run, the resulting non-secret plugin configuration, and installed
file checksums.

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
