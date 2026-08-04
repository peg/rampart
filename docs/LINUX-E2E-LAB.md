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

The OpenClaw runtime suites start from the official OpenClaw image, resolve the
current stable npm dist-tag to an exact version, and install that version in a
new disposable container. This prevents a lagging container tag from silently
testing an older package than users receive. The controller cross-builds
Rampart for the Docker daemon's Linux architecture, so this isolated suite can
also run from a macOS controller. Only the candidate Rampart binary is mounted
read-only. The state, workspace, plugin, policies, Rampart token, gateway, and
policy service all live inside the container and are deleted after evidence is
collected. No host OpenClaw configuration, credentials, memories, sessions,
databases, workspaces, or user services are read or modified.

The acceptance step records the OpenClaw image metadata and digest, resolved npm
package metadata and installed version, the first zero-config installation log,
a machine-readable 12-canary report, a second idempotency run, the resulting
non-secret plugin configuration, and installed file checksums.

## Opt-in real host proofs

The normal lab suites do not spend model tokens or copy user credentials.
Two separate opt-in harnesses exercise real host boundaries with disposable
state:

```bash
scripts/compat-hermes-host.sh --yes
scripts/compat-claude-host.sh --yes
```

Use `scripts/compat-hermes-host.sh --yes --gateway` to exercise the same two
Hermes canaries through an isolated localhost API gateway rather than the
direct one-shot CLI. It does not connect the source profile's Telegram,
Discord, or other messaging gateways.
Gateway mode refuses `--copy-env` so an isolated run cannot accidentally load
live messaging-platform tokens; it requires an `auth.json`-backed provider.

The Hermes harness copies only `auth.json` and non-secret model selection by
default. Env-only providers require explicit `--copy-env`. It does not load
source memories, sessions, rules, skills, gateways, MCP servers, workspaces, or
plugins. The Claude harness uses a disposable home and copies only
`.credentials.json` on Linux/Windows when present. A macOS Keychain login is not
resolvable from the disposable home in Claude Code 2.1.220, so the harness
requires an ephemeral `CLAUDE_CODE_OAUTH_TOKEN` environment value for an
authenticated macOS proof. Subprocess environment scrubbing prevents Bash from
receiving that token. The harness excludes source settings, sessions, memories,
plugins, MCP servers, and project instructions.

Both harnesses run one deny and one allow canary, remove their disposable
runtime, and optionally retain sanitized evidence with `--artifacts DIR`.

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

The runner creates its run tree with private permissions, clears the inherited
environment before candidate tests, and scans every retained text artifact for
credential filenames, private keys, provider tokens, JWTs, authorization
headers, credentialed URLs, and secret assignments. `credential-scan.json`
records only finding types and relative paths; it never reproduces a matched
value. Any finding changes the run to failed. Do not publish or upload artifacts
from a failed credential scan.

## Invoke over SSH

After configuring a local SSH alias such as `rampart-lab`:

```bash
ssh rampart-lab \
  '~/rampart/source/scripts/lab/run-e2e.sh --sha <sha> --suite e2e'
```

The first VM session should be a read-only inventory. Confirm actual executable
paths, user-service names, agent state locations, and whether the installed
Hermes runtime uses a dedicated Python environment before enabling live suites.
