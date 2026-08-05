# OpenClaw release acceptance

This is the canonical maintainer checklist for OpenClaw release evidence. User
installation and troubleshooting belong in the
[OpenClaw integration guide](https://docs.rampart.sh/integrations/openclaw/);
general lab operation belongs in [`docs/LINUX-E2E-LAB.md`](../LINUX-E2E-LAB.md).

## Automated candidate gate

Run the isolated container suite against the exact candidate commit:

```bash
scripts/lab/run-e2e.sh --sha <40-character-sha> --suite openclaw
```

The gate must resolve the current stable OpenClaw npm package, install that
exact version in a disposable official container, complete all 12 behavioral
canaries, and pass a second idempotent setup. A passing harness script is not a
completed result; retain the candidate SHA, resolved OpenClaw version, summary,
canary report, and checksums.

## Credentialed native-runtime proof

This opt-in check invokes a configured model and must run only with disposable
state and a dedicated test login. It is separate from ordinary CI.

Prepare a private isolation root and log in normally inside it. Never copy an
agent home, `auth.json`, `auth-profiles.json`, refresh token, or production
credential into the root. Before starting the isolated gateway, configure
`plugins.entries.rampart` with `enabled: true`,
`serveUrl: http://127.0.0.1:19090`, and `failOpen: false`.

The root must be mode `0700`. Add a mode-`0600`
`credential-isolation.json` operator declaration:

```json
{
  "schema_version": 1,
  "purpose": "rampart-openclaw-codex-e2e",
  "credential_source": "dedicated-test-login",
  "production_credentials_copied": false
}
```

The declaration is an explicit operator acknowledgement, not proof of account
separation. A dedicated machine or operating-system account remains the
strongest boundary.

Run:

```bash
export RAMPART_OPENCLAW_ISOLATION_ROOT=/path/to/disposable/root
export HOME="$RAMPART_OPENCLAW_ISOLATION_ROOT/home"
export CODEX_HOME="$HOME/.codex"
export OPENCLAW_STATE_DIR="$HOME/.openclaw"
export OPENCLAW_CONFIG_PATH="$OPENCLAW_STATE_DIR/openclaw.json"
RAMPART_OPENCLAW_RUNTIME=1 \
RAMPART_OPENCLAW_RESTART_SERVICES= \
node scripts/test-openclaw-codex-native-audit.mjs
```

The script refuses primary or outside-root agent state, symlink escapes,
non-private roots, inherited credential variables, service restarts, and raw
artifact retention. Candidate processes receive an allowlisted environment.

The proof passes only when all three actions have correlated OpenClaw
trajectory and Rampart audit records:

- an allowed native Codex `bash` call executes;
- an `allow-once` approval resumes and executes the exact pending call; and
- a denied native `bash` call leaves its disposable canary unchanged.

Command output or an assistant response alone is not evidence that the action
crossed Rampart's policy boundary.

## Manual product check

Before promoting a release that claims the native approval experience is
verified, confirm one approval in a real supported OpenClaw client:

- exactly one user-facing approval is created;
- allow once, deny, and timeout have the documented outcome;
- allow always writes a rule to `~/.rampart/policies/user-overrides.yaml`; and
- a matching future action uses that learned rule without a second queue.

## Release bar

- Exact-candidate CI and the OpenClaw container gate are green.
- The resolved stable OpenClaw version is recorded.
- Native-runtime evidence is current when the support tier depends on it.
- No failed credential scan or raw credentialed artifact is published.
- The support matrix and `assurance/integrations.yaml` describe the same
  verified boundary and limitations.
