# OpenClaw approval-path acceptance checklist

This checklist exists to validate the polished minor-version path for Rampart's OpenClaw integration.

## Goal

Rampart owns policy decisioning, audit, and durable allow learning.
OpenClaw owns approval UX, native cards/buttons, and approval lifecycle.

## Deterministic local checks

Run from the repo root.

### 1. Plugin smoke test

```bash
node internal/plugin/openclaw/smoke-test.mjs
```

Pass criteria:
- `exec` + `ask` returns `requireApproval`
- no legacy `params.ask = "always"` path

### 2. Approval regression suite

```bash
node internal/plugin/openclaw/approval-regression.mjs
```

Pass criteria:
- `ask` returns `requireApproval`
- `deny` returns `block: true`
- `allow-always` persists learned rule intent via `/v1/rules/learn`

### 3. Build

```bash
go build ./cmd/rampart
```

Pass criteria:
- build completes successfully

## Installed integration checks

### 4. Reinstall plugin

```bash
go build -o ~/.local/bin/rampart ./cmd/rampart
~/.local/bin/rampart setup openclaw
systemctl --user restart openclaw-gateway.service
systemctl --user restart rampart-serve.service
systemctl --user is-active openclaw-gateway.service
systemctl --user is-active rampart-serve.service
```

Pass criteria:
- plugin installs cleanly
- gateway returns `active`
- rampart serve returns `active`
- sensitive tools do not silently fail open when serve is unavailable

## Real product validation

### 5. Native Discord approval card

Validate with one real Discord DM case that becomes a real tool invocation.

Pass criteria:
- approval object is created
- native Discord approval box appears
- approval is clearly associated with the current DM/session

### 6. Decision outcomes

Pass criteria:
- allow once succeeds
- deny blocks execution
- allow always writes durable learned rule to `~/.rampart/policies/user-overrides.yaml`
- no hidden second approval queue is created by Rampart

### 7. Live three-state proof

Validate one case for each state:
- allow: a previously learned command like `sudo true`
- ask: a new privileged command like `sudo id`
- deny: a destructive command like `rm -rf /tmp`

Pass criteria:
- learned allow executes without prompting
- new privileged command prompts and user choice is respected
- destructive command is hard-blocked by policy

## Ship bar for the minor

Do not ship until all of the following are true:

- deterministic local checks pass
- plugin installs cleanly on a fresh reinstall
- one real native Discord approval box appears on the cleaned path
- allow/deny/allow-always semantics are confirmed
- durable writeback is verified in `~/.rampart/policies/user-overrides.yaml`
- documentation reflects that plain chat text is not itself a tool call
- documentation reflects that `rampart serve` must be healthy for approval-path validation

## Non-goals

- using natural-language DM prompts as the main regression harness
- reintroducing a separate Rampart-owned pending approval queue for OpenClaw-hosted tool calls
- special-casing `exec` away from the unified approval contract
