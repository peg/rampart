# OpenClaw Approval Ownership

Status: proposed

## Problem

Rampart currently supports multiple approval mechanisms:

- OpenClaw native approvals (`exec.approval.requested` / Discord native approval UI)
- Rampart-native approval objects (`/v1/approvals`, dashboard/API/webhook flows)
- OpenClaw plugin `requireApproval` flows
- legacy OpenClaw exec dist patching that short-circuits into `/v1/tool/exec`

These mechanisms are individually valid, but they become unsafe and confusing when more than one human-facing approval object is created for the same tool call.

That exact split-brain behavior causes the current OpenClaw integration failure mode:

- a command is flagged by Rampart
- a Rampart approval object is created
- OpenClaw Discord native approvals look at OpenClaw's own approval queue instead
- Discord sees no pending approval, even though Rampart does

## Decision

For **OpenClaw-hosted workflows**, OpenClaw owns the operator-facing pending approval state.

Rampart owns:

- policy evaluation
- auto-resolution for allow/deny
- persistent rule writeback for `allow-always`
- audit trail
- diagnostics

Rampart does **not** create a second human-facing approval object for the same OpenClaw-hosted tool call.

For **non-OpenClaw workflows**, Rampart's native approval store remains canonical.

## Canonical ownership rules

### OpenClaw-hosted flow

1. OpenClaw determines that an exec/tool action requires approval.
2. OpenClaw creates the native pending approval record.
3. Discord/native approval surfaces read that native record.
4. Rampart bridge/plugin evaluates the request.
5. Rampart may:
   - auto-resolve allow
   - auto-resolve deny
   - leave the native approval pending for human review
6. If a human resolves it:
   - `allow-once` resolves the native approval only
   - `allow-always` resolves the native approval and writes a persistent Rampart rule
   - `deny` resolves the native approval only

### Rampart-hosted flow

Rampart's own approval store is canonical when the host runtime is not OpenClaw native approvals, for example:

- standalone dashboard/API approval workflows
- explicit `/v1/approvals` usage
- webhook or external review flows
- non-OpenClaw integrations

## Hard invariant

**Exactly one system may own the operator-facing pending approval object for a given tool call.**

Supporting metadata, audit events, and persistence helpers are fine. A second human-facing pending approval object is not.

## Consequences

### Allowed

- OpenClaw native approval object + Rampart policy evaluation
- OpenClaw native approval object + Rampart allow-always persistence
- Rampart-native approval object for non-OpenClaw workflows

### Forbidden

- OpenClaw native approval + Rampart-native approval for the same command
- OpenClaw plugin `requireApproval` + separate Rampart pending approval for the same action
- legacy exec dist patch that bypasses native OpenClaw approval creation by polling Rampart `/v1/tool/exec`

## Implementation direction

### 1. Bridge-first OpenClaw exec flow

`internal/bridge/openclaw.go` becomes the canonical OpenClaw exec approval seam:

- receive `exec.approval.requested`
- evaluate with Rampart engine
- auto-resolve allow/deny where possible
- leave native approval pending for human review
- persist allow-always after human resolution

### 2. Remove legacy exec short-circuiting

`cmd/rampart/cli/setup.go` must not install approval behavior that bypasses OpenClaw native approval creation for exec.

### 3. Keep plugin asks single-owned

`internal/plugin/openclaw/index.js` may use OpenClaw `requireApproval`, but it must not create or depend on a second Rampart pending approval object for the same action.

### 4. Doctor must detect drift

`rampart doctor` should detect:

- stale exec dist patch still installed
- bridge connected but native approval events absent
- dual-queue behavior in OpenClaw mode
- plugin loaded but ownership rules violated

### 5. Tests must enforce the contract

At least one end-to-end integration test should prove:

- OpenClaw native approval is created for an exec ask
- Rampart sees and evaluates it
- no second Rampart approval object is created for the same OpenClaw action
- allow-always writes a persistent rule
- subsequent matching command is silent

## Why this is the best UX

This preserves the operator's mental model:

- one approval card
- one approval ID
- one place to click
- one visible source of truth

Approvers stay in Discord where they already work, and Rampart makes that experience safer and smarter without introducing a second queue.
