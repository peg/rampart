# OpenClaw Approval Implementation Checklist

This checklist tracks the work required to align Rampart's OpenClaw integration with the approval ownership decision in `openclaw-approval-ownership.md`.

## Goal

For OpenClaw-hosted workflows:

- OpenClaw owns pending approval state and operator UI
- Rampart owns evaluation, auto-resolution, persistence, audit, and diagnostics
- no dual-queue approval behavior exists for the same tool call

---

## A. Setup and install path

### A1. Remove legacy exec approval short-circuiting
- [ ] Keep `cmd/rampart/cli/setup.go:patchExecInDist()` as a no-op for approval handling
- [ ] Ensure `rampart setup openclaw` no longer installs exec approval behavior that calls `/v1/tool/exec` before OpenClaw creates a native approval
- [ ] Add regression test coverage around setup output / install behavior

### A2. Migration / cleanup path
- [ ] Add a repair path to remove stale legacy exec dist approval patches from existing OpenClaw installs
- [ ] Document how to restore native OpenClaw exec approval flow on machines already patched with the old design
- [ ] Make `rampart doctor --fix` able to remove or warn on stale patches

---

## B. Bridge path (`internal/bridge/openclaw.go`)

### B1. Confirm canonical OpenClaw exec flow
- [ ] Treat `exec.approval.requested` as the canonical exec approval hook for OpenClaw-hosted flows
- [ ] Preserve current auto-resolution behavior for allow/deny
- [ ] Preserve native OpenClaw approval object as the pending object for human review

### B2. Human review path
- [ ] Revisit `escalateToServe()` and confirm whether it creates only backend review state, not a competing operator-facing approval object
- [ ] If needed, refactor escalation so Rampart can track policy review state without presenting a second approval object to the operator
- [ ] Ensure `allow-always` writes rules cleanly after native OpenClaw resolution

### B3. Logging and observability
- [ ] Add clearer logs around receipt of native approval events
- [ ] Log when Rampart auto-resolves vs leaves pending for human review
- [ ] Log when a second approval object would have been created, and prevent it

---

## C. Plugin path (`internal/plugin/openclaw/index.js`)

### C1. Keep plugin approvals single-owned
- [ ] Ensure plugin `ask` uses OpenClaw `requireApproval`
- [ ] Ensure plugin path does not create or depend on a separate Rampart pending approval object for the same action
- [ ] Keep `allow-always` persistence writeback only

### C2. Plugin-mode diagnostics
- [ ] Add debug logs that make ownership visible during plugin approval flows
- [ ] Detect if plugin path still receives `approval_id` from `/v1/tool/*` and treat that as a bug in OpenClaw-hosted mode

---

## D. Proxy path (`internal/proxy/eval_handlers.go`, `internal/proxy/approval_handlers.go`)

### D1. Separate OpenClaw-hosted from Rampart-hosted flows
- [ ] Make it explicit which callers are allowed to create native Rampart approval objects
- [ ] Ensure OpenClaw-hosted approval flows do not use `/v1/tool/exec` pending approvals as canonical operator state
- [ ] Preserve Rampart approval store for dashboard/API/non-OpenClaw integrations

### D2. Clarify API semantics
- [ ] Document that `/v1/tool/*` approval creation is for Rampart-native approval workflows, not OpenClaw-native operator approvals
- [ ] Document `/v1/approvals` as standalone/native Rampart review surface only

---

## E. Doctor / operator experience

### E1. Add checks
- [ ] Detect stale exec dist patch still installed
- [ ] Detect bridge connected but native approval queue bypassed
- [ ] Detect plugin loaded but dual-queue behavior active
- [ ] Detect missing native approval delivery expectations for Discord/OpenClaw mode

### E2. Add fixes or recommendations
- [ ] `rampart doctor` should explain the canonical ownership model plainly
- [ ] `rampart doctor --fix` should be able to remove stale approval patching where safe

---

## F. Tests

### F1. End-to-end approval contract
- [ ] Add an integration test that proves an OpenClaw exec ask creates a native OpenClaw approval object
- [ ] Assert Rampart sees and evaluates the native approval event
- [ ] Assert no second Rampart-native pending approval is created for the same OpenClaw action
- [ ] Assert allow-always writes a persistent rule
- [ ] Assert a repeated matching command runs without prompting

### F2. Regression coverage
- [ ] Add test coverage for stale-patch detection
- [ ] Add plugin approval ownership regression tests
- [ ] Add bridge escalation behavior tests around human review and allow-always

---

## G. Docs and messaging

### G1. Update docs
- [ ] Align `docs/guides/openclaw-approval.md` with the ownership decision
- [ ] Remove any wording that implies dual approval ownership is acceptable
- [ ] Add a migration section for older patched installs

### G2. Product messaging
- [ ] Define the UX principle: one review surface, one approval object, one mental model
- [ ] Make Discord/OpenClaw the clear operator-facing approval product for OpenClaw-hosted workflows

---

## Suggested execution order

1. Setup cleanup (`patchExecInDist`, stale patch migration)
2. Bridge ownership audit
3. Plugin ownership audit
4. Doctor checks
5. End-to-end test
6. Docs cleanup
