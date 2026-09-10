---
title: Security Posture Report
---

# Security Posture Report

`rampart report compliance` summarizes local audit and policy evidence. It does
not certify enforcement, human oversight, or compliance with an external
standard. The `compliance` command name remains for compatibility.

## Generate a report

```bash
rampart report compliance
rampart report compliance --since 2026-02-01 --until 2026-02-28
rampart report compliance --format json --output posture-report.json
```

Dates use `YYYY-MM-DD`. The default reporting period is the last 30 days.
The JSON report includes the period, Rampart version, decision counts and
per-control evidence. Review it before sharing: evidence can include local
audit and policy paths.

## What the controls establish

| Control | Evidence collected | Limit |
|---------|--------------------|-------|
| RC-1 — Tool Call Authorization | Audit events within the reporting period | Events do not prove that every host action was evaluated or that the host enforced each decision. |
| RC-2 — Audit Logging | Hash-chain validation across available audit files, plus consistency checks for any local anchors | Local consistency does not establish that all original events or anchors are present. |
| RC-3 — Human-in-the-Loop | Number of `ask` and legacy `require_approval` decisions | A request does not prove that a human reviewed or resolved it, or that the host enforced the result. |
| RC-4 — Data Exfiltration Prevention | Sensitive-path keywords near deny text in the supplied policy file | This heuristic does not validate policy syntax, loaded configuration, rule matching, or actual prevention. |

RC-1, RC-3 and RC-4 report **WARN** when evidence is available because those
observations cannot prove enforcement. Finding more requests or policy keywords
does not turn them into a passing assurance claim. RC-2 can report **PASS** when
the available local chain and anchors validate.

An otherwise healthy installation will therefore normally produce an overall
**PARTIAL** result. This means additional evidence is needed; it is not a reason
to weaken policy. A deployment that denies every forbidden action may correctly
have no approval requests.

## Status levels

| Status | Meaning |
|--------|---------|
| PASS | The stated check passed within its documented boundary. |
| WARN | The evidence is missing or insufficient to establish the control. |
| PARTIAL | Overall result when at least one control warns and none fail. |
| FAIL | A required local check failed or audit logs were unavailable. |

A fresh installation without audit logs reports FAIL because there is no audit
chain to inspect. An empty, valid audit file can pass chain validation while the
other controls remain unproven.

## Follow up on the evidence

- **RC-1:** Check installation with `rampart doctor`, then validate harmless
  allowed and denied actions through the actual host. Consult the
  [support matrix](../getting-started/support-matrix.md) for each verifier's limits.
- **RC-2:** Run `rampart audit verify` to inspect local chain integrity. For
  evidence held outside the local machine, see
  [external witnessing](../features/external-witness.md).
- **RC-3:** Validate complete redacted review, denial, expiry and allow-once
  behavior through the host's approval flow. Keep deny rules for actions that
  must remain forbidden; do not replace them with asks to improve report counts.
- **RC-4:** Review the active policy and safely verify representative
  sensitive-path denials. A matching keyword is not proof that a rule applies.

The report can support an organization's assessment alongside deployment
configuration and behavioral evidence. It cannot make a compliance determination
on its own.
