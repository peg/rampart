---
title: Security Posture Report
---

# Security Posture Report

`rampart report compliance` generates a security posture report that evaluates how well your Rampart deployment enforces key agent security controls.

## What it checks

The report evaluates four areas of Rampart's enforcement:

| Control | Name | What it checks |
|---------|------|----------------|
| RC-1 | Tool Call Authorization | All tool calls are evaluated against policy before executing |
| RC-2 | Audit Logging | A tamper-evident audit chain is maintained |
| RC-3 | Human-in-the-Loop | Sensitive operations require human approval |
| RC-4 | Data Exfiltration Prevention | Credential and sensitive path access is blocked |

These are Rampart's own controls — they are not part of an external compliance standard. If your organization needs to comply with frameworks like [AIUC-1](https://aiuc-1.com), [SOC 2](https://www.aicpa.org/soc2), or [NIST AI RMF](https://www.nist.gov/artificial-intelligence/risk-management-framework), this report can serve as supporting evidence but does not constitute certification.

## Generating a report

```bash
rampart report compliance
```

Example output (with audit logs):

```
Rampart Security Posture Report
================================
This report evaluates how well your Rampart deployment enforces key
agent security controls.
Learn more: https://docs.rampart.sh/guides/compliance/

Report ID: 3a1e1cc1-09b5-4641-b502-3ef8b1f9fc29
Generated: 2026-02-28T22:08:48Z
Period: 2026-01-29 to 2026-02-28
Rampart Version: v0.8.1
Standard: Rampart Security Posture
Overall Status: PASS

Decision Counts
---------------
Total: 1,247
Allow: 1,089 (87%)
Deny: 143 (11%)
Ask: 15 (1%)

Controls
--------
RC-1 PASS Tool Call Authorization
 - 1,247 tool calls evaluated against policy
 - 0 tool calls bypassed policy evaluation

RC-2 PASS Audit Logging
 - Audit chain verified: 1,247 events, 0 hash mismatches

RC-3 PASS Human-in-the-Loop
 - 15 ask decisions recorded in reporting period

RC-4 PASS Data Exfiltration Prevention
 - Policy covers: /etc/shadow, ~/.ssh/*, *.env, ~/.aws/credentials
```

## Status levels

| Status | Meaning |
|--------|---------|
| PASS | All four controls pass |
| PARTIAL | Some controls pass, some warn |
| FAIL | One or more controls fail |

!!! note
    A fresh installation with no audit history will show FAIL. This is expected — run Rampart with an agent to generate audit logs, then re-run the report.

## Date ranges

Scope the report to a specific period:

```bash
rampart report compliance --since 2026-02-01
rampart report compliance --since 2026-02-01 --until 2026-02-28
```

Dates use `YYYY-MM-DD` format. The default period is the last 30 days.

## JSON output

For CI pipelines or tooling integrations:

```bash
rampart report compliance --format json
rampart report compliance --format json --output posture-report.json
```

JSON output includes the full evidence array per control, suitable for internal audits or sharing with security teams.

## What each control evaluates

### RC-1 — Tool Call Authorization

Checks that Rampart is actively evaluating tool calls. Passes if:
- Audit logs exist with allow or deny decisions
- No evidence of policy bypass

### RC-2 — Audit Logging

Verifies the tamper-evident hash chain in audit logs. Each event's hash covers the previous event's hash — if any event is modified or deleted, chain verification fails.

### RC-3 — Human-in-the-Loop

Checks that `ask` decisions exist in the audit log during the period. Passes if at least one human approval was requested.

If all sensitive operations are auto-denied rather than asking for approval, this control will warn. Consider using `action: ask` for borderline operations.

### RC-4 — Data Exfiltration Prevention

Checks that the active policy contains rules blocking access to credential paths (`/etc/shadow`, `~/.ssh/*`, `*.env`, `~/.aws/credentials`, etc.).

This check uses keyword proximity heuristics on the policy file — manual review of your policy is recommended for full assurance.

## Sharing with security teams

The JSON report includes:

- Report ID (UUID for tracking)
- Generation timestamp and Rampart version
- Audit period and decision counts
- Per-control status and evidence array
- Chain verification result

Export and share:

```bash
rampart report compliance --format json --output posture-$(date +%Y-%m-%d).json
```

## Improving your posture

1. **RC-1**: Ensure Rampart hooks are installed and active (`rampart doctor`)
2. **RC-2**: Ensure audit logging is enabled (on by default)
3. **RC-3**: Use `action: ask` for sensitive operations instead of always-deny
4. **RC-4**: Use `rampart init --profile standard` or ensure your policy covers credential paths

Run `rampart doctor` to verify your setup before generating a report.

## Relationship to compliance frameworks

Rampart's security posture report is designed to provide evidence that can support compliance with external frameworks:

- **[AIUC-1](https://aiuc-1.com)**: Tool call authorization, audit logging, and human oversight align with AIUC-1's security and accountability principles
- **SOC 2**: Tamper-evident audit chain and access controls support Trust Services Criteria
- **NIST AI RMF**: Policy enforcement and monitoring support the Govern and Measure functions

However, Rampart does not certify compliance with any external standard. Compliance determinations require assessment by qualified auditors against the full requirements of each framework.
