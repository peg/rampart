---
title: AIUC-1 Compliance Reporting
description: Generate evidence-based compliance reports for the AI Unified Controls v1 standard.
---

# AIUC-1 Compliance Reporting

`rampart report compliance` generates a compliance evidence report for the [AIUC-1 standard](https://aiuc-1.com) — the first compliance framework for AI agent operations.

## What is AIUC-1?

AIUC-1 (AI Unified Controls v1) defines four controls for demonstrating that AI agents operate under human oversight:

| Control | Name | What it checks |
|---------|------|----------------|
| AIUC-1.1 | Tool Call Authorization | All tool calls are evaluated against policy before executing |
| AIUC-1.2 | Audit Logging | A tamper-evident audit chain is maintained |
| AIUC-1.3 | Human-in-the-Loop | Sensitive operations require human approval |
| AIUC-1.4 | Data Exfiltration Prevention | Credential and sensitive path access is blocked |

ElevenLabs became the first AIUC-1 certified organization in February 2026. Audit firms offering AIUC-1 assessments include 360 Advanced and Schellman.

## Generating a report

```bash
rampart report compliance
```

Example output (fresh install with audit logs):

```
AIUC-1 Compliance Report
========================
Report ID:  3a1e1cc1-09b5-4641-b502-3ef8b1f9fc29
Generated:  2026-02-28T22:08:48Z
Period:     2026-01-29 to 2026-02-28
Version:    v0.7.0
Standard:   AIUC-1
Status:     COMPLIANT

Decision Counts
---------------
Total:  1,247
Allow:  1,089  (87%)
Deny:   143    (11%)
Ask:    15     (1%)

Controls
--------
AIUC-1.1 PASS Tool Call Authorization
  - 1,247 tool calls evaluated against policy
  - 0 tool calls bypassed policy evaluation

AIUC-1.2 PASS Audit Logging
  - Audit chain verified: 1,247 events, 0 hash mismatches

AIUC-1.3 PASS Human-in-the-Loop
  - 15 ask decisions recorded in reporting period

AIUC-1.4 PASS Data Exfiltration Prevention
  - Policy covers: /etc/shadow, ~/.ssh/*, *.env, ~/.aws/credentials
```

## Status levels

| Status | Meaning |
|--------|---------|
| `COMPLIANT` | All four controls pass |
| `PARTIAL` | Some controls pass, some warn |
| `NON-COMPLIANT` | One or more controls fail |

> **Note:** A fresh installation with no audit history will show `NON-COMPLIANT`. This is expected — run Rampart with an agent to generate audit logs, then re-run the report.

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
rampart report compliance --format json --output aiuc1-report.json
```

JSON output includes the full evidence array per control, suitable for sharing with auditors.

## What each control evaluates

### AIUC-1.1 — Tool Call Authorization

Checks that Rampart is actively evaluating tool calls. Passes if:
- Audit logs exist with `allow` or `deny` decisions
- No evidence of policy bypass

### AIUC-1.2 — Audit Logging

Verifies the tamper-evident hash chain in audit logs. Each event's hash covers the previous event's hash — if any event is modified or deleted, chain verification fails.

### AIUC-1.3 — Human-in-the-Loop

Checks that `ask` decisions exist in the audit log during the period. Passes if at least one human approval was requested.

> If all sensitive operations are auto-denied rather than asking for approval, this control will warn. Consider using `action: ask` for borderline operations.

### AIUC-1.4 — Data Exfiltration Prevention

Checks that the active policy contains rules blocking access to credential paths (`/etc/shadow`, `~/.ssh/*`, `*.env`, `~/.aws/credentials`, etc.).

> This check uses keyword proximity heuristics on the policy file. It is labeled as a heuristic in the output — manual review by an auditor is recommended for full assurance.

## Sharing with auditors

The JSON report includes:
- Report ID (UUID for tracking)
- Generation timestamp and Rampart version
- Audit period and decision counts
- Per-control status and evidence array
- Chain verification result

Export and share:

```bash
rampart report compliance --format json --output aiuc1-$(date +%Y-%m-%d).json
```

## Achieving COMPLIANT status

1. **AIUC-1.1**: Ensure Rampart hooks are installed and active (`rampart doctor`)
2. **AIUC-1.2**: Ensure audit logging is enabled (on by default)
3. **AIUC-1.3**: Use `action: ask` for sensitive operations instead of always-deny
4. **AIUC-1.4**: Use `rampart init --profile standard` or ensure your policy covers credential paths

Run `rampart doctor` to verify your setup before generating a compliance report.
