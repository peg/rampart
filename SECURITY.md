# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| 1.7.x | ✅ Current release |
| 1.6.x | ⚠️ Critical fixes only |
| < 1.6 | ❌ No longer supported |

## Reporting a Vulnerability

If you discover a security vulnerability in Rampart, please report it responsibly.

**Email:** [rampartsec@pm.me](mailto:rampartsec@pm.me)

**What to include:**
- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Impact assessment (what can an attacker do?)
- Suggested fix (if you have one)

**What to expect:**
- **Acknowledgment** within 48 hours
- **Initial assessment** within 1 week
- **Fix timeline** communicated within 2 weeks
- **Coordinated disclosure** — we'll work with you on timing

**Please do NOT:**
- Open public GitHub issues for security vulnerabilities
- Disclose publicly before we've had time to respond
- Test against production systems you don't own

## Security Design

Rampart's threat model is documented in [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md). Key design principles:

- **Explicit degraded behavior** — failure behavior is integration-specific and
  documented; managed OpenClaw protection fails closed, while compatibility
  paths such as preload may fail open
- **Deny-wins evaluation** — any deny from any policy overrides all allows
- **Local-first by default** — Rampart has no telemetry or mandatory cloud
  dependency; explicitly configured notification, decision-webhook, semantic
  verification, and SIEM integrations send their documented data to the
  operator-selected endpoint
- **Hash-chained audit** — tamper-evident append-only trail with SIEM export

The machine-readable integration guarantees, evidence paths, known limitations,
and shared adversarial corpus live in [`assurance/`](assurance/README.md).

## Scope

The following are **in scope** for security reports:
- Policy engine bypasses (commands that should be denied but aren't)
- Audit trail integrity issues (undetected tampering)
- Authentication bypass on the HTTP API
- Privilege escalation through Rampart
- Information disclosure through error messages or logs

The following are **out of scope:**
- Denial of service against `rampart serve` (rate limiting is a known gap)
- Attacks requiring pre-existing root/admin access
- Social engineering
- Issues in dependencies (report upstream, but let us know)

## Bug Bounty

We don't currently have a formal bug bounty program. Significant findings will be credited in the changelog and release notes (with your permission).
