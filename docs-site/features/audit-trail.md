---
title: Audit Trail
description: "Inspect Rampart policy decisions in a local hash-chained audit trail. Verify retained history, stream events, and understand the limits of local evidence."
---

# Audit Trail

Rampart records evaluated tool calls in a local hash-chained JSONL audit trail.
Each entry includes a SHA-256 hash of the previous entry. The trail records
decisions at the configured integration boundary; it does not prove that an
allowed process executed exactly as intended or expose actions outside that
boundary.

## Why Hash-Chained?

A hash chain makes inconsistent event hashes and broken links detectable.
An identity that can replace all local records and checkpoints can still
construct a different valid history. Independent retention is needed to
detect that rewrite; hashing alone does not make files immutable.

## Viewing the Audit Trail

```bash
# Stream events in real time
rampart audit tail --follow

# Last 50 events
rampart audit tail

# Check chain integrity
rampart audit verify

# Decision breakdown
rampart audit stats

# Search by tool, agent, decision, or time range
rampart audit search --tool exec --decision deny
```

## Live Dashboard

```bash
rampart watch
```

```
╔══════════════════════════════════════════════════════════════╗
║  RAMPART — enforce — 3 policies                             ║
╠══════════════════════════════════════════════════════════════╣
║  ✅ 21:03:42 exec  "git push origin main"     [allow-git]   ║
║  ✅ 21:03:41 read  ~/project/src/main.go      [default]     ║
║  🔴 21:03:38 exec  "rm -rf /tmp/*"            [protect-sys] ║
║  ✅ 21:03:35 exec  "npm test"                 [allow-dev]   ║
║  🟡 21:03:33 exec  "curl https://api.io"      [log-http]    ║
╠══════════════════════════════════════════════════════════════╣
║  1,247 total │ 1,201 allow │ 12 deny │ 34 log               ║
╚══════════════════════════════════════════════════════════════╝
```

## Log Format

Each event is a JSON line:

```json
{
  "id": "01HQXYZ...",
  "timestamp": "2026-02-11T21:03:38Z",
  "tool": "exec",
  "request": {"command": "rm -rf /tmp/*"},
  "decision": {
    "action": "deny",
    "matched_policies": ["protect-sys"],
    "evaluation_time_us": 8,
    "message": "Destructive command blocked"
  },
  "agent": "claude-code",
  "session": "abc123",
  "prev_hash": "sha256:a1b2c3..."
}
```

Response-side evaluations are separate events so an initial allow and a later
redaction cannot be confused. These events set `request.rampart_phase` to
`response`, link back through `request.request_audit_id`, record only
`response_bytes` (not the raw output), and include `response.flags` such as
`response-evaluated` or `response-redacted`.

## Storage

- **Location:** `~/.rampart/audit/` (configurable)
- **Format:** JSONL (one JSON object per line)
- **Rotation:** Daily files with chain continuity across files
- **IDs:** ULID (time-ordered, sortable)
- **Integrity:** Local `audit-anchor.json` checkpoint every 100 events by default, stored beside the logs
- **Durability:** long-running service writes use `fsync`; short-lived native hooks use the same cross-process chain lock and a validated tail checkpoint, then rely on normal OS flush behavior to avoid adding an `fsync` delay to every agent tool call

## HTML Reports

Generate a human-readable report:

```bash
rampart report
```

## Tamper Detection

Verification checks retained event hashes, links, and local checkpoints. A
complete rewrite with a new valid chain is not detectable from the local
history alone. Neither is deletion of a valid suffix beyond the retained
checkpoint. Verification also cannot establish that every action was logged.

`rampart serve` verifies the complete chain when it starts. One-shot native
hooks validate the current checkpoint, file size, and tail record before
appending; if that checkpoint is missing or stale, they fall back to complete
recovery. Run `rampart audit verify` whenever you need an explicit full-history
integrity check.

For stronger guarantees:

- For centralized HTTP/SDK deployments, run `rampart serve` as a [separate user](../deployment/user-separation.md) so the agent cannot access service-owned audit files; native hooks need an external sink for an independent trust boundary
- Configure [SIEM export](siem-integration.md) to a separately controlled
  collector with suitable retention and access controls. Export is best effort;
  the local verifier does not retrieve or validate remote evidence.
- Use [webhook notifications](webhooks.md) for selected alerts to an external
  system, rather than as a complete copy of the audit trail.
