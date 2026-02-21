---
title: Audit Trail
description: "Rampart logs every AI agent action to a hash-chained audit trail. Verify integrity, stream events live, and prove what commands were allowed or blocked."
---

# Audit Trail

Every tool call Rampart evaluates is logged to a hash-chained JSONL audit trail. Each entry includes a SHA-256 hash of the previous entry — tamper with any record and the chain breaks.

## Why Hash-Chained?

In regulated environments, you need to prove what your AI agent did. A hash chain means no one can edit history without detection. Each record cryptographically depends on the one before it.

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

## Storage

- **Location:** `~/.rampart/audit/` (configurable)
- **Format:** JSONL (one JSON object per line)
- **Rotation:** Daily files with chain continuity across files
- **IDs:** ULID (time-ordered, sortable)
- **Integrity:** External anchor every 100 events
- **Durability:** `fsync` on every write

## HTML Reports

Generate a human-readable report:

```bash
rampart report
```

## Tamper Detection

The hash chain detects **partial tampering** — editing, inserting, or deleting individual records breaks the chain. A complete rewrite with a new valid chain is not detectable from the log alone.

For stronger guarantees:

- Run `rampart serve` as a [separate user](../deployment/user-separation.md) so the agent can't access audit files
- Enable [SIEM export](siem-integration.md) for an external trust anchor
- Use [webhook notifications](webhooks.md) for real-time alerts to an external system
