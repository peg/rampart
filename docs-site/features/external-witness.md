---
title: External Witnessing
description: "Retain audit checkpoints independently and verify all witnessed positions without exporting tool requests or agent content."
---

# External Witnessing

**Experimental.** External witnessing adds separately retained evidence to local
hash-chain verification. It is an optional client and protocol; Rampart does not
operate or install a witness service. Local logging continues when publication
fails, and existing `serve`, hook and MCP behavior is unchanged.

A witness retains small checkpoints containing a chain identity, event count,
hash and timestamp. It receives no commands, paths, event IDs, host names,
prompts, agent content or credentials in the checkpoint. HTTPS credentials travel
only in the authorization header to the configured endpoint.

## Establish the trust boundary first

The destination must be administered independently of the agent. Its publication
credential must not permit deletion, overwrite, history filtering or witness-key
changes. HTTPS and signatures authenticate statements; they do not establish
immutable storage, honest operators or complete execution coverage.

Choose one persistent, lowercase chain identifier of 16–64 letters, digits,
hyphens or underscores. Retain the operator configuration, witness identity and
public-key pins outside the audit directory and outside the agent's write
authority. Keep an independent backup. Rampart never generates a replacement
identity or learns a new trusted key from the destination after metadata loss.

Every accepted position must remain discoverable. Verification checks **all
retained checkpoints** against one local history snapshot. Looking only at the
latest checkpoint is insufficient: a compromised publisher could append a higher
checkpoint for rewritten history while leaving older conflicting evidence behind.

The guarantee covers recorded history through the last valid retained checkpoint.
Later local events form an unwitnessed tail. It does not prove that an allowed
action executed, that all host activity was intercepted, or that event contents
were truthful before their first checkpoint was independently retained.

## Configure an HTTPS destination

Provision an independently controlled endpoint implementing the contract below,
then retain configuration such as:

```json
{
  "version": 1,
  "chain_id": "replace-with-retained-chain-id",
  "witness_id": "operator-witness-identity",
  "url": "https://witness.example/chain-endpoint",
  "token_file": "/run/secrets/rampart-witness-token",
  "keys": {
    "witness-key-1": "REPLACE_WITH_BASE64_ED25519_PUBLIC_KEY"
  },
  "max_age_seconds": 86400
}
```

Use an absolute credential-file path and owner-restricted permissions. The token
must contain 16–4096 characters. No private witness signing key belongs on the
publisher. Both publication and retrieval require bearer authentication and
normal HTTPS certificate validation. Redirects are refused, including redirects
to another HTTPS URL. Response bodies and credentials are never included in
transport-error output.

```bash
# Publish one checkpoint, with bounded retries for unavailable transport.
rampart audit witness publish --config /etc/rampart/witness.json

# Run separately under an operator-managed process supervisor.
rampart audit witness publish --config /etc/rampart/witness.json --follow --interval 5m

# Retrieve independent evidence and inspect integrity, freshness and delivery.
rampart audit witness status --config /etc/rampart/witness.json

# Fail if independent evidence is missing, invalid, stale or unavailable.
rampart audit verify --require-witness --witness-config /etc/rampart/witness.json
```

`--require-witness` without configuration fails. Supplying `--witness-config`
also makes successful retrieval and comparison mandatory. `--since` cannot be
combined with witnessing: a partial local scan cannot establish a full witnessed
prefix. An ordinary `rampart audit verify` remains a local-only check.

## File destinations

For storage whose access and retention are separately administered:

```json
{
  "version": 1,
  "chain_id": "replace-with-retained-chain-id",
  "witness_id": "operator-storage-identity",
  "file_directory": "/srv/independent-witness",
  "max_age_seconds": 86400
}
```

The directory must already exist and use an absolute, non-symlink path. Each
checkpoint is stored as `<chain_id>.<20-digit-event-count>.json`. The client uses
exclusive creation, never replaces existing evidence, and retains the original
checkpoint time on a duplicate. A different hash at an existing position fails.
Malformed files, conflicting position spellings and incomplete writes require
operator attention; the client does not erase or repair them automatically.

**Ordinary create-only files do not enforce independent retention.** The same OS
identity may still be able to rewrite or delete them outside this client. Use
separate storage controls and independently retained copies appropriate to the
deployment. File-mode verification reports
`authentication: separately_administered_storage`; it cannot validate that those
controls actually exist. File checkpoint time is supplied by the publisher and
is not an independently authenticated acceptance time.

## Results and operating limits

| Status | Meaning |
| --- | --- |
| `witnessed_head` | All retained positions match and the latest checkpoint covers the local snapshot head. |
| `witnessed_prefix` | All retained positions match; `unwitnessed_events` reports the later local tail. |
| `witness_ahead` | Retained evidence references events missing from the local snapshot. |
| `hash_mismatch` | At least one retained position conflicts with local history, even if a newer head matches. |
| `stale_checkpoint` | Latest acceptance exceeds `max_age_seconds`; in file mode this uses publisher time. |
| `unavailable`, `unauthenticated`, `malformed` | Required destination evidence could not be retrieved or validated. |
| `conflict`, `incomplete_evidence`, `stale_view`, `evidence_limit` | Retained evidence or its retrieval view cannot be accepted completely. |
| `no_evidence`, `not_configured` | No accepted evidence or configuration is available. |
| `local_invalid`, `verification_incomplete`, `unsupported_legacy_epochs` | Local history could not establish the required prefix. |

Only `witnessed_head` and `witnessed_prefix` return `verified: true`. A fresh,
valid prefix may coexist with `delivery: degraded`: earlier evidence remains
valid even though publishing the latest head failed. Conversely, stale evidence
does not imply failed transport. Duplicate publication does not refresh the
original acceptance time, so a quiet chain can become stale. Set a freshness
threshold appropriate to the deployment; freshness does not prove missing
activity was recorded.

Delivery metadata in the local audit directory is advisory. Its absence means
`delivery: unknown`, never permission to substitute cached evidence. Restart and
local metadata deletion do not discard independently retained checkpoints.

Publication is serialized, with no event queue. `--follow` waits at least one
minute between cycles and coalesces changes to the next snapshot. Unavailable
transport receives at most three attempts, with one- and two-second backoffs.
Each attempt defaults to a 30-second deadline; `--timeout` accepts 1 second to
10 minutes. Every HTTP request also has a 10-second limit. Local filesystem
operations and acquisition of the existing advisory writer lock depend on OS
behavior and cannot be forcibly canceled by that deadline.

The snapshot captures file identities and lengths under the shared writer lock;
it reads and hashes the captured history **outside** that lock. Concurrent appends
remain possible. Removal, replacement or shortening invalidates the snapshot.
Snapshot capture examines directory metadata and is limited to 10,000 entries.
The complete local scan costs O(history), and retained-evidence validation costs
O(checkpoints), including signature verification. This is not a constant-cost
per-event service. Choose a cadence appropriate to trail size and measure with
`go test ./internal/audit -run '^$' -bench '^BenchmarkWitnessSnapshot$'`.

Retrieval is limited to 100,000 retained receipts and bounded HTTPS pages; file
directories are limited to 100,000 entries. Reaching a limit fails verification,
never silently skips older evidence. Rampart does not prune witness history.
Normal JSONL rotation preserves the same chain identity and event count. Legacy
logs containing disconnected chain epochs remain locally verifiable but cannot
be claimed as one witnessed history; witnessing refuses that layout.

## Version 1 HTTPS contract

The endpoint is operator-provided. The client implements only these two operations:

- **POST** receives one checkpoint and returns its signed acceptance receipt
  with HTTP 200 or 201. An identical chain/position/hash is idempotent and returns
  the original acceptance; a conflicting position returns 409. Accepted records
  are retained even if later publications conflict with earlier local history.
- **GET** with `offset=0&limit=64` starts an immutable view containing **every**
  retained receipt, ordered by strictly increasing event count. Subsequent GETs
  include the signed `view_id`, next offset and the same limit. The server must
  preserve that view's contents and total throughout retrieval, including while
  other publishers append. No middle or final page may be omitted. Unknown
  views fail; they must not silently restart pagination.

Checkpoint fields, in signing order, are `version`, `chain_id`, `event_count`,
`hash`, `created_at`. Version is 1; hash retains Rampart's exact
`sha256:<64-lowercase-hex-digits>` format. Counts are positive signed 64-bit
integers. Timestamps use UTC RFC 3339 with optional fractional seconds.

An acceptance contains `version`, `witness_id`, `checkpoint`, `accepted_at`,
`key_id`, then `signature`. Ed25519 signs the UTF-8 domain prefix
`rampart.audit.witness.receipt.v1\n` followed by the compact JSON of the first five
fields in that order. The signature is standard base64.

A page contains `version`, `witness_id`, `chain_id`, `view_id`, `total`, `offset`,
`next_offset`, `complete`, `issued_at`, `key_id`, `receipts`, then `signature`.
The page signature uses domain prefix `rampart.audit.witness.page.v1\n` and compact
JSON of the first eleven fields in that order, including each receipt's signature.
Canonical encoding is Go `encoding/json` for the named public structures in
`internal/audit/witness.go` and `witness_pages.go`, with UTC timestamps encoded as
RFC3339Nano. The domain prefixes end in one actual newline, not a backslash and n.

Pages contain at most 64 receipts and 64 KiB of JSON. Retrieval accepts at most
1,564 pages; servers should fill non-final pages to the requested limit.
`next_offset` must equal
`offset + len(receipts)` and `complete` must exactly indicate reaching `total`.
View identifiers use the same 16–64-character format as chain identities. Pages
must be issued within five minutes of the verifier's clock. Responses reject
unknown fields, duplicate object keys, trailing JSON, invalid signatures and
unexpected identities. A missing page, changed view/total, repeated position or
unsupported evidence volume makes the entire retrieval unsuccessful.

Every page and receipt key must already be in `keys`. During key rotation,
explicitly retain old public keys needed for stored receipts and add the new
key before switching the witness. Never infer a trust update from a remote
`key_id`. Removing a retained receipt's key makes its evidence unauthenticated.
Only independent operators control signing keys, retention and complete-view
retrieval; the publication credential must not grant those powers.
