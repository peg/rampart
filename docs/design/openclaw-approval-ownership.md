# Approval identity and OpenClaw ownership

Status: accepted

An approval authorizes the represented action at a supported interception
boundary. It does not establish model intent, arbitrary program behavior,
filesystem race freedom, or that an audited action executed.

## One owner, one pending action

OpenClaw owns its native pending approvals and resume operation. Rampart returns
policy decisions and a redacted action review; it does not create a second
Rampart pending object for an OpenClaw-hosted request. A native `allow` means
Rampart does not object. It does not satisfy another host approval requirement.
Hard denies remain terminal before native approval creation.

Rampart's existing approval store owns pending requests for its API/dashboard
and non-hosted integrations. Its once-only retry identity includes the original
command and structured input, tool class, agent/depth, session, run/call IDs,
working directory and credential-owner scope. Quoting, component order,
redirections, target changes and different input values remain distinct.
Missing run or call identity cannot acquire an exact replay grant.

The OpenClaw adapter additionally preserves the original tool name, original
arguments, all parsed batch targets, and available host requester identity in
the represented request. Only supplied context is evidence: a policy service's
local path resolution is not authoritative for another host or namespace.

## Review and durable state

The versioned `action` response is a redacted display projection, not a replay
token. The CLI exposes complete details with `rampart pending --details`; the
dashboard's expanded approval shows the same complete represented parameters
and context. Compact list previews are not the approval scope. Terminal control
characters, HTML and Markdown are rendered as data.

Pending journals contain redacted review data. The immutable original action
fingerprint is captured before redaction and protected with HMAC-SHA256 using a
32-byte key beside the journal (`<journal>.identity-key`). The key is stored with
owner-only access and a single hard link. It protects a copied journal against
guessing secret-bearing inputs without the key; it does not protect a
compromised operating-system account.

First startup migrates legacy pending records transactionally under the journal
lock, preserving their exact original identity while redacting stored content.
Version 3 pending/replay formats cannot be consumed as older unscoped grants.
Previously published legacy replay grants are not carried forward: retrying
requires fresh approval. Redacted requests cannot become permanent literal
command/path rules. If redaction changes the agent, session or run identity,
the pending request cannot authorize future calls for that run; its original
once-only fingerprint remains usable.

Keep the identity key with its journal and replay directory when restoring
state. Missing, malformed or linked keys refuse new authorization. A running store
also rejects a replaced key. Rampart never regenerates a missing key over
version 3 state. After restart, an unrelated well-formed replacement key cannot
replay the original pending fingerprints; restoring the original key is
necessary to preserve those approvals. To retire a key,
stop all services using that state, explicitly retire the pending/replay state,
then initialize fresh state. There is no implicit rotation or recovery grant.
A downgrade discards version 3 pending grants rather than authorizing their
redacted display as though it were the original action.

## OpenClaw contract and limits

The reviewed stable source is [OpenClaw v2026.9.1](https://github.com/openclaw/openclaw/tree/v2026.9.1).
Its [hook runner](https://github.com/openclaw/openclaw/blob/v2026.9.1/src/plugins/hooks.ts)
gives each modifying hook an isolated copy of the original event. Prior
returned rewrites are not the event seen by Rampart. The first approval freezes
the selected parameter snapshot; later hooks can block but cannot replace it.
Freezing does not prove Rampart evaluated the final composed parameters. Other
parameter-mutating plugins remain part of the trusted host configuration.

`onResolution` receives a decision, not a replacement action or a consume-time
veto. Rampart cannot use that callback to validate resumed execution. Native
plugin approvals therefore offer `allow-once` and `deny`; persistent allowances
require an explicit operator policy. A command/path rule alone does not bind
all the parameters and execution context of an approved action.

The native hook's [approval forwarding](https://github.com/openclaw/openclaw/blob/v2026.9.1/src/agents/agent-tools.before-tool-call.approval.ts)
forwards a description but no complete-review attachment. Its
[wire limit](https://github.com/openclaw/openclaw/blob/v2026.9.1/src/infra/plugin-approvals.ts)
is 512 characters. Rampart sends a complete safely rendered action within that
limit or blocks before creating a native approval. It never replaces a
meaningful suffix with an ellipsis and offers approval on the prefix. Split an
oversized request into smaller independently reviewable actions, or configure
an explicit operator-reviewed policy. A service too old to provide the redacted
review also blocks asks until upgraded.

| Boundary | Owner and remaining limit |
| --- | --- |
| Rampart native pending/replay | Rampart consumes the exact captured input once after reevaluating policy; missing identity returns to approval. |
| OpenClaw plugin | OpenClaw owns timeout, native delivery and resume; Rampart cannot veto a callback or observe earlier returned parameter rewrites. |
| Claude Code and other hosted hooks | The host owns native approval and execution. Rampart's replay store does not strengthen a host-owned resume contract. |
| Paths and allowed programs | Canonicalization is policy evidence, not a filesystem lock, sandbox, syscall monitor or guarantee about an allowed script. Replay binds the represented path, not the underlying object if a symlink is retargeted. |

Credential-free adapter and API tests prove mapping, display, persistence,
restart and replay behavior. They do not prove authenticated native approval
delivery or a model loop. Installed-boundary verification and its limits remain
in `assurance/integrations.yaml` and the support matrix.
