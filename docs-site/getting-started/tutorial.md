---
title: Check Your First Protected Agent
description: "Check Rampart with harmless marker files: observe allowed and denied calls, review an approval, and correlate the audit record."
---

# Check Your First Protected Agent

This walkthrough uses Claude Code on macOS or Linux and harmless marker files
in a disposable project. It separates policy checks from evidence that a real
host invoked Rampart. Follow the [installation guide](installation.md) first.

## Protect and inspect

```bash
rampart protect claude-code
rampart verify claude-code
rampart status
```

Resolve any reported failures before continuing. Claude's verifier checks the
installed configuration and Rampart adapter without launching Claude or running
a tool. The next steps exercise the actual host boundary.

## Create a disposable project

Run these commands yourself in a terminal:

```bash
rampart_tutorial_dir=$(mktemp -d "${TMPDIR:-/tmp}/rampart-tutorial.XXXXXX")
cd "$rampart_tutorial_dir"
git init -q
mkdir .rampart
```

Save this policy as `.rampart/policy.yaml` in that new directory:

```yaml
version: "1"
default_action: allow
policies:
  - name: tutorial-marker-actions
    match:
      tool: [exec]
    rules:
      - action: deny
        when:
          command_contains: [rampart-denied-marker.txt]
        message: "Tutorial marker creation denied"
      - action: ask
        when:
          command_contains: [rampart-review-marker.txt]
        message: "Review this harmless tutorial marker"
      - action: allow
        when:
          command_contains: [rampart-allowed-marker.txt]
```

Project policy adds restrictions to the global policy. It does not override a
global deny. Keep `RAMPART_NO_PROJECT_POLICY` unset for this walkthrough. See
[Project Policies](../guides/project-policies.md) if your environment disables
project policy or imposes additional restrictions.

## Check the policy before using the agent

```bash
rampart policy lint .rampart/policy.yaml
rampart test --config .rampart/policy.yaml "touch rampart-allowed-marker.txt"
rampart test --config .rampart/policy.yaml "touch rampart-denied-marker.txt"
rampart test --config .rampart/policy.yaml "touch rampart-review-marker.txt"
```

Expect `allow`, `deny`, and `ask`, respectively. These commands evaluate the
example policy as data; they do not create files or prove host enforcement.
The agent also evaluates your global policy, which may be more restrictive.

## Observe the real tool calls

In a second terminal, start `rampart watch`. Launch Claude Code from the
new project directory and complete any host configuration trust prompts.
Ask for each command separately, using its shell tool and this project as its
working directory. Tell it to stop after that one attempt and not substitute
another tool or command.

| Request to the agent | What to check |
| --- | --- |
| Run `touch rampart-allowed-marker.txt` | A matching allow record and the marker file appear. |
| Run `touch rampart-denied-marker.txt` | The audit record names `tutorial-marker-actions` with a deny; the marker is absent. |
| Run `touch rampart-review-marker.txt` | Claude shows its native approval prompt. Before resolving it, the marker is absent. Deny the prompt and confirm it remains absent. |

Check the files yourself in the original terminal, not through the agent:

```bash
ls -l rampart-allowed-marker.txt
test ! -e rampart-denied-marker.txt && echo "Denied marker absent"
test ! -e rampart-review-marker.txt && echo "Review marker absent"
```

A model refusal or missing file alone is inconclusive: the host must attempt
the call and a matching Rampart decision must appear. If the agent uses a
different tool, changes the command, or never invokes a tool, repeat the
requested shell action before drawing a conclusion. If a denied marker appears,
stop using that boundary and inspect the integration with
[troubleshooting](troubleshooting.md).

## Approve one action

Request `touch rampart-review-marker.txt` again. Inspect the complete command
and working directory in Claude's prompt, then approve only that invocation.
Confirm the marker appears and correlate the request with its audit record.

Remove that one marker yourself:

```bash
rm -- rampart-review-marker.txt
```

Ask for the same shell command once more. It should require fresh review;
deny it and confirm the marker stays absent. Do not select a persistent host
permission while checking an individual approval.

Claude owns its native prompt and resume. A dashboard entry mirrored for
`ask.audit` is not another way to resume that native request. Codex and Cursor
use Rampart's external queue; OpenClaw uses its own native approval UI. Use the
[approval paths and limits](support-matrix.md#approval-paths-and-limits) for
other integrations.

## Read the evidence and finish

```bash
rampart audit tail
rampart audit verify
```

Check the tool, command, decision, and available session/call identifiers.
The audit records the decision at Rampart's boundary; the marker provides
separate evidence of an effect. Neither establishes coverage inside an allowed
process or across every possible host tool.

For release validation, also exercise expiry, cancellation, service failure,
and changed arguments through the affected host. Host timeout and resume
behavior differ; the [support matrix](support-matrix.md) identifies those limits.
Do failure testing in an isolated installation, not by stopping a service that
protects other ongoing work.

When finished, exit the agent and remove the tutorial policy and marker files
from this disposable project. Keep your ordinary installation protected.
For real policies, continue with [Customizing Policy](../guides/customizing-policy.md).
