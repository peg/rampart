# Frequently Asked Questions

## What happens if Rampart crashes?

There is no universal fallback. Claude Code, Codex, and Cline normally evaluate
local policy without `rampart serve`; Rampart-handled parse/config errors deny
in enforce mode, while an unexpected hook-process crash or timeout follows the
host's behavior. Managed OpenClaw denies when its policy service is unavailable.
Hermes can fail open only for explicitly configured lower-risk tools. See the
[support matrix](support-matrix.md#degraded-behavior-notes).

## How do I update Rampart?

Same way you installed it. `brew upgrade rampart` for Homebrew, `go install github.com/peg/rampart/cmd/rampart@latest` for Go, or download the latest binary from [GitHub Releases](https://github.com/peg/rampart/releases). Your policies and audit logs are untouched. Then run `rampart protect` once to refresh Rampart-managed integrations and verify detected agent boundaries; unrelated hooks and agent state are preserved.

## How do I uninstall?

Run `rampart setup claude-code --remove` (or `cline --remove` / `openclaw --remove`) to cleanly remove hooks. Then uninstall the binary with `brew uninstall rampart` or delete it. Policies and logs live in `~/.rampart/` — delete that folder to fully clean up. See the [uninstall guide](uninstall.md) for details.

## What's the performance impact?

Core matching is local and benchmarked in microseconds. Hook process startup and
audit I/O add machine-dependent overhead. The optional
[semantic verification sidecar](../features/semantic-verification.md) adds a
network model call when configured.

## Does it work on Windows?

The policy engine and Claude Code/Codex hook setup are built and tested on
Windows CI. A physical Windows host E2E is still pending, Cline's installed hook
scripts currently require Bash, and `rampart wrap`/preload are Unix-only. See
the [Windows guide](../guides/windows.md).

## Can I use project-specific policies?

Yes. Put a `rampart.yaml` in your project root and Rampart will use it. You can also layer global policies (`~/.rampart/policies/`) with project-specific overrides. See [Customizing Policy](../guides/customizing-policy.md).

## Can my agent bypass Rampart?

Pattern-based deny rules can be evaded by obfuscation or by behavior inside an
allowed process. Allowlist mode reduces that risk, but Rampart is not an OS
sandbox. Its standard policy also blocks recognized self-modification paths;
separate users and file permissions are required for a stronger boundary. See
the [Threat Model](../reference/threat-model.md).

## Can I require human approval for certain commands?

Set `action: ask` on a policy rule. Claude Code uses its native prompt,
OpenClaw can use its native approval UI, Codex uses Rampart's external queue,
Cline blocks with context, and Hermes currently blocks without resume. Consult
the support matrix before relying on a particular approval workflow.

```yaml
policies:
  - name: approve-deploys
    rules:
      - action: ask
        when:
          command_matches: ["kubectl apply *"]
        message: "Deployment requires approval"
```

See the [Native Ask Prompt guide](../guides/native-ask.md) for full details.

## Is this a sandbox?

No. Sandboxes isolate the entire process — great for untrusted code, but they break workflows that need real file and network access. Rampart is a policy engine: it lets your agent work normally and only blocks the dangerous stuff.
