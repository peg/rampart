# Frequently Asked Questions

## What happens if Rampart crashes?

Your tools keep working. Rampart fails open by default — if the policy engine is unreachable, commands pass through normally. You'll never get locked out of your own machine.

## How do I update Rampart?

Same way you installed it. `brew upgrade rampart` for Homebrew, `go install github.com/peg/rampart/cmd/rampart@latest` for Go, or download the latest binary from [GitHub Releases](https://github.com/peg/rampart/releases). Your policies and audit logs are untouched.

## How do I uninstall?

Run `rampart setup claude-code --remove` (or `cline --remove` / `openclaw --remove`) to cleanly remove hooks. Then uninstall the binary with `brew uninstall rampart` or delete it. Policies and logs live in `~/.rampart/` — delete that folder to fully clean up. See the [uninstall guide](uninstall.md) for details.

## What's the performance impact?

Effectively zero. Policy checks are pure in-memory pattern matching — no network calls, no disk I/O, no measurable impact on your agent's workflow. The optional [semantic verification sidecar](../features/semantic-verification.md) does use an LLM call, but only when you opt in and only for ambiguous cases.

## Does it work on Windows?

Yes. Install with PowerShell: `irm https://rampart.sh/install.ps1 | iex`. The policy engine and hook integrations (Claude Code, Cline) work fully on Windows. Shell wrapping (`rampart wrap`) and LD_PRELOAD are Linux/macOS only.

## Can I use project-specific policies?

Yes. Put a `rampart.yaml` in your project root and Rampart will use it. You can also layer global policies (`~/.rampart/policies/`) with project-specific overrides. See [Customizing Policy](../guides/customizing-policy.md).

## Can my agent bypass Rampart?

Pattern-based deny rules can be evaded by obfuscated commands (quoting, variable expansion). For high-security environments, use allowlist mode: set `default_action: deny` — only explicitly permitted commands run, and evasion techniques fail by default. Rampart also blocks agents from modifying their own policies. See the [Threat Model](../reference/threat-model.md) for a full analysis.

## Can I require human approval for certain commands?

Yes. Set `action: require_approval` on any policy rule. Your agent pauses, Rampart sends a notification (Discord, Slack, or any webhook), and the command stays blocked until you approve or deny it from the [dashboard](../features/dashboard.md) or CLI.

## Is this a sandbox?

No. Sandboxes isolate the entire process — great for untrusted code, but they break workflows that need real file and network access. Rampart is a policy engine: it lets your agent work normally and only blocks the dangerous stuff.
