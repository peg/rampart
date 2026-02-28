# Project Policies

Rampart can auto-load project-specific policies from `.rampart/policy.yaml` in the root of a Git repository. This allows projects to ship security rules alongside their code.

## How It Works

When Rampart evaluates a tool call, it looks for a `.rampart/policy.yaml` file in the Git repository root (determined via `git rev-parse --show-toplevel`). If found, those policies are layered on top of your global policies.

**Precedence rules:**
- Global policies take priority for `default_action` and `notify` settings
- Deny always wins across both layers
- Duplicate policy names in the project file are skipped with a warning

## Security Considerations

Project policies are potentially untrusted — they come from the repository, not from you. To help users distinguish the source:

- Denial messages from project policies are prefixed with `[Project Policy]`
- Ask prompts from project policies show the same prefix

This allows users to make informed decisions about whether to trust a project-defined rule.

## Disabling Project Policies

If you want to prevent Rampart from loading any project policies (e.g., when working in untrusted repositories), set:

```bash
export RAMPART_NO_PROJECT_POLICY=1
```

With this environment variable set, Rampart will only use your global policies from `~/.rampart/policies/`.

## Example Project Policy

```yaml
# .rampart/policy.yaml
version: "1"

policies:
  - name: project-no-deploy
    description: "Require approval before deploying from this repo"
    match:
      tool: ["exec"]
    rules:
      - action: require_approval
        when:
          command_matches:
            - "kubectl apply *"
            - "terraform apply *"
        message: "Deployment requires approval"
```

## See Also

- [Policy Reference](/docs/policies) — full policy syntax documentation
- [Exceptions Guide](/docs/exceptions) — how to allow specific operations
