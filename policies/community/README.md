# Community Policies

Ready-to-use policy files for common toolchains. Install them with the CLI:

```bash
rampart policy search kubernetes       # find policies
rampart policy show kubernetes         # preview before installing
rampart policy fetch kubernetes        # install to ~/.rampart/policies/
```

Rampart auto-loads all `*.yaml` files in `~/.rampart/policies/` — no merge step needed.

## Available Policies

| Policy | Protects Against |
|--------|-----------------|
| [kubernetes.yaml](kubernetes.yaml) | Namespace deletion, unchecked deploys, secret extraction |
| [aws-cli.yaml](aws-cli.yaml) | Instance termination, IAM escalation, credential leaks |
| [terraform.yaml](terraform.yaml) | Auto-approve destroy, state tampering, state exfiltration |
| [docker.yaml](docker.yaml) | Privileged containers, host mounts, unreviewed pushes |
| [node-python.yaml](node-python.yaml) | Global installs, eval injection, .env leaks, npm/pypi publish |

## Contributing

PRs welcome. See [docs/community-policies.md](../../docs/community-policies.md) for full contributor workflow.

Every community policy must include metadata headers:

```yaml
# @name: my-policy
# @description: What this policy protects against
# @author: @your-github-username
# @tags: tag1, tag2
# @min-rampart: 0.6.0
```

CI automatically runs `rampart policy lint` and `rampart bench --min-coverage 60` on every PR.

Good community policies should:

1. **Have clear comments** explaining what each rule does and why
2. **Start permissive** — block the dangerous stuff, allow everything else
3. **Use `require_approval`** for risky-but-legitimate operations
4. **Include `log` rules** for audit trail on read-only operations
5. **Not assume a specific setup** — work across cloud providers, cluster configs, etc.

File an issue or open a PR at [github.com/peg/rampart](https://github.com/peg/rampart).
