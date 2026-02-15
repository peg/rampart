# Community Policies

Ready-to-use policy files for common toolchains. Copy one, customize it, and point Rampart at it:

```bash
cp policies/community/kubernetes.yaml ~/.rampart/policies/my-policy.yaml
# Edit as needed
rampart serve --config ~/.rampart/policies/my-policy.yaml
```

## Available Policies

| Policy | Protects Against |
|--------|-----------------|
| [kubernetes.yaml](kubernetes.yaml) | Namespace deletion, unchecked deploys, secret extraction |
| [aws-cli.yaml](aws-cli.yaml) | Instance termination, IAM escalation, credential leaks |
| [terraform.yaml](terraform.yaml) | Auto-approve destroy, state tampering, state exfiltration |
| [docker.yaml](docker.yaml) | Privileged containers, host mounts, unreviewed pushes |
| [node-python.yaml](node-python.yaml) | Global installs, eval injection, .env leaks, npm/pypi publish |

## Combining Policies

Merge multiple community policies into one file or use includes:

```yaml
# my-policy.yaml — combine what you need
version: "1"
default_action: allow

policies:
  # Paste rules from kubernetes.yaml, docker.yaml, etc.
```

## Contributing

PRs welcome. Good community policies should:

1. **Have clear comments** explaining what each rule does and why
2. **Start permissive** — block the dangerous stuff, allow everything else
3. **Use `require_approval`** for risky-but-legitimate operations
4. **Include `log` rules** for audit trail on read-only operations
5. **Not assume a specific setup** — work across cloud providers, cluster configs, etc.

File an issue or open a PR at [github.com/peg/rampart](https://github.com/peg/rampart).
