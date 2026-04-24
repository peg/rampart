# Community Policies

Rampart ships with **built-in profiles** (standard, paranoid, yolo, etc.) and a growing library of **community policies** for specific toolchains. Community policies are installed alongside your main profile — Rampart auto-loads all `*.yaml` files in `~/.rampart/policies/`.

## Discovering Policies

### Search

```bash
rampart policy search kubernetes

NAME          DESCRIPTION                        TAGS              SCORE
kubernetes    Blocks destructive cluster ops     k8s,helm,cluster  87%
```

Filter by tag or minimum bench score:

```bash
rampart policy search cloud --tag aws
rampart policy search k8s --min-score 80
rampart policy search terraform --json    # machine-readable output
```

### List All

```bash
rampart policy list
```

Shows all built-in profiles and community policies together, with installed state:

```
NAME                    DESCRIPTION                              SOURCE      INSTALLED
block-prompt-injection  Built-in profile                         built-in
docker                  Container guardrails                     community
kubernetes              Blocks destructive cluster ops            community   ✓
mcp-server              Built-in profile                         built-in
standard                Built-in profile                         built-in    ✓
```

### Preview

Print a policy's full YAML before installing:

```bash
rampart policy show kubernetes
```

## Installing Policies

```bash
rampart policy fetch kubernetes          # canonical command
rampart policy install kubernetes        # alias — same behavior

# Overwrite an existing policy:
rampart policy fetch kubernetes --force

# Preview without writing:
rampart policy fetch kubernetes --dry-run
```

Policies are saved to `~/.rampart/policies/<name>.yaml`. Rampart auto-loads them — no additional configuration needed.

### Via `rampart init`

Community policies work with `--profile` just like built-in profiles:

```bash
rampart init --profile kubernetes
```

This downloads the community policy and writes it to `~/.rampart/policies/kubernetes.yaml`.

### Proactive Discovery

When you run `rampart init` or `rampart doctor`, Rampart detects tools in your `PATH` and suggests relevant community policies:

```
✓ Setup complete.

  We found tools in your environment with community policies:
  kubectl → rampart policy fetch kubernetes (87%)
  terraform → rampart policy fetch terraform (79%)
```

## Removing Policies

```bash
rampart policy remove kubernetes
```

This deletes `~/.rampart/policies/kubernetes.yaml`. Built-in profiles cannot be removed.

## Available Community Policies

| Policy | Protects Against | Tags |
|--------|-----------------|------|
| kubernetes | Namespace deletion, unchecked deploys, secret extraction | kubernetes, helm, cluster |
| aws-cli | Instance termination, IAM escalation, credential leaks | aws, cloud, iam |
| terraform | Auto-approve destroy, state tampering, state exfiltration | terraform, iac, opentofu |
| docker | Privileged containers, host mounts, unreviewed pushes | docker, containers, compose |
| node-python | Global installs, eval injection, .env leaks, npm/pypi publish | node, python, npm, pip |

## Contributing a Community Policy

### 1. Create your policy file

Add `policies/community/my-policy.yaml` with metadata headers:

```yaml
# @name: my-policy
# @description: Brief description of what this policy protects against
# @author: @your-github-username
# @tags: tag1, tag2, tag3
# @min-rampart: 0.6.0
#
# Longer description and usage instructions here.

version: "1"
default_action: allow

policies:
  - name: my-rule
    # ... your rules ...
```

### 2. Validate locally

```bash
rampart policy lint policies/community/my-policy.yaml
rampart bench --policy policies/community/my-policy.yaml --min-coverage 60
```

### 3. Submit a PR

- Fork the repo
- Add your policy file with the metadata header
- CI will automatically run lint, bench, and metadata validation
- Maintainer review → merge → policy appears in the next registry update

### Quality Gates (enforced by CI)

- `rampart policy lint` passes (no errors)
- `rampart bench --min-coverage 60` passes
- All required metadata fields present (`@name`, `@description`, `@author`, `@tags`, `@min-rampart`)
- `@min-rampart` is valid semver format (`X.Y.Z`)

### Writing Good Community Policies

1. **Start permissive** — block the dangerous stuff, allow everything else
2. **Use `ask`** for risky-but-legitimate operations
3. **Include `log` rules** for audit trail on read-only operations
4. **Add clear comments** explaining what each rule does and why
5. **Don't assume a specific setup** — work across cloud providers, cluster configs, etc.
