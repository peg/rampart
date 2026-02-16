# Example Policies

Ready-to-use policy templates. Copy one, customize it, go.

| Template | Default | Use Case |
|----------|---------|----------|
| [`web-developer.yaml`](web-developer.yaml) | allow | Node.js, React, Python web apps — blocks danger, approves deploys |
| [`infrastructure.yaml`](infrastructure.yaml) | allow | Kubernetes, Terraform, Docker — approves all mutations |
| [`data-science.yaml`](data-science.yaml) | allow | Python, ML, data pipelines — blocks exfiltration, protects datasets |
| [`lockdown.yaml`](lockdown.yaml) | **deny** | High-security — only explicitly allowed commands run |

## Quick Start

```bash
# Copy a template
cp policies/examples/web-developer.yaml ~/.rampart/policy.yaml

# Customize it
$EDITOR ~/.rampart/policy.yaml

# Validate your changes
rampart test ~/.rampart/policy.yaml
rampart policy lint ~/.rampart/policy.yaml

# Apply it
rampart setup claude-code --config ~/.rampart/policy.yaml
```

## Writing Your Own

Every template includes inline tests — run `rampart test <file>` to verify your customizations work as expected.

See the [policy documentation](https://docs.rampart.sh/features/policy-engine/) for the full reference.
