---
title: Production Guard
description: Require approval for a small set of infrastructure, database migration, and explicitly targeted Kubernetes CLI mutations.
---

# Production Guard

`production-guard` is an opt-in CLI policy overlay for Rampart **1.9 and later**.
It adds approval to selected infrastructure, database migration, and Kubernetes
commands. It does not discover your production environment or inspect the code
inside a migration, manifest, script, or infrastructure plan.

## Install alongside your base policy

Keep your existing base policy, such as `standard`, installed. Preview the YAML
and install the overlay through the policy registry:

```bash
rampart policy show production-guard
rampart policy fetch production-guard --dry-run
rampart policy install production-guard
```

The registry pins the remote policy body with a SHA256 digest. Installation
writes `~/.rampart/policies/production-guard.yaml`; a running service that loads
that policy directory reloads it. File-only configurations must also load the
overlay. It deliberately omits `default_action`, so your base profile controls
unmatched actions. Used alone, the engine's unspecified default is deny.

**Upgrade Rampart before installing.** The registry's `min_rampart` field is
currently descriptive metadata; older clients do not enforce it. An older
engine may parse this YAML while missing the operand-aware interpretations
that this profile needs. A network failure can use the policy embedded in your
installed binary; that trusted local fallback can differ from the newest
remote policy.

## What requires approval

| CLI | Covered mutations | Target boundary |
| --- | --- | --- |
| Terraform / OpenTofu | `apply`, `destroy`, `import`, `force-unlock`; `state mv`, `rm`, `push`, `replace-provider` | Approval in every environment; state, provider and workspace configuration can hide the destination |
| Pulumi | `up`, `destroy`, `refresh` | Approval in every environment; the stack and program can hide the destination |
| Prisma | `migrate deploy`, `db push` | Approval in every environment; database configuration can hide the destination |
| Alembic | `upgrade`, `downgrade` | Approval in every environment; the migration environment can hide the destination |
| kubectl | `apply`, `delete`, `patch`, `replace`, `scale`, `rollout restart` | An explicit literal `--context` or `--namespace` / `-n` equal to `prod` or `production` |

For example, `terraform -chdir=infra apply saved.plan` asks even if the directory
is called `dev`. Terraform's global directory flag changes where it reads
configuration; the name does not establish the target's safety. Prisma likewise
reads its datasource from configuration.
([Terraform CLI](https://developer.hashicorp.com/terraform/cli/commands),
[Prisma migrate deploy](https://docs.prisma.io/docs/cli/migrate/deploy))

The Kubernetes rules use exact names. `production-east` is a different name;
edit the context and namespace patterns in the installed YAML to match your
own deployment. The last occurrence of a repeated flag wins, including
`-n` versus `--namespace`. An explicit production context still asks when the
namespace is `dev`.

## Supported command forms

The engine preserves quoted operand boundaries and consumes known option values
before interpreting verbs and targets. Supported forms include:

- Literal POSIX command components separated by `;`, `&&`, `||`, or newlines;
  literal shell `-c` bodies and the existing transparent executor wrappers.
- Executable paths, quoted literal words, Terraform `-chdir=DIR`, and ordinary
  value flags such as `-var`, `--stack`, `--schema`, `--config`, and `-f`.
- kubectl target flags before or after the verb, using `--context=NAME`,
  `--context NAME`, `--namespace=NAME`, `--namespace NAME`, `-n NAME`, or `-nNAME`.
- Direct Prisma, `npx prisma` (also `-y`, `--yes`, or `--no-install`),
  `pnpm exec prisma`, and `npm exec -- prisma`.

These are restrictive policy interpretations. A compact rule such as
`terraform apply` can require approval for the supported argument forms; the
same interpretation cannot grant an `allow`, `watch`, or `webhook` rule.
Approval and audit identity remain the original command. Compound commands keep
the most restrictive applicable decision.

## Workflows the overlay leaves to your base policy

Read, plan, preview and status commands do not match these mutation rules.
Examples include `terraform plan`, `terraform state list`, `pulumi preview`,
`prisma migrate status`, and `kubectl get pods --context production`. Ordinary
local commands such as `git status` and `npm test` also stay with your base policy.
`prisma migrate dev` is deliberately outside this first profile's scope.

Known help flags, Pulumi `refresh --preview-only`, Alembic `--sql`, and kubectl
`--dry-run=client` or `--dry-run=server` do not create a mutation alias. Alembic's
offline mode generates SQL; kubectl server dry run sends a request without
persisting the resource. These commands can still access configuration or
execute tool-specific code; the profile makes no general safety claim about
them. ([Alembic offline mode](https://alembic.sqlalchemy.org/en/latest/offline.html),
[kubectl apply](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_apply/))

Other profiles remain active. `guard` deliberately asks for broader external
and opaque commands. The community Terraform and Kubernetes policies include
additional hard denies; installing this overlay does not override them.

## Limits

Unknown option arity, expanded variables, current Kubernetes context, implicit
namespaces, configuration contents, aliases/functions, and arbitrary package
runners are not resolved. For example, `--context "$CONTEXT"` does not establish
an explicit production target. A file named `production.yaml` does not either.
The parser does not classify SQL strings, arbitrary programs, chained activity
across separate tool calls, or every CLI operation. This is a bounded approval
profile, not a complete barrier around production credentials.

Shared shell matching also conservatively inspects substitution-like text
inside quoted strings. Literal examples containing `$()` or backticks can
therefore require approval; use `rampart policy explain` to inspect the match.

Native structured MCP database or infrastructure tools are outside this profile.
An MCP shell tool already mapped to `exec` can use the CLI rules. Extending this
to native tools needs exact tool identities and validated typed mutation and
target parameters; a tool name or stringified parameter is insufficient.

Use [the built-in guard profile](https://github.com/peg/rampart/blob/main/policies/guard.yaml) and
[custom policy](customizing-policy.md) when you need a more restrictive boundary,
and verify the actual configured policy on your installed host.
