---
title: Production Checklist
description: "Use Rampart's production checklist to harden AI agent deployments with user separation, monitoring, alerting, and policy controls before unsupervised runs."
---

# Production Checklist

Before running AI agents unsupervised in production, verify each item.

## Security

- [ ] **Policy ownership** — Active policy files are not writable by the agent user; centralized API deployments may use a dedicated service account ([guide](user-separation.md))
- [ ] **Agent is non-root** — Your AI agent runs as an unprivileged user
- [ ] **Sudo is restricted** — Agent's sudo access limited to specific commands
- [ ] **Policy reviewed** — All YAML policies reviewed and tested
- [ ] **Default action** — Set to `deny` for high-security environments

## Monitoring

- [ ] **SIEM export enabled** — `--syslog` or `--cef` sending to your SIEM ([guide](../features/siem-integration.md))
- [ ] **Webhook notifications** — Alerts configured for `deny` events ([guide](../features/webhooks.md))
- [ ] **Service monitoring** — Rampart process monitored (systemd, Nagios, etc.)
- [ ] **Audit verification** — Periodic `rampart audit verify` in cron

## Reliability

- [ ] **Service lifecycle** — Integrations that need `rampart serve` use a monitored service (`rampart serve install` on supported desktop/user-service deployments)
- [ ] **Degraded behavior tested** — Each installed integration was tested for its documented unavailable-service behavior; do not assume every path fails open or fails closed
- [ ] **Log retention** — Audit directory has adequate disk space and an explicit retention/export plan
- [ ] **Backup** — Policy files and audit logs are backed up

## Policies

- [ ] **Credential protection** — SSH keys, AWS creds, env files blocked
- [ ] **Exfiltration protection** — Known exfil domains blocked
- [ ] **Destructive commands** — `rm -rf`, `mkfs`, `dd` blocked
- [ ] **Response scanning** — Credential patterns in output are tested on every integration where response hooks are supported
- [ ] **Anti-exfiltration** — Encoding + network pipe patterns blocked

## Testing

- [ ] **Policy validation** — `rampart policy check` passes
- [ ] **Integration verification** — `rampart verify <integration>` passes for every installed native integration
- [ ] **Deny test** — Confirmed a blocked command returns error
- [ ] **Allow test** — Confirmed normal commands work
- [ ] **Webhook test** — Notifications arrive on deny
- [ ] **Chain verification** — `rampart audit verify` passes

## Documentation

- [ ] **Runbook** — Team knows how to approve pending commands
- [ ] **Escalation** — Process for reviewing audit anomalies
- [ ] **Upgrade plan** — Re-run setup/protect and behavioral verification after host-tool upgrades; use legacy file patching only where the support matrix explicitly requires it
