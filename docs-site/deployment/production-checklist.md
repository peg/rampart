---
title: Production Checklist
description: "Use Rampart's production checklist to harden AI agent deployments with user separation, monitoring, alerting, and policy controls before unsupervised runs."
---

# Production Checklist

Before running AI agents unsupervised in production, verify each item.

## Security

- [ ] **User separation** — Rampart runs as a dedicated `rampart-svc` user ([guide](user-separation.md))
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

- [ ] **Auto-restart** — Systemd/launchd configured with `Restart=always`
- [ ] **Fail-open understood** — Team knows commands pass through if Rampart is down
- [ ] **Log rotation** — Audit directory has adequate disk space
- [ ] **Backup** — Policy files and audit logs are backed up

## Policies

- [ ] **Credential protection** — SSH keys, AWS creds, env files blocked
- [ ] **Exfiltration protection** — Known exfil domains blocked
- [ ] **Destructive commands** — `rm -rf`, `mkfs`, `dd` blocked
- [ ] **Response scanning** — Credential patterns in output detected
- [ ] **Anti-exfiltration** — Encoding + network pipe patterns blocked

## Testing

- [ ] **Policy validation** — `rampart policy check` passes
- [ ] **Deny test** — Confirmed a blocked command returns error
- [ ] **Allow test** — Confirmed normal commands work
- [ ] **Webhook test** — Notifications arrive on deny
- [ ] **Chain verification** — `rampart audit verify` passes

## Documentation

- [ ] **Runbook** — Team knows how to approve pending commands
- [ ] **Escalation** — Process for reviewing audit anomalies
- [ ] **Upgrade plan** — Re-patch file tools after framework upgrades
