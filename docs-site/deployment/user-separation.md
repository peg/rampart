---
title: User Separation
description: "Deploy Rampart with user separation to prevent AI agents from editing policies or audit logs. Protect enforcement integrity in production environments."
---

# User Separation

By default, Rampart's zero-configuration native hooks run as the same user as the AI agent. This is convenient, but it means OS ownership alone does not stop that user from reading audit logs or modifying user-owned policy files.

Running `rampart serve` as a separate user is an advanced option for centralized HTTP/SDK deployments. It is **not** a drop-in hardening switch for Claude Code, Codex, Cline, OpenClaw, or other native hooks: those hooks still execute in the host tool's user context and must be tested against the topology you deploy.

## Why It Matters

| Centralized serve setup | Agent reads service audit? | Agent modifies service policy? |
|-------|-------------------|----------------------|
| Same user (default) | ✅ Yes | ✅ Yes |
| Separate user | ❌ No | ❌ No |

For files written and read by the centralized service, a separate user can provide:

- **Audit logs** are protected from agent tampering
- **Policy files** can't be weakened by the agent
- **A narrower API credential** — compatible clients can use an eval-scoped per-agent token rather than the service's admin token

Do not give an untrusted agent the admin token to recover compatibility. Approval APIs and policy mutations intentionally require admin scope. If an integration requires those APIs, either keep it in the supported same-user native topology or design and test a trusted broker for that approval path.

## Setup

### 1. Create a Service Account

```bash
sudo useradd --system --home /var/lib/rampart --create-home --shell /usr/sbin/nologin rampart-svc
```

### 2. Move Config and Audit

```bash
sudo mkdir -p /etc/rampart /var/lib/rampart/audit
sudo cp ~/.rampart/policies/*.yaml /etc/rampart/
sudo chown -R root:rampart-svc /etc/rampart
sudo chmod 750 /etc/rampart
sudo chmod 640 /etc/rampart/*.yaml
sudo chown -R rampart-svc:rampart-svc /var/lib/rampart
sudo chmod 700 /var/lib/rampart /var/lib/rampart/audit
```

### 3. Run as the Separate User

```bash
# Direct
sudo -u rampart-svc rampart serve \
  --config /etc/rampart/standard.yaml \
  --audit-dir /var/lib/rampart/audit

# Or update your systemd service
# User=rampart-svc
```

For a compatible API/SDK client, create an eval-only token as the service user and deliver only that one-time plaintext token to the client:

```bash
sudo -u rampart-svc -H rampart token create --agent my-agent --scope eval
```

An eval token cannot resolve approvals, reload policy, or perform other admin mutations.

### 4. Systemd Service

```ini
[Unit]
Description=Rampart Policy Server
After=network.target

[Service]
Type=simple
User=rampart-svc
ExecStart=/usr/local/bin/rampart serve \
  --config /etc/rampart/standard.yaml \
  --audit-dir /var/lib/rampart/audit
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now rampart
```

## Prerequisites

!!! warning "Verify the actual integration"
    Run the behavioral verification for every client against this service before treating separation as an enforcement boundary. The normal native-hook installers are designed primarily for same-user desktop/CLI operation.

!!! warning "Don't run agents as root"
    If the agent runs as root, user separation provides no protection — root can read and modify all files regardless of ownership.

!!! warning "Restrict sudo"
    An agent with `NOPASSWD: ALL` can bypass separation via `sudo cat /etc/rampart/policy.yaml`. Restrict sudo to specific commands:

    ```
    agent ALL=(ALL) NOPASSWD: /usr/bin/apt, /bin/systemctl, /usr/local/bin/k3s
    ```
