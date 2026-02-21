---
title: User Separation
description: "Deploy Rampart with user separation to prevent AI agents from editing policies or audit logs. Protect enforcement integrity in production environments."
---

# User Separation

By default, Rampart runs as the same user as your AI agent. This is fine for development but means the agent can read audit logs and modify policy files.

For production deployments, run Rampart as a separate user.

## Why It Matters

| Setup | Agent reads audit? | Agent modifies policy? |
|-------|-------------------|----------------------|
| Same user (default) | ✅ Yes | ✅ Yes |
| Separate user | ❌ No | ❌ No |

With a separate user:

- **Audit logs** are protected from agent tampering
- **Policy files** can't be weakened by the agent
- **The agent loses zero capability** — it communicates with Rampart over HTTP

## Setup

### 1. Create a Service Account

```bash
sudo useradd -r -s /usr/sbin/nologin rampart-svc
```

### 2. Move Config and Audit

```bash
sudo mkdir -p /etc/rampart /var/lib/rampart/audit
sudo cp ~/.rampart/policies/*.yaml /etc/rampart/
sudo chown -R rampart-svc:rampart-svc /etc/rampart /var/lib/rampart
sudo chmod 700 /etc/rampart /var/lib/rampart/audit
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

!!! warning "Don't run agents as root"
    If the agent runs as root, user separation provides no protection — root can read and modify all files regardless of ownership.

!!! warning "Restrict sudo"
    An agent with `NOPASSWD: ALL` can bypass separation via `sudo cat /etc/rampart/policy.yaml`. Restrict sudo to specific commands:

    ```
    agent ALL=(ALL) NOPASSWD: /usr/bin/apt, /bin/systemctl, /usr/local/bin/k3s
    ```
