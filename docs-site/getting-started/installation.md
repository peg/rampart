---
title: Installation
description: "Install Rampart on Windows, macOS, or Linux. Get the security layer needed to control and audit AI agent tool actions."
---

# Installation

=== "Windows"

    **PowerShell (recommended):**
    ```powershell
    irm https://rampart.sh/install.ps1 | iex
    ```
    
    This downloads the latest release, installs to `~\.rampart\bin`, adds it to your PATH, and offers to set up Claude Code hooks.
    
    **Manual:** Download the `.zip` from [GitHub Releases](https://github.com/peg/rampart/releases), extract `rampart.exe`, and add to your PATH.
    
    !!! success "No Server Required"
        Basic protection works immediately after `rampart setup claude-code` — no need to run `rampart serve`. The hook evaluates policies locally. Run serve only if you want the live dashboard or approval flow.

=== "macOS & Linux"

    **Homebrew (recommended):**
    ```bash
    brew install peg/tap/rampart
    ```

    **One-liner:**
    ```bash
    curl -fsSL https://rampart.sh/install | sh
    ```

## Homebrew (macOS & Linux)

The fastest way to install Rampart:

```bash
brew install peg/tap/rampart
```

This installs the `rampart` binary.

## Go Install

Requires Go 1.24+:

```bash
go install github.com/peg/rampart/cmd/rampart@latest
```

!!! tip "Add to PATH"
    Make sure `$(go env GOPATH)/bin` is in your `$PATH`, or create a symlink:

    ```bash
    sudo ln -sf $(go env GOPATH)/bin/rampart /usr/local/bin/rampart
    ```

## Binary Download

Download pre-built binaries from [GitHub Releases](https://github.com/peg/rampart/releases).

Binaries are available for Linux and macOS (amd64/arm64) as `.tar.gz` archives. Windows builds are published as `.zip` archives:

```bash
# Example: Linux amd64
tar xzf rampart_*_linux_amd64.tar.gz
sudo mv rampart /usr/local/bin/

# Example: macOS arm64
tar xzf rampart_*_darwin_arm64.tar.gz
sudo mv rampart /usr/local/bin/
```

## Docker

Multi-arch container image (amd64 + arm64), built on distroless for minimal attack surface:

```bash
docker run --rm -p 9090:9090 ghcr.io/peg/rampart:latest
```

Or use with docker-compose. First, create a policy file (e.g. `mkdir policies && rampart init > policies/rampart.yaml`):

```yaml
services:
  rampart:
    image: ghcr.io/peg/rampart:latest
    ports:
      - "9090:9090"
    volumes:
      - ./policies:/policies:ro
      - rampart-audit:/audit
    command: ["serve", "--addr", "0.0.0.0", "--port", "9090", "--config", "/policies/rampart.yaml", "--audit-dir", "/audit"]

volumes:
  rampart-audit:
```

Available tags include full versions such as `1.0.0`, minor versions such as `1.0`, and `latest` for the current stable release. Prereleases use their full tag, for example `1.0.0-rc.3`, and do not move `latest`. Pin to a specific version tag for reproducibility. Images are published on [GitHub Container Registry](https://github.com/peg/rampart/pkgs/container/rampart).

## Build from Source

```bash
git clone https://github.com/peg/rampart.git
cd rampart
go build -o rampart ./cmd/rampart
go test ./...
sudo mv rampart /usr/local/bin/
```

## Verify Installation

```bash
rampart --version
```

## Windows Notes

Rampart works on Windows with some limitations:

| Feature | Windows | macOS/Linux |
|---------|---------|-------------|
| `rampart serve` | ✅ Foreground only | ✅ Background supported |
| `rampart setup claude-code` | ✅ | ✅ |
| `rampart hook` | ✅ | ✅ |
| `rampart watch` | ✅ | ✅ |
| `rampart mcp` | ✅ | ✅ |
| `rampart upgrade` | ❌ Re-run installer | ✅ |
| `rampart wrap` | ❌ | ✅ |
| `rampart preload` | ❌ | ✅ Linux only |

**Path matching works cross-platform:** Policies like `**/.ssh/id_*` will match Windows paths like `C:\Users\You\.ssh\id_rsa`.

**Uninstall on Windows:**
```powershell
rampart setup claude-code --remove  # Remove hooks
Remove-Item -Recurse ~\.rampart     # Delete files
```

## Next Steps

- [Quick Start →](quickstart.md) — Set up Rampart with Claude Code, Codex, Cline, or OpenClaw
- [Configuration →](configuration.md) — Learn the YAML policy format
