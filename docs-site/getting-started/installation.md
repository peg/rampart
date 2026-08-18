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
    
    This downloads and validates the latest release, transactionally installs
    it to `~\.rampart\bin`, and adds that directory to your user PATH. It does
    not modify an agent configuration; run `rampart protect` afterward to
    detect, configure, and behaviorally verify supported installed agents.
    
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

    The installer fails closed unless the release archive checksum and embedded
    Rampart version both match the requested release. Upgrades stage and verify
    the candidate beside the installed binary, then activate it with an atomic
    same-filesystem rename. If final verification fails, the prior binary is
    restored before the installer exits.

    A sudden power loss can leave a `.rampart-install.*` transaction directory
    in the install directory, but the `rampart` path will resolve to either the
    complete old binary or the complete verified candidate. Rerun the installer
    to retry; once no installer is running, stale transaction directories can
    be removed.

## Homebrew (macOS & Linux)

The fastest way to install Rampart:

```bash
brew install peg/tap/rampart
```

This installs the `rampart` binary.

## Go Install

Requires Go 1.25.13+:

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
docker run --rm -p 127.0.0.1:9090:9090 ghcr.io/peg/rampart:latest
```

Or use with docker-compose. First, create a policy file (e.g. `mkdir policies && rampart init > policies/rampart.yaml`):

```yaml
services:
  rampart:
    image: ghcr.io/peg/rampart:latest
    ports:
      - "127.0.0.1:9090:9090"
    volumes:
      - ./policies:/policies:ro
      - rampart-audit:/audit
    command: ["serve", "--addr", "0.0.0.0", "--port", "9090", "--config", "/policies/rampart.yaml", "--audit-dir", "/audit"]

volumes:
  rampart-audit:
```

The loopback bind keeps the bearer-token control API off your LAN. For remote administration, put Rampart behind a trusted HTTPS reverse proxy and supply `RAMPART_TOKEN` explicitly; do not publish port 9090 directly over plaintext HTTP.

Available tags include full versions such as `1.6.0`, minor versions such as `1.6`, and `latest` for the current stable release. Prereleases use their full tag, for example `1.6.0-rc.1`, and do not move `latest`. Pin to a specific version tag for reproducibility. Images are published on [GitHub Container Registry](https://github.com/peg/rampart/pkgs/container/rampart).

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

> **Upgrading from Rampart 1.2.x:** rerun `irm https://rampart.sh/install.ps1 | iex`. The installer repairs the affected legacy `~\.rampart` ACL before replacing the binary. Do not rely on `rampart upgrade` when the existing binary is inaccessible.

| Feature | Windows | macOS/Linux |
|---------|---------|-------------|
| `rampart serve` | ✅ Foreground and `--background` | ✅ Background supported |
| `rampart setup claude-code` | ✅ | ✅ |
| `rampart hook` | ✅ | ✅ |
| `rampart watch` | ✅ | ✅ |
| `rampart mcp` | ✅ | ✅ |
| `rampart upgrade` | ❌ Re-run installer | ✅ |
| `rampart wrap` | ❌ | ✅ |
| `rampart preload` | ❌ | ⚠️ Linux/macOS; native library must be built from source |

The release archive and Homebrew formula install the CLI only. To use the
optional preload boundary, check out the matching Rampart source revision and
run `make -C preload install`. macOS coverage remains subject to SIP and
hardened-runtime restrictions.

**Path matching works cross-platform:** Policies like `**/.ssh/id_*` will match Windows paths like `C:\Users\You\.ssh\id_rsa`.

**Uninstall on Windows:**
```powershell
rampart setup claude-code --remove  # Remove hooks
Remove-Item -Recurse ~\.rampart     # Delete files
```

## Next Steps

- [Quick Start →](quickstart.md) — Set up Rampart with Claude Code, Codex, Cline, Cursor, or OpenClaw
- [Configuration →](configuration.md) — Learn the YAML policy format
