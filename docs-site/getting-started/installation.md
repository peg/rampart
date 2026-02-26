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
    
    !!! note "Windows Limitations"
        `rampart serve` runs in foreground only. Keep the terminal open while using Claude Code, or use Task Scheduler/NSSM to run it at startup. See [Windows Notes](#windows-notes) below.

=== "macOS & Linux"

    **Homebrew (recommended):**
    ```bash
    brew tap peg/rampart && brew install rampart
    ```

    **One-liner:**
    ```bash
    curl -fsSL https://rampart.sh/install | sh
    ```

## Homebrew (macOS & Linux)

The fastest way to install Rampart:

```bash
brew tap peg/rampart && brew install rampart
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

Binaries are available for Linux (amd64/arm64) as `.tar.gz` and macOS (amd64/arm64) as `.zip`:

```bash
# Example: Linux amd64
tar xzf rampart_*_linux_amd64.tar.gz
sudo mv rampart /usr/local/bin/

# Example: macOS (unzip, then move)
unzip rampart_*_darwin_arm64.zip
sudo mv rampart /usr/local/bin/
```

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

- [Quick Start →](quickstart.md) — Set up Rampart with Claude Code in 60 seconds
- [Configuration →](configuration.md) — Learn the YAML policy format
