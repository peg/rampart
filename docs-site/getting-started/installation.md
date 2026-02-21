---
title: Installation
description: "Install Rampart on macOS or Linux with Homebrew, Go, or script methods. Get the security layer needed to control and audit AI agent tool actions."
---

# Installation

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

## Next Steps

- [Quick Start →](quickstart.md) — Set up Rampart with Claude Code in 60 seconds
- [Configuration →](configuration.md) — Learn the YAML policy format
