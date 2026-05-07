#!/bin/sh
# Rampart install script.
#
# Canonical source for the website and legacy installer copies. Keep
# docs/install, docs/install.sh, and scripts/install.sh byte-for-byte synced
# with this file.
# Usage: curl -fsSL https://rampart.sh/install | sh
#        curl -fsSL https://rampart.sh/install | sh -s -- --version v0.1.0
#        curl -fsSL https://rampart.sh/install | sh -s -- --auto-setup
#        RAMPART_INSTALL_DRY_RUN=1 sh install.sh --version v1.0.0
#        RAMPART_VERSION=v1.0.0 RAMPART_INSTALL_DIR=$HOME/.local/bin sh install.sh
set -e

REPO="peg/rampart"
INSTALL_DIR="${RAMPART_INSTALL_DIR:-}"
BINARY="rampart"
VERSION="${RAMPART_VERSION:-}"
AUTO_SETUP="${RAMPART_AUTO_SETUP:-0}"
DRY_RUN="${RAMPART_INSTALL_DRY_RUN:-0}"

# Colors (if terminal supports them).
if [ -t 1 ]; then
    BOLD="\033[1m"
    GREEN="\033[32m"
    RED="\033[31m"
    YELLOW="\033[33m"
    RESET="\033[0m"
else
    BOLD="" GREEN="" RED="" YELLOW="" RESET=""
fi

info()  { printf "${GREEN}▸${RESET} %s\n" "$1"; }
warn()  { printf "${YELLOW}▸${RESET} %s\n" "$1"; }
error() { printf "${RED}✗${RESET} %s\n" "$1" >&2; exit 1; }

fetch() { # fetch <url> [dest]
    URL="$1"
    DEST="${2:-}"
    if command -v curl >/dev/null 2>&1; then
        if [ -n "$DEST" ]; then
            curl -fsSL -o "$DEST" "$URL"
        else
            curl -fsSL "$URL"
        fi
    elif command -v wget >/dev/null 2>&1; then
        if [ -n "$DEST" ]; then
            wget -qO "$DEST" "$URL"
        else
            wget -qO- "$URL"
        fi
    else
        error "Neither curl nor wget found. Install one and retry."
    fi
}

# Parse args.
while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --version=*) VERSION="${1#--version=}"; shift ;;
        --auto-setup) AUTO_SETUP=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        *) error "Unknown option: $1" ;;
    esac
done

# Detect OS.
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
    linux)  OS="linux" ;;
    darwin) OS="darwin" ;;
    *)      error "Unsupported OS: $OS (need linux or darwin)" ;;
esac

# Detect architecture.
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)   ARCH="amd64" ;;
    aarch64|arm64)   ARCH="arm64" ;;
    *)               error "Unsupported architecture: $ARCH (need amd64 or arm64)" ;;
esac

info "Detected ${BOLD}${OS}/${ARCH}${RESET}"

# Determine version.
if [ -z "$VERSION" ]; then
    info "Fetching latest version..."
    VERSION=$(fetch "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
    if [ -z "$VERSION" ]; then
        error "Could not determine latest version. Try: --version v0.1.0"
    fi
fi

# Normalise version: release tags include a leading "v".
case "$VERSION" in
    v*) ;;
    *)  VERSION="v${VERSION}" ;;
esac

info "Installing ${BOLD}rampart ${VERSION}${RESET}"

if [ -z "$INSTALL_DIR" ]; then
    if [ "$(id -u)" -eq 0 ]; then
        INSTALL_DIR="/usr/local/bin"
    elif [ -d "$HOME/.local/bin" ]; then
        INSTALL_DIR="$HOME/.local/bin"
    elif [ "$DRY_RUN" = "1" ]; then
        INSTALL_DIR="$HOME/.local/bin"
    elif mkdir -p "$HOME/.local/bin" 2>/dev/null; then
        INSTALL_DIR="$HOME/.local/bin"
    else
        INSTALL_DIR="/usr/local/bin"
    fi
fi

# Build download URLs.
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
TARBALL="rampart_${VERSION#v}_${OS}_${ARCH}.tar.gz"
TARBALL_URL="${BASE_URL}/${TARBALL}"
CHECKSUM_URL="${BASE_URL}/checksums.txt"

if [ "$DRY_RUN" = "1" ]; then
    info "Dry-run — no changes will be made"
    info "Would download: ${TARBALL_URL}"
    info "Would verify:  ${CHECKSUM_URL}"
    info "Would install: ${INSTALL_DIR}/${BINARY}"
    exit 0
fi

# Create temp directory.
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# Download archive.
info "Downloading archive..."
if ! fetch "$TARBALL_URL" "${TMP_DIR}/${TARBALL}"; then
    error "Download failed. Check that ${VERSION} exists at:\n  ${TARBALL_URL}"
fi

# Download and verify checksum.
info "Verifying checksum..."
if fetch "$CHECKSUM_URL" "${TMP_DIR}/checksums.txt" 2>/dev/null; then
    EXPECTED=$(grep "${TARBALL}" "${TMP_DIR}/checksums.txt" | awk '{print $1}')
    if command -v sha256sum >/dev/null 2>&1; then
        ACTUAL=$(sha256sum "${TMP_DIR}/${TARBALL}" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        ACTUAL=$(shasum -a 256 "${TMP_DIR}/${TARBALL}" | awk '{print $1}')
    else
        warn "No sha256sum or shasum found — skipping verification"
        ACTUAL="$EXPECTED"
    fi

    if [ -z "$EXPECTED" ]; then
        warn "No checksum entry found for ${TARBALL} — skipping verification"
    elif [ "$EXPECTED" != "$ACTUAL" ]; then
        error "Checksum mismatch!\n  Expected: ${EXPECTED}\n  Got:      ${ACTUAL}"
    else
        info "Checksum verified ✓"
    fi
else
    warn "No checksums.txt found — skipping verification"
fi

tar -xzf "${TMP_DIR}/${TARBALL}" -C "$TMP_DIR"

if [ ! -f "${TMP_DIR}/${BINARY}" ]; then
    error "Archive did not contain ${BINARY}"
fi

# Install.
chmod +x "${TMP_DIR}/${BINARY}"

if [ ! -d "$INSTALL_DIR" ]; then
    if ! mkdir -p "$INSTALL_DIR" 2>/dev/null; then
        info "Need sudo to create ${INSTALL_DIR}"
        sudo mkdir -p "$INSTALL_DIR"
    fi
fi

if [ -w "$INSTALL_DIR" ]; then
    mv "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
else
    info "Need sudo to install to ${INSTALL_DIR}"
    sudo mv "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
fi

info "Installed to ${BOLD}${INSTALL_DIR}/${BINARY}${RESET}"

# Verify.
RAMPART_BIN="${INSTALL_DIR}/${BINARY}"
if [ -x "$RAMPART_BIN" ]; then
    printf "\n"
    "$RAMPART_BIN" version 2>/dev/null || true

    if echo ":${PATH}:" | grep -q ":${INSTALL_DIR}:"; then
        printf "\n${GREEN}${BOLD}Ready!${RESET} Run ${BOLD}rampart quickstart${RESET} to get started.\n"
    else
        printf "\n${YELLOW}Note:${RESET} ${INSTALL_DIR} may not be in your PATH.\n"
        printf "Add it: ${BOLD}export PATH=\"${INSTALL_DIR}:\$PATH\"${RESET}\n"
        printf "Then run: ${BOLD}rampart quickstart${RESET}\n"
    fi
else
    warn "Could not verify installed binary at ${INSTALL_DIR}/${BINARY}"
fi

# Detect AI agents and suggest setup commands.
detect_agents_and_suggest() {
    printf "\n"

    # Detect OpenClaw
    OPENCLAW_FOUND=0
    if command -v openclaw >/dev/null 2>&1; then
        OPENCLAW_FOUND=1
    elif [ -f "$HOME/.local/bin/openclaw" ] || [ -f "/usr/local/bin/openclaw" ] || [ -f "/usr/bin/openclaw" ]; then
        OPENCLAW_FOUND=1
    fi

    # Detect Claude Code (claude CLI)
    CLAUDE_FOUND=0
    if command -v claude >/dev/null 2>&1; then
        CLAUDE_FOUND=1
    elif [ -f "$HOME/.claude/settings.json" ]; then
        CLAUDE_FOUND=1
    fi

    if [ "$OPENCLAW_FOUND" -eq 1 ] || [ "$CLAUDE_FOUND" -eq 1 ]; then
        printf "${GREEN}${BOLD}✓ AI agent(s) detected!${RESET}\n\n"
    fi

    if [ "$OPENCLAW_FOUND" -eq 1 ]; then
        if [ "$AUTO_SETUP" = "1" ]; then
            printf "${GREEN}▸${RESET} Auto-setup: protecting OpenClaw...\n"
            "$RAMPART_BIN" setup openclaw 2>&1 || printf "${YELLOW}  ↳ Auto-setup failed — run manually: rampart setup openclaw${RESET}\n"
        else
            printf "  Run this to protect your OpenClaw agent:\n"
            printf "    ${BOLD}rampart setup openclaw${RESET}\n"
            printf "\n"
        fi
    fi

    if [ "$CLAUDE_FOUND" -eq 1 ]; then
        if [ "$AUTO_SETUP" = "1" ]; then
            printf "${GREEN}▸${RESET} Auto-setup: protecting Claude Code...\n"
            "$RAMPART_BIN" setup claude-code 2>&1 || printf "${YELLOW}  ↳ Auto-setup failed — run manually: rampart setup claude-code${RESET}\n"
        else
            printf "  Run this to protect Claude Code:\n"
            printf "    ${BOLD}rampart setup claude-code${RESET}\n"
            printf "\n"
        fi
    fi

    if [ "$OPENCLAW_FOUND" -eq 0 ] && [ "$CLAUDE_FOUND" -eq 0 ]; then
        printf "  To protect an AI agent, run:\n"
        printf "    ${BOLD}rampart setup openclaw${RESET}      — for OpenClaw\n"
        printf "    ${BOLD}rampart setup claude-code${RESET}   — for Claude Code\n"
        printf "\n"
    fi
}

if [ -x "$RAMPART_BIN" ]; then
    detect_agents_and_suggest
fi
