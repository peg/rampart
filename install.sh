#!/bin/sh
# Rampart install script
# Usage: curl -fsSL https://rampart.sh/install | sh
#        curl -fsSL https://rampart.sh/install | sh -s -- --version v0.1.0
set -e

REPO="peg/rampart"
INSTALL_DIR="/usr/local/bin"
BINARY="rampart"
VERSION=""

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

# Parse args.
while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --version=*) VERSION="${1#--version=}"; shift ;;
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
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
    if [ -z "$VERSION" ]; then
        error "Could not determine latest version. Try: --version v0.1.0"
    fi
fi

info "Installing ${BOLD}rampart ${VERSION}${RESET}"

# Build download URLs.
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
BINARY_URL="${BASE_URL}/rampart-${OS}-${ARCH}"
CHECKSUM_URL="${BASE_URL}/rampart-${OS}-${ARCH}.sha256"

# Create temp directory.
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# Download binary.
info "Downloading binary..."
if ! curl -fsSL -o "${TMP_DIR}/${BINARY}" "$BINARY_URL"; then
    error "Download failed. Check that ${VERSION} exists at:\n  ${BINARY_URL}"
fi

# Download and verify checksum.
info "Verifying checksum..."
if curl -fsSL -o "${TMP_DIR}/${BINARY}.sha256" "$CHECKSUM_URL" 2>/dev/null; then
    EXPECTED=$(awk '{print $1}' "${TMP_DIR}/${BINARY}.sha256")
    if command -v sha256sum >/dev/null 2>&1; then
        ACTUAL=$(sha256sum "${TMP_DIR}/${BINARY}" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        ACTUAL=$(shasum -a 256 "${TMP_DIR}/${BINARY}" | awk '{print $1}')
    else
        warn "No sha256sum or shasum found — skipping verification"
        ACTUAL="$EXPECTED"
    fi

    if [ "$EXPECTED" != "$ACTUAL" ]; then
        error "Checksum mismatch!\n  Expected: ${EXPECTED}\n  Got:      ${ACTUAL}"
    fi
    info "Checksum verified ✓"
else
    warn "No checksum file found — skipping verification"
fi

# Install.
chmod +x "${TMP_DIR}/${BINARY}"

if [ "$(id -u)" -eq 0 ]; then
    INSTALL_DIR="/usr/local/bin"
elif [ -d "$HOME/.local/bin" ] || mkdir -p "$HOME/.local/bin" 2>/dev/null; then
    INSTALL_DIR="$HOME/.local/bin"
else
    INSTALL_DIR="/usr/local/bin"
fi

if [ -w "$INSTALL_DIR" ]; then
    mv "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
else
    info "Need sudo to install to ${INSTALL_DIR}"
    sudo mv "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
fi

info "Installed to ${BOLD}${INSTALL_DIR}/${BINARY}${RESET}"

# Verify.
if command -v rampart >/dev/null 2>&1; then
    printf "\n"
    rampart version 2>/dev/null || true
    printf "\n${GREEN}${BOLD}Ready!${RESET} Run ${BOLD}rampart init${RESET} to get started.\n"
else
    printf "\n${YELLOW}Note:${RESET} ${INSTALL_DIR} may not be in your PATH.\n"
    printf "Add it: ${BOLD}export PATH=\"${INSTALL_DIR}:\$PATH\"${RESET}\n"
    printf "Then run: ${BOLD}rampart init${RESET}\n"
fi
