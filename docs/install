#!/bin/sh
# Rampart installer
# Usage: curl -fsSL https://rampart.sh/install | bash
#        curl -fsSL https://rampart.sh/install | RAMPART_VERSION=v0.3.0 bash
#
# Env vars:
#   RAMPART_VERSION          — pin a version (default: latest)
#   RAMPART_INSTALL_DIR      — install directory (default: ~/.local/bin)
#   RAMPART_INSTALL_DRY_RUN  — set to 1 to print actions without running them
set -e

REPO="peg/rampart"
INSTALL_DIR="${RAMPART_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${RAMPART_VERSION:-}"
DRY_RUN="${RAMPART_INSTALL_DRY_RUN:-0}"

# ── Colors ────────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
    BOLD="\033[1m"; GREEN="\033[32m"; YELLOW="\033[33m"; RED="\033[31m"; RESET="\033[0m"
else
    BOLD=""; GREEN=""; YELLOW=""; RED=""; RESET=""
fi

info()  { printf "${GREEN}▸${RESET} %s\n" "$1"; }
warn()  { printf "${YELLOW}▸${RESET} %s\n" "$1" >&2; }
error() { printf "${RED}✗${RESET} %s\n" "$1" >&2; exit 1; }
step()  { printf "\n${BOLD}%s${RESET}\n" "$1"; }
dry()   { printf "${YELLOW}[dry-run]${RESET} %s\n" "$1"; }

# ── Downloader ─────────────────────────────────────────────────────────────────
fetch() {  # fetch <url> [dest]
    URL="$1"; DEST="$2"
    if command -v curl >/dev/null 2>&1; then
        if [ -n "$DEST" ]; then curl -fsSL -o "$DEST" "$URL"
        else curl -fsSL "$URL"; fi
    elif command -v wget >/dev/null 2>&1; then
        if [ -n "$DEST" ]; then wget -qO "$DEST" "$URL"
        else wget -qO- "$URL"; fi
    else
        error "Neither curl nor wget found. Install one and retry."
    fi
}

# ── OS / Arch ──────────────────────────────────────────────────────────────────
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
    linux)  OS="linux"  ;;
    darwin) OS="darwin" ;;
    *)      error "Unsupported OS: $(uname -s). Only linux and darwin are supported." ;;
esac

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *)             error "Unsupported architecture: $(uname -m). Only amd64 and arm64 are supported." ;;
esac

info "Platform: ${BOLD}${OS}/${ARCH}${RESET}"

# ── Resolve version ────────────────────────────────────────────────────────────
if [ -z "$VERSION" ]; then
    info "Fetching latest release..."
    VERSION="$(fetch "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
    [ -n "$VERSION" ] || error "Could not determine latest version. Set RAMPART_VERSION=vX.Y.Z and retry."
fi

# Normalise: ensure leading 'v'
case "$VERSION" in
    v*) ;;
    *)  VERSION="v${VERSION}" ;;
esac

info "Version:  ${BOLD}${VERSION}${RESET}"

# ── Build URLs ─────────────────────────────────────────────────────────────────
TARBALL="rampart_${OS}_${ARCH}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
TARBALL_URL="${BASE_URL}/${TARBALL}"
CHECKSUM_URL="${BASE_URL}/rampart_${OS}_${ARCH}_checksums.txt"

if [ "$DRY_RUN" = "1" ]; then
    step "Dry-run — no changes will be made"
    dry "Would download: ${TARBALL_URL}"
    dry "Would install:  ${INSTALL_DIR}/rampart"
    dry "Would run:      rampart quickstart"
    if ! echo ":${PATH}:" | grep -q ":${INSTALL_DIR}:"; then
        dry "Would hint to add ${INSTALL_DIR} to PATH"
    fi
    exit 0
fi

# ── Download & extract ─────────────────────────────────────────────────────────
step "Downloading rampart ${VERSION}..."

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fetch "$TARBALL_URL" "${TMP_DIR}/${TARBALL}" \
    || error "Download failed.\nURL: ${TARBALL_URL}\nCheck that ${VERSION} exists: https://github.com/${REPO}/releases"

# Optional checksum verification
if fetch "$CHECKSUM_URL" "${TMP_DIR}/checksums.txt" 2>/dev/null; then
    if command -v sha256sum >/dev/null 2>&1; then
        HASH_CMD="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then
        HASH_CMD="shasum -a 256"
    else
        HASH_CMD=""
    fi
    if [ -n "$HASH_CMD" ]; then
        EXPECTED="$(grep "${TARBALL}" "${TMP_DIR}/checksums.txt" | awk '{print $1}')"
        ACTUAL="$($HASH_CMD "${TMP_DIR}/${TARBALL}" | awk '{print $1}')"
        if [ -n "$EXPECTED" ] && [ "$EXPECTED" != "$ACTUAL" ]; then
            error "Checksum mismatch!\n  Expected: ${EXPECTED}\n  Got:      ${ACTUAL}"
        fi
        info "Checksum verified ✓"
    fi
fi

tar -xzf "${TMP_DIR}/${TARBALL}" -C "$TMP_DIR"

# ── Install ────────────────────────────────────────────────────────────────────
step "Installing to ${INSTALL_DIR}..."

mkdir -p "$INSTALL_DIR"
mv "${TMP_DIR}/rampart" "${INSTALL_DIR}/rampart"
chmod +x "${INSTALL_DIR}/rampart"

info "Installed: ${BOLD}${INSTALL_DIR}/rampart${RESET}"

# PATH hint
if ! echo ":${PATH}:" | grep -q ":${INSTALL_DIR}:"; then
    warn "${INSTALL_DIR} is not in your PATH."
    warn "Add this to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
    printf "    ${BOLD}export PATH=\"\$HOME/.local/bin:\$PATH\"${RESET}\n" >&2
    export PATH="${INSTALL_DIR}:${PATH}"
fi

# ── Quickstart ─────────────────────────────────────────────────────────────────
step "Running quickstart..."

if [ -t 0 ] && [ -t 1 ]; then
    rampart quickstart
else
    rampart quickstart --env none 2>/dev/null || true
fi

printf "\n${GREEN}${BOLD}Done!${RESET} rampart ${VERSION} is installed.\n"
printf "Docs: ${BOLD}https://docs.rampart.sh${RESET}\n\n"
