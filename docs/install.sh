#!/bin/sh
# Rampart install script.
#
# Canonical source for the website and legacy installer copies. Keep
# docs/install and docs/install.sh byte-for-byte synced
# with this file.
# Usage: curl -fsSL https://rampart.sh/install | sh
#        curl -fsSL https://rampart.sh/install | sh -s -- --version v0.1.0
#        curl -fsSL https://rampart.sh/install | sh -s -- --auto-setup
#        RAMPART_INSTALL_DRY_RUN=1 sh install.sh --version v1.6.0
#        RAMPART_VERSION=v1.6.0 RAMPART_INSTALL_DIR=$HOME/.local/bin sh install.sh
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
        --version)
            [ $# -ge 2 ] || error "--version requires a value"
            VERSION="$2"
            shift 2
            ;;
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

# VERSION is used in both a release URL and a local archive filename. Accept
# only the same strict SemVer tag shape enforced by the release workflow so a
# caller-controlled value cannot introduce path separators or option syntax.
SEMVER_RE='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$'
if ! printf '%s\n' "$VERSION" | grep -Eq "$SEMVER_RE"; then
    error "Invalid release version: ${VERSION}. Expected a tag such as v1.6.0 or v1.6.0-rc.1."
fi

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

# Downloads can live in the system temp directory. The candidate used for the
# final rename is staged under INSTALL_DIR later so activation stays on one
# filesystem and is atomic.
TMP_DIR="$(mktemp -d)"
TXN_DIR=""
TRANSACTION_ACTIVE=0
ACTIVATED=0
HAD_EXISTING=0
BACKGROUND_SERVE_ACTIVE=0
STOPPED_SYSTEMD_SERVICES=""
STOPPED_LAUNCHD_SERVICES=""
RUNTIME_CAN_RESTART=1

install_cmd() {
    if [ "$NEED_SUDO" = "1" ]; then
        sudo "$@"
    else
        "$@"
    fi
}

systemd_quote_word() {
    # Match the quoting emitted by `rampart serve install`. Install paths are
    # not expected to contain control characters; such paths simply fail the
    # exact ownership comparison below and are left untouched.
    printf '%s' "$1" | sed \
        -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g' \
        -e 's/%/%%/g' \
        -e '1s/^/"/' \
        -e '$s/$/"/'
}

systemd_service_is_owned() {
    SERVICE_FILE="$1"
    [ -f "$SERVICE_FILE" ] && [ ! -L "$SERVICE_FILE" ] || return 1

    EXEC_START=$(awk '
        /^[[:space:]]*ExecStart=/ {
            sub(/^[[:space:]]*ExecStart=[[:space:]]*/, "")
            sub(/\r$/, "")
            count++
            value=$0
        }
        END { if (count == 1) print value }
    ' "$SERVICE_FILE")
    [ -n "$EXEC_START" ] || return 1

    QUOTED_BINARY=$(systemd_quote_word "$RAMPART_BIN")
    QUOTED_PREFIX="${QUOTED_BINARY} serve"
    case "$EXEC_START" in
        "$QUOTED_PREFIX"|"$QUOTED_PREFIX "*) return 0 ;;
    esac

    # Older Rampart-generated proxy units did not quote their executable.
    # Accept that legacy form only when the path itself is unambiguous.
    case "$RAMPART_BIN" in
        *[[:space:]]*) return 1 ;;
    esac
    LEGACY_PREFIX="${RAMPART_BIN} serve"
    case "$EXEC_START" in
        "$LEGACY_PREFIX"|"$LEGACY_PREFIX "*) return 0 ;;
    esac
    return 1
}

launchd_service_is_owned() {
    PLIST_PATH="$1"
    EXPECTED_LABEL="$2"
    [ -f "$PLIST_PATH" ] && [ ! -L "$PLIST_PATH" ] || return 1
    command -v plutil >/dev/null 2>&1 || return 1

    ACTUAL_LABEL=$(plutil -extract Label raw -o - "$PLIST_PATH" 2>/dev/null) || return 1
    PROGRAM=$(plutil -extract ProgramArguments.0 raw -o - "$PLIST_PATH" 2>/dev/null) || return 1
    SUBCOMMAND=$(plutil -extract ProgramArguments.1 raw -o - "$PLIST_PATH" 2>/dev/null) || return 1
    [ "$ACTUAL_LABEL" = "$EXPECTED_LABEL" ] || return 1
    [ "$PROGRAM" = "$RAMPART_BIN" ] || return 1
    [ "$SUBCOMMAND" = "serve" ] || return 1
    return 0
}

detect_and_stop_managed_runtime() {
    # The PID-file path is fixed by Rampart. The old binary performs the final
    # process identity check before signaling, so the installer never kills a
    # PID based only on a caller-writable number.
    SERVE_PID_PATH="${HOME}/.rampart/serve.pid"
    if [ -f "$SERVE_PID_PATH" ] && [ ! -L "$SERVE_PID_PATH" ]; then
        info "Stopping the managed Rampart background server..."
        if "$RAMPART_BIN" serve stop >/dev/null 2>&1; then
            BACKGROUND_SERVE_ACTIVE=1
        else
            error "Could not authenticate and stop the Rampart background server. The existing installation was not changed."
        fi
    fi

    if [ "$OS" = "linux" ] && command -v systemctl >/dev/null 2>&1; then
        SYSTEMD_DIR="${HOME}/.config/systemd/user"
        for SERVICE_NAME in rampart-serve.service rampart-proxy.service; do
            SERVICE_FILE="${SYSTEMD_DIR}/${SERVICE_NAME}"
            if systemd_service_is_owned "$SERVICE_FILE" && \
                systemctl --user is-active --quiet "$SERVICE_NAME" >/dev/null 2>&1; then
                # Record before stopping so cleanup also recovers a manager
                # that completed the stop but returned an error afterward.
                STOPPED_SYSTEMD_SERVICES="${STOPPED_SYSTEMD_SERVICES} ${SERVICE_NAME}"
                info "Stopping managed systemd service ${SERVICE_NAME}..."
                if ! systemctl --user stop "$SERVICE_NAME"; then
                    error "Could not stop managed systemd service ${SERVICE_NAME}. The existing installation was not changed."
                fi
            fi
        done
    fi

    if [ "$OS" = "darwin" ] && command -v launchctl >/dev/null 2>&1; then
        LAUNCH_AGENT_DIR="${HOME}/Library/LaunchAgents"
        for SERVICE_LABEL in sh.rampart.serve com.rampart.proxy com.rampart.serve; do
            PLIST_PATH="${LAUNCH_AGENT_DIR}/${SERVICE_LABEL}.plist"
            if launchd_service_is_owned "$PLIST_PATH" "$SERVICE_LABEL" && \
                launchctl list "$SERVICE_LABEL" >/dev/null 2>&1; then
                STOPPED_LAUNCHD_SERVICES="${STOPPED_LAUNCHD_SERVICES} ${SERVICE_LABEL}"
                info "Stopping managed launchd service ${SERVICE_LABEL}..."
                if ! launchctl unload "$PLIST_PATH"; then
                    error "Could not stop managed launchd service ${SERVICE_LABEL}. The existing installation was not changed."
                fi
            fi
        done
    fi
}

launchd_plist_path() {
    printf '%s/Library/LaunchAgents/%s.plist\n' "$HOME" "$1"
}

restart_managed_runtime() {
    RESTART_MODE="$1"
    RESTART_FAILED=0

    for SERVICE_NAME in $STOPPED_SYSTEMD_SERVICES; do
        SYSTEMD_VERB="start"
        [ "$RESTART_MODE" = "rollback" ] && SYSTEMD_VERB="restart"
        if systemctl --user "$SYSTEMD_VERB" "$SERVICE_NAME"; then
            info "Restarted managed systemd service ${SERVICE_NAME}"
        else
            warn "Could not restart managed systemd service ${SERVICE_NAME}."
            RESTART_FAILED=1
        fi
    done

    for SERVICE_LABEL in $STOPPED_LAUNCHD_SERVICES; do
        PLIST_PATH=$(launchd_plist_path "$SERVICE_LABEL")
        if [ "$RESTART_MODE" = "rollback" ]; then
            launchctl unload "$PLIST_PATH" >/dev/null 2>&1 || true
        fi
        if launchctl load "$PLIST_PATH"; then
            info "Restarted managed launchd service ${SERVICE_LABEL}"
        else
            warn "Could not restart managed launchd service ${SERVICE_LABEL}."
            RESTART_FAILED=1
        fi
    done

    if [ "$BACKGROUND_SERVE_ACTIVE" = "1" ]; then
        if [ "$RESTART_MODE" = "rollback" ]; then
            "$RAMPART_BIN" serve stop >/dev/null 2>&1 || true
        fi
        if "$RAMPART_BIN" serve --background >/dev/null 2>&1; then
            info "Restarted the managed Rampart background server"
        else
            warn "Could not restart the managed Rampart background server."
            RESTART_FAILED=1
        fi
    fi

    [ "$RESTART_FAILED" -eq 0 ]
}

cleanup_install() {
    STATUS="$1"
    trap - 0 1 2 15
    set +e

    # A candidate that failed its post-rename check must not remain installed.
    # Restoring the backup is another same-filesystem rename.
    if [ "$TRANSACTION_ACTIVE" = "1" ] && [ "$ACTIVATED" = "1" ]; then
        if [ "$HAD_EXISTING" = "1" ] && { [ -e "${TXN_DIR}/rampart.previous" ] || [ -L "${TXN_DIR}/rampart.previous" ]; }; then
            if install_cmd mv "${TXN_DIR}/rampart.previous" "${INSTALL_DIR}/${BINARY}"; then
                warn "Installation failed; restored the previous Rampart binary."
            else
                warn "Installation failed and automatic rollback failed. Previous binary remains at ${TXN_DIR}/rampart.previous"
                RUNTIME_CAN_RESTART=0
                TXN_DIR=""
            fi
        else
            install_cmd rm -f "${INSTALL_DIR}/${BINARY}" >/dev/null 2>&1
        fi
    fi

    if [ "$STATUS" -ne 0 ] && [ "$RUNTIME_CAN_RESTART" = "1" ]; then
        if ! restart_managed_runtime rollback; then
            warn "Automatic runtime recovery was incomplete; restart the reported managed service manually."
        fi
    fi

    if [ -n "$TXN_DIR" ]; then
        case "$TXN_DIR" in
            "${INSTALL_DIR}"/.rampart-install.*) install_cmd rm -rf "$TXN_DIR" ;;
            *) warn "Refusing to remove unexpected transaction path: ${TXN_DIR}" ;;
        esac
    fi
    rm -rf "$TMP_DIR"
    exit "$STATUS"
}

trap 'cleanup_install $?' 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

# Download archive.
info "Downloading archive..."
if ! fetch "$TARBALL_URL" "${TMP_DIR}/${TARBALL}"; then
    error "Download failed. Check that ${VERSION} exists at:\n  ${TARBALL_URL}"
fi

# Download and verify checksum. Installation fails closed if release integrity
# cannot be established; a security tool must never silently install an
# unverified binary.
info "Verifying checksum..."
if ! fetch "$CHECKSUM_URL" "${TMP_DIR}/checksums.txt" 2>/dev/null; then
    error "Could not download checksums.txt; refusing to install an unverified binary."
fi

EXPECTED=$(awk -v file="$TARBALL" '$2 == file { print $1 }' "${TMP_DIR}/checksums.txt")
EXPECTED_COUNT=$(printf '%s\n' "$EXPECTED" | awk 'NF { count++ } END { print count+0 }')
if [ "$EXPECTED_COUNT" -ne 1 ]; then
    error "Expected exactly one checksum entry for ${TARBALL}; refusing unverified install."
fi
case "$EXPECTED" in
    *[!0-9a-fA-F]*|'') error "Invalid SHA-256 checksum for ${TARBALL}." ;;
esac
if [ "${#EXPECTED}" -ne 64 ]; then
    error "Invalid SHA-256 checksum length for ${TARBALL}."
fi

if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL=$(sha256sum "${TMP_DIR}/${TARBALL}" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    ACTUAL=$(shasum -a 256 "${TMP_DIR}/${TARBALL}" | awk '{print $1}')
else
    error "No SHA-256 tool found (need sha256sum or shasum); refusing unverified install."
fi

if [ "$(printf '%s' "$EXPECTED" | tr '[:upper:]' '[:lower:]')" != "$(printf '%s' "$ACTUAL" | tr '[:upper:]' '[:lower:]')" ]; then
    error "Checksum mismatch!\n  Expected: ${EXPECTED}\n  Got:      ${ACTUAL}"
fi
info "Checksum verified ✓"

if ! tar -xzf "${TMP_DIR}/${TARBALL}" -C "$TMP_DIR" "$BINARY"; then
    error "Could not extract ${BINARY} from the release archive."
fi

if [ ! -f "${TMP_DIR}/${BINARY}" ] || [ -L "${TMP_DIR}/${BINARY}" ]; then
    error "Archive did not contain a regular ${BINARY} binary"
fi

# Make the downloaded candidate executable, then prove both its identity and
# requested release version before reading or replacing any existing install.
chmod +x "${TMP_DIR}/${BINARY}"

EXPECTED_VERSION="${VERSION#v}"
VALIDATION_OUTPUT=""
VALIDATION_ERROR=""

validate_binary() {
    VALIDATION_PATH="$1"
    VALIDATION_OUTPUT=""
    VALIDATION_ERROR=""

    if [ ! -f "$VALIDATION_PATH" ] || [ ! -x "$VALIDATION_PATH" ]; then
        VALIDATION_ERROR="candidate is not a regular executable file"
        return 1
    fi
    if ! VALIDATION_OUTPUT=$("$VALIDATION_PATH" version 2>&1); then
        VALIDATION_ERROR="candidate could not execute its version command"
        return 1
    fi

    VALIDATION_NAME=$(printf '%s\n' "$VALIDATION_OUTPUT" | awk 'NR == 1 { print $1; exit }')
    VALIDATION_VERSION=$(printf '%s\n' "$VALIDATION_OUTPUT" | awk 'NR == 1 { print $2; exit }')
    case "$VALIDATION_VERSION" in
        v*) VALIDATION_VERSION="${VALIDATION_VERSION#v}" ;;
    esac
    if [ "$VALIDATION_NAME" != "rampart" ] || [ "$VALIDATION_VERSION" != "$EXPECTED_VERSION" ]; then
        VALIDATION_ERROR="candidate reports ${VALIDATION_NAME:-unknown} ${VALIDATION_VERSION:-unknown}; expected rampart ${EXPECTED_VERSION}"
        return 1
    fi
    return 0
}

if ! validate_binary "${TMP_DIR}/${BINARY}"; then
    error "Downloaded Rampart candidate failed validation: ${VALIDATION_ERROR}."
fi
info "Candidate version verified ✓"

if [ ! -d "$INSTALL_DIR" ]; then
    if ! mkdir -p "$INSTALL_DIR" 2>/dev/null; then
        info "Need sudo to create ${INSTALL_DIR}"
        sudo mkdir -p "$INSTALL_DIR"
    fi
fi

if [ -w "$INSTALL_DIR" ]; then
    NEED_SUDO=0
else
    NEED_SUDO=1
    if ! command -v sudo >/dev/null 2>&1; then
        error "${INSTALL_DIR} is not writable and sudo is unavailable."
    fi
    info "Need sudo to install to ${INSTALL_DIR}"
fi

RAMPART_BIN="${INSTALL_DIR}/${BINARY}"
if [ -L "$RAMPART_BIN" ]; then
    error "Refusing to replace symlink install path: ${RAMPART_BIN}. Install to the symlink target explicitly."
fi
# `mv source destination` treats a directory as a container rather than
# replacing the destination path. Refuse that shape before creating
# transaction state so activation and rollback can never deposit installer
# files inside an unrelated directory.
if [ -d "$RAMPART_BIN" ]; then
    error "Refusing to replace directory install path: ${RAMPART_BIN}"
fi

# mktemp creates a dedicated transaction directory below INSTALL_DIR. The staged
# candidate, backup, and destination therefore share a filesystem.
if ! TXN_DIR=$(install_cmd mktemp -d "${INSTALL_DIR}/.rampart-install.XXXXXX"); then
    error "Could not create a transaction directory in ${INSTALL_DIR}."
fi
# A root-owned transaction directory needs search permission so the invoking
# user can execute the staged candidate without running downloaded code as root.
if [ "$NEED_SUDO" = "1" ]; then
    install_cmd chmod 711 "$TXN_DIR"
fi
STAGED_BIN="${TXN_DIR}/rampart.candidate"
if ! install_cmd cp "${TMP_DIR}/${BINARY}" "$STAGED_BIN" || ! install_cmd chmod 755 "$STAGED_BIN"; then
    error "Could not stage Rampart in ${INSTALL_DIR}."
fi

# Validate the same bytes that will be renamed into place. This also detects a
# broken mount or permission setup before the installed binary is touched.
if ! validate_binary "$STAGED_BIN"; then
    error "Staged Rampart candidate failed validation: ${VALIDATION_ERROR}."
fi

if [ -e "$RAMPART_BIN" ] || [ -L "$RAMPART_BIN" ]; then
    HAD_EXISTING=1
    if ! install_cmd cp -Pp "$RAMPART_BIN" "${TXN_DIR}/rampart.previous"; then
        error "Could not back up the existing Rampart binary; installation was not changed."
    fi
fi

# Stop only runtimes whose PID or fixed service definition authenticates this
# exact installed executable. Their state remains part of the transaction: a
# later activation or restart failure restores the old binary and runtime.
if [ "$HAD_EXISTING" = "1" ]; then
    detect_and_stop_managed_runtime
fi

# The old binary remains in place until this same-filesystem rename. If the
# activation or final verification fails, the exit trap restores the backup.
TRANSACTION_ACTIVE=1
if ! install_cmd mv "$STAGED_BIN" "$RAMPART_BIN"; then
    error "Could not activate the new Rampart binary; the previous installation is unchanged."
fi
ACTIVATED=1

# Verify through the final path before declaring the transaction committed.
if ! validate_binary "$RAMPART_BIN"; then
    error "Installed Rampart binary failed validation: ${VALIDATION_ERROR}."
fi

if ! restart_managed_runtime activate; then
    error "Rampart was installed, but a previously active managed runtime did not restart. Rolling back."
fi
TRANSACTION_ACTIVE=0
BACKGROUND_SERVE_ACTIVE=0
STOPPED_SYSTEMD_SERVICES=""
STOPPED_LAUNCHD_SERVICES=""

info "Installed to ${BOLD}${RAMPART_BIN}${RESET}"
printf "\n%s\n" "$VALIDATION_OUTPUT"

case ":${PATH}:" in
*":${INSTALL_DIR}:"*)
    printf "\n${GREEN}${BOLD}Ready!${RESET} Run ${BOLD}rampart quickstart${RESET} to get started.\n"
    ;;
*)
    printf "\n${YELLOW}Note:${RESET} ${INSTALL_DIR} may not be in your PATH.\n"
    printf "Add it: ${BOLD}export PATH=\"${INSTALL_DIR}:\$PATH\"${RESET}\n"
    printf "Then run: ${BOLD}rampart quickstart${RESET}\n"
    ;;
esac

printf "\n"
if [ "$AUTO_SETUP" = "1" ]; then
    printf "${GREEN}▸${RESET} Auto-setup: detecting and protecting supported AI agents...\n"
    "$RAMPART_BIN" protect 2>&1 || printf "${YELLOW}  ↳ Auto-setup failed — run manually: rampart protect${RESET}\n"
else
    printf "  Detect, protect, and verify supported AI agents:\n"
    printf "    ${BOLD}rampart protect${RESET}\n\n"
fi
