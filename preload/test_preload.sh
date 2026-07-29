#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "[test] SKIP: live preload contract tests require Linux LD_PRELOAD"
  exit 0
fi

SCRIPT_DIR="${RAMPART_PRELOAD_SOURCE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rampart-preload-test.XXXXXX")"
LIB_PATH="${TMP_DIR}/librampart.so"
SPAWN_PROBE="${TMP_DIR}/spawn_probe"
SERVER_PID=""

cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "[test] compiling preload library and spawn probe"
gcc -shared -fPIC -Wall -Wextra -Werror -pedantic -std=c99 \
  -o "$LIB_PATH" "$SCRIPT_DIR/librampart.c" -ldl -lcurl -lpthread
gcc -Wall -Wextra -Werror -pedantic -std=c99 \
  -o "$SPAWN_PROBE" "$SCRIPT_DIR/spawn_probe.c"

run_preloaded() {
  local url="$1"
  local fail_open="$2"
  local stderr_path="$3"
  shift 3
  if [[ -n "${RAMPART_CONTRACT_PROXY:-}" ]]; then
    HTTP_PROXY="$RAMPART_CONTRACT_PROXY" \
    HTTPS_PROXY="$RAMPART_CONTRACT_PROXY" \
    ALL_PROXY="$RAMPART_CONTRACT_PROXY" \
    http_proxy="$RAMPART_CONTRACT_PROXY" \
    https_proxy="$RAMPART_CONTRACT_PROXY" \
    all_proxy="$RAMPART_CONTRACT_PROXY" \
    NO_PROXY= no_proxy= \
      run_preloaded_direct "$url" "$fail_open" "$stderr_path" "$@"
    return
  fi
  run_preloaded_direct "$url" "$fail_open" "$stderr_path" "$@"
}

run_preloaded_direct() {
  local url="$1"
  local fail_open="$2"
  local stderr_path="$3"
  shift 3
  RAMPART_DEBUG=1 \
    RAMPART_MODE=enforce \
    RAMPART_FAIL_OPEN="$fail_open" \
    RAMPART_AGENT=preload-contract \
    RAMPART_SESSION=preload-contract \
    RAMPART_TOKEN="${RAMPART_CONTRACT_TOKEN:-contract-token}" \
    RAMPART_URL="$url" \
    LD_PRELOAD="$LIB_PATH" \
    "$@" >/dev/null 2>"$stderr_path"
}

expect_result() {
  local name="$1"
  local expected="$2"
  local url="$3"
  local fail_open="$4"
  shift 4
  local stderr_path="${TMP_DIR}/${name}.stderr"
  set +e
  run_preloaded "$url" "$fail_open" "$stderr_path" "$@"
  local status=$?
  set -e
  if [[ "$expected" == "allow" && "$status" -ne 0 ]]; then
    echo "[test] FAIL: $name should allow, got status $status"
    sed -n '1,80p' "$stderr_path"
    exit 1
  fi
  if [[ "$expected" == "deny" && "$status" -eq 0 ]]; then
    echo "[test] FAIL: $name should deny"
    exit 1
  fi
  if ! grep -q '\[rampart\]' "$stderr_path"; then
    echo "[test] FAIL: $name did not exercise the preload library"
    exit 1
  fi
  echo "[test] PASS: $name ($expected)"
}

# Explicit fail-open applies to transport failures, while fail-closed blocks.
expect_result transport-fail-open allow "http://127.0.0.1:1" 1 \
  /bin/sh -c 'exec /bin/true'
expect_result transport-fail-closed deny "http://127.0.0.1:1" 0 \
  /bin/sh -c 'exec /bin/true'

PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
python3 "$SCRIPT_DIR/test_contract_server.py" "$PORT" &
SERVER_PID=$!
for _ in $(seq 1 50); do
  if python3 -c 'import socket,sys; s=socket.socket(); s.settimeout(.1); sys.exit(s.connect_ex(("127.0.0.1", int(sys.argv[1]))))' "$PORT"; then
    break
  fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "[test] FAIL: contract server exited during startup"
    exit 1
  fi
  sleep 0.05
done

BASE_URL="http://127.0.0.1:${PORT}"
expect_result policy-allow allow "${BASE_URL}/allow" 0 /bin/sh -c 'exec /bin/true'
expect_result policy-deny deny "${BASE_URL}/deny" 1 /bin/sh -c 'exec /bin/true'
expect_result deceptive-response deny "${BASE_URL}/deceptive" 1 /bin/sh -c 'exec /bin/true'
expect_result malformed-response deny "${BASE_URL}/malformed" 1 /bin/sh -c 'exec /bin/true'
expect_result auth-failure deny "${BASE_URL}/auth" 1 /bin/sh -c 'exec /bin/true'
expect_result oversized-response deny "${BASE_URL}/oversized" 1 /bin/sh -c 'exec /bin/true'
expect_result server-fail-open allow "${BASE_URL}/server-error" 1 /bin/sh -c 'exec /bin/true'
expect_result server-fail-closed deny "${BASE_URL}/server-error" 0 /bin/sh -c 'exec /bin/true'

# Ambient proxy variables must never receive policy commands or bearer tokens.
# Point every proxy variable at a closed local port: a proxy-aware client would
# fail closed instead of reaching the allow endpoint directly.
RAMPART_CONTRACT_PROXY="http://127.0.0.1:1" \
  expect_result ambient-proxy-ignored allow "${BASE_URL}/allow" 0 \
  /bin/sh -c 'exec /bin/true'

# Debug diagnostics describe the decision without copying raw argv secrets to
# stderr, terminal logs, or host artifacts.
expect_result debug-command-redaction allow "${BASE_URL}/allow" 0 \
  /bin/sh -c 'exec /bin/true rampart-debug-secret-canary'
if grep -q 'rampart-debug-secret-canary' "${TMP_DIR}/debug-command-redaction.stderr"; then
  echo "[test] FAIL: debug log exposed the intercepted command" >&2
  exit 1
fi

# Unsupported schemes and URL credentials are local configuration failures;
# fail-open applies only to transport/5xx degradation.
expect_result unsupported-protocol deny "file:///tmp/rampart-policy" 1 \
  /bin/sh -c 'exec /bin/true'
expect_result embedded-url-credentials deny "http://user:secret@127.0.0.1:${PORT}/allow" 1 \
  /bin/sh -c 'exec /bin/true'

# Both spawn variants must enforce and must report the real executable rather
# than the caller-controlled argv[0].
expect_result posix-spawn-allow allow "${BASE_URL}/allow" 0 "$SPAWN_PROBE" spawn
expect_result posix-spawn-deny deny "${BASE_URL}/deny" 1 "$SPAWN_PROBE" spawn
expect_result posix-spawnp-allow allow "${BASE_URL}/allow" 0 "$SPAWN_PROBE" spawnp
expect_result posix-spawnp-deny deny "${BASE_URL}/deny" 1 "$SPAWN_PROBE" spawnp

# When invoked by the isolated Linux lab, retain the real Rampart policy check.
if [[ -n "${RAMPART_ADDR:-}" ]]; then
  BLOCK_CMD="${RAMPART_BLOCK_CMD:-rm -rf /tmp/rampart_preload_block_test_$$}"
  RAMPART_CONTRACT_TOKEN="${RAMPART_TOKEN:-}" \
    expect_result real-policy-deny deny "${RAMPART_URL:-http://$RAMPART_ADDR}" 0 \
    /bin/sh -c "$BLOCK_CMD"
else
  echo "[test] SKIP: RAMPART_ADDR is not set; skipped real-policy assertion"
fi

echo "[test] all preload contract checks passed"
