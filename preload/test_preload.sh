#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_PATH="/tmp/librampart.so"
ERR_OK="/tmp/rampart_preload_ok.stderr"
ERR_BLOCK="/tmp/rampart_preload_block.stderr"

rm -f "$LIB_PATH" "$ERR_OK" "$ERR_BLOCK"

echo "[test] compiling preload library"
gcc -shared -fPIC -o "$LIB_PATH" "$SCRIPT_DIR/librampart.c" -ldl -lcurl -lpthread

echo "[test] running allowed command under LD_PRELOAD"
set +e
RAMPART_DEBUG=1 \
RAMPART_MODE=monitor \
RAMPART_FAIL_OPEN=1 \
RAMPART_URL="${RAMPART_URL:-http://127.0.0.1:19090}" \
LD_PRELOAD="$LIB_PATH" \
/bin/sh -c 'echo rampart-preload-ok >/dev/null' 2>"$ERR_OK"
status=$?
set -e

if [[ "$status" -ne 0 ]]; then
  echo "[test] FAIL: expected allowed command to exit 0, got $status"
  exit 1
fi

if ! grep -q "\[rampart\]" "$ERR_OK"; then
  echo "[test] FAIL: preload library did not emit rampart stderr output"
  exit 1
fi

echo "[test] PASS: allowed command succeeded and preload output was observed"

if [[ -n "${RAMPART_ADDR:-}" ]]; then
  echo "[test] running blocked-command check with RAMPART_ADDR=$RAMPART_ADDR"
  BLOCK_CMD="${RAMPART_BLOCK_CMD:-rm -rf /tmp/rampart_preload_block_test_$$}"
  set +e
  RAMPART_DEBUG=1 \
  RAMPART_MODE=enforce \
  RAMPART_FAIL_OPEN=0 \
  RAMPART_URL="${RAMPART_URL:-http://$RAMPART_ADDR}" \
  LD_PRELOAD="$LIB_PATH" \
  /bin/sh -c "$BLOCK_CMD" >/dev/null 2>"$ERR_BLOCK"
  block_status=$?
  set -e

  if [[ "$block_status" -eq 0 ]]; then
    echo "[test] FAIL: expected blocked command to fail, but it succeeded"
    echo "[test] command: $BLOCK_CMD"
    exit 1
  fi

  if ! grep -q "Blocking" "$ERR_BLOCK"; then
    echo "[test] FAIL: blocked command failed but no blocking log was found"
    exit 1
  fi

  echo "[test] PASS: blocked command was denied"
else
  echo "[test] SKIP: RAMPART_ADDR is not set; skipped blocked-command assertion"
fi

echo "[test] all checks passed"
