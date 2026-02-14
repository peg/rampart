#!/usr/bin/env bash

set -euo pipefail

PORT="${PORT:-19091}"
TOKEN="${RAMPART_TOKEN:-openclaw-approval-test-token}"
TMP_DIR="$(mktemp -d)"
CONFIG_PATH="$TMP_DIR/rampart-approval.yaml"
AUDIT_DIR="$TMP_DIR/audit"
SERVER_LOG="$TMP_DIR/server.log"
SERVER_PID=""

cleanup() {
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

mkdir -p "$AUDIT_DIR"

cat > "$CONFIG_PATH" <<'YAML'
version: "1"
default_action: allow

policies:
  - name: dangerous-commands
    match:
      tool: exec
    rules:
      - action: require_approval
        when:
          command_matches:
            - "rm *"
            - "terraform *"
            - "kubectl delete *"
        message: "Requires human approval"
YAML

echo "[1/6] Starting Rampart with require_approval policy"
echo "Expected: service starts and health endpoint reports status=ok"
RAMPART_TOKEN="$TOKEN" go run ./cmd/rampart \
  --config "$CONFIG_PATH" \
  serve --mode enforce --port "$PORT" --audit-dir "$AUDIT_DIR" \
  >"$SERVER_LOG" 2>&1 &
SERVER_PID="$!"

for _ in $(seq 1 50); do
  if curl -sf "http://127.0.0.1:${PORT}/healthz" >/dev/null; then
    break
  fi
  sleep 0.2
done

HEALTH_JSON="$(curl -s "http://127.0.0.1:${PORT}/healthz")"
echo "healthz: $HEALTH_JSON"

echo
echo "[2/6] Sending tool call that should require approval"
echo "Expected: HTTP 202 and JSON includes approval_id + approval_status=pending"
TOOL_RESP_FILE="$TMP_DIR/tool-response.json"
TOOL_STATUS="$(curl -sS -o "$TOOL_RESP_FILE" -w "%{http_code}" \
  -X POST "http://127.0.0.1:${PORT}/v1/tool/exec" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"agent":"codex","session":"openclaw-flow","params":{"command":"kubectl delete pod x"}}')"
TOOL_BODY="$(cat "$TOOL_RESP_FILE")"
echo "status: $TOOL_STATUS"
echo "body:   $TOOL_BODY"

if [[ "$TOOL_STATUS" != "202" ]]; then
  echo "ERROR: expected 202 from require_approval path"
  exit 1
fi

APPROVAL_ID="$(printf '%s' "$TOOL_BODY" | sed -n 's/.*"approval_id"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p')"
if [[ -z "$APPROVAL_ID" ]]; then
  echo "ERROR: approval_id missing from response"
  exit 1
fi

echo "extracted approval_id: $APPROVAL_ID"

echo
echo "[3/6] Listing pending approvals"
echo "Expected: approvals array contains the same approval_id"
PENDING_RESP="$(curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:${PORT}/v1/approvals")"
echo "pending: $PENDING_RESP"

if ! printf '%s' "$PENDING_RESP" | grep -q "$APPROVAL_ID"; then
  echo "ERROR: pending approvals did not include approval_id"
  exit 1
fi

echo
echo "[4/6] Resolving approval as approved=true"
echo "Expected: HTTP 200 and status=approved"
RESOLVE_RESP_FILE="$TMP_DIR/resolve-response.json"
RESOLVE_STATUS="$(curl -sS -o "$RESOLVE_RESP_FILE" -w "%{http_code}" \
  -X POST "http://127.0.0.1:${PORT}/v1/approvals/${APPROVAL_ID}/resolve" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"approved":true,"resolved_by":"openclaw-test"}')"
RESOLVE_BODY="$(cat "$RESOLVE_RESP_FILE")"
echo "status: $RESOLVE_STATUS"
echo "body:   $RESOLVE_BODY"

if [[ "$RESOLVE_STATUS" != "200" ]]; then
  echo "ERROR: expected 200 from resolve endpoint"
  exit 1
fi
if ! printf '%s' "$RESOLVE_BODY" | grep -q '"status":"approved"'; then
  echo "ERROR: resolve response did not report approved status"
  exit 1
fi

echo
echo "[5/6] Listing approvals again"
echo "Expected: approvals array is empty (resolved items are removed from pending store)"
PENDING_AFTER="$(curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:${PORT}/v1/approvals")"
echo "pending-after: $PENDING_AFTER"

if ! printf '%s' "$PENDING_AFTER" | grep -q '"approvals":\[\]'; then
  echo "WARNING: pending list not empty; inspect output above"
fi

echo
echo "[6/6] Approval flow test completed"
echo "Expected: all checks above passed without ERROR"
