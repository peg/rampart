#!/usr/bin/env bash

set -euo pipefail

PORT="${PORT:-19091}"
TOKEN="${RAMPART_TOKEN:-openclaw-approval-test-token}"
TMP_DIR="$(mktemp -d)"
CONFIG_PATH="$TMP_DIR/rampart-approval.yaml"
AUDIT_DIR="$TMP_DIR/audit"
SERVER_LOG="$TMP_DIR/server.log"
SERVER_BIN="$TMP_DIR/rampart"
TEST_HOME="$TMP_DIR/home"
SERVER_PID=""

cleanup() {
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

mkdir -p "$AUDIT_DIR" "$TEST_HOME/.config" "$TEST_HOME/.local/state"

cat > "$CONFIG_PATH" <<'YAML'
version: "1"
default_action: allow

policies:
  - name: dangerous-commands
    match:
      tool: exec
    rules:
      - action: ask
        when:
          command_matches:
            - "rm *"
            - "terraform *"
            - "kubectl delete *"
        message: "Requires human approval"
YAML

echo "[1/8] Starting Rampart with ask policy"
echo "Expected: service starts and health endpoint reports status=ok"
go build -o "$SERVER_BIN" ./cmd/rampart
HOME="$TEST_HOME" \
XDG_CONFIG_HOME="$TEST_HOME/.config" \
XDG_STATE_HOME="$TEST_HOME/.local/state" \
RAMPART_TOKEN="$TOKEN" "$SERVER_BIN" \
  --config "$CONFIG_PATH" \
  serve --mode enforce --port "$PORT" --audit-dir "$AUDIT_DIR" \
  >"$SERVER_LOG" 2>&1 &
SERVER_PID="$!"

for _ in $(seq 1 50); do
  if curl -sf "http://127.0.0.1:${PORT}/healthz" >/dev/null; then
    break
  fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "ERROR: Rampart exited before becoming healthy"
    sed -n '1,120p' "$SERVER_LOG"
    exit 1
  fi
  sleep 0.2
done

if ! curl -sf "http://127.0.0.1:${PORT}/healthz" >/dev/null; then
  echo "ERROR: Rampart did not become healthy on port $PORT"
  sed -n '1,120p' "$SERVER_LOG"
  exit 1
fi

HEALTH_JSON="$(curl -s "http://127.0.0.1:${PORT}/healthz")"
echo "healthz: $HEALTH_JSON"

echo
echo "[2/8] Sending tool call that should require approval"
echo "Expected: HTTP 202 and JSON includes approval_id + approval_status=pending"
TOOL_REQUEST='{"agent":"codex","session":"openclaw-flow","run_id":"approval-flow-run","tool_call_id":"approval-flow-tool-call","params":{"command":"kubectl delete pod x"}}'
TOOL_RESP_FILE="$TMP_DIR/tool-response.json"
TOOL_STATUS="$(curl -sS -o "$TOOL_RESP_FILE" -w "%{http_code}" \
  -X POST "http://127.0.0.1:${PORT}/v1/tool/exec" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$TOOL_REQUEST")"
TOOL_BODY="$(cat "$TOOL_RESP_FILE")"
echo "status: $TOOL_STATUS"
echo "body:   $TOOL_BODY"

if [[ "$TOOL_STATUS" != "202" ]]; then
  echo "ERROR: expected 202 from ask path"
  exit 1
fi

APPROVAL_ID="$(python3 - "$TOOL_RESP_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    value = json.load(handle).get("approval_id", "")
print(value if isinstance(value, str) else "")
PY
)"
if [[ -z "$APPROVAL_ID" ]]; then
  echo "ERROR: approval_id missing from response"
  exit 1
fi

echo "extracted approval_id: $APPROVAL_ID"

echo
echo "[3/8] Listing pending approvals"
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
echo "[4/8] Resolving approval as approved=true"
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
echo "[5/8] Replaying the exact approved tool call"
echo "Expected: HTTP 200 with allowed=true, decision=allow, and one-shot approval metadata"
REPLAY_RESP_FILE="$TMP_DIR/replay-response.json"
REPLAY_STATUS="$(curl -sS -o "$REPLAY_RESP_FILE" -w "%{http_code}" \
  -X POST "http://127.0.0.1:${PORT}/v1/tool/exec" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$TOOL_REQUEST")"
REPLAY_BODY="$(cat "$REPLAY_RESP_FILE")"
echo "status: $REPLAY_STATUS"
echo "body:   $REPLAY_BODY"

if [[ "$REPLAY_STATUS" != "200" ]]; then
  echo "ERROR: expected 200 from exact approved replay"
  exit 1
fi
if ! python3 - "$REPLAY_RESP_FILE" "$APPROVAL_ID" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    payload = json.load(handle)
expected_id = sys.argv[2]
valid = (
    payload.get("allowed") is True
    and payload.get("decision") == "allow"
    and payload.get("approval_id") == expected_id
    and payload.get("approval_status") == "approved"
    and payload.get("approval_scope") == "once"
    and payload.get("approval_resolved_by") == "openclaw-test"
    and isinstance(payload.get("approval_policy_audit_id"), str)
    and bool(payload.get("approval_policy_audit_id"))
)
raise SystemExit(0 if valid else 1)
PY
then
  echo "ERROR: approved replay did not return explicit allow-once semantics"
  exit 1
fi

echo
echo "[6/8] Listing approvals after the approved replay"
echo "Expected: approvals array is empty"
PENDING_AFTER="$(curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:${PORT}/v1/approvals")"
echo "pending-after: $PENDING_AFTER"

if ! python3 - "$PENDING_AFTER" <<'PY'
import json
import sys

payload = json.loads(sys.argv[1])
raise SystemExit(0 if payload.get("approvals") == [] else 1)
PY
then
  echo "ERROR: resolved approval remained in the pending list"
  exit 1
fi

echo
echo "[7/8] Replaying the same call a second time"
echo "Expected: HTTP 202 with a new pending approval; the one-shot grant cannot be reused"
SECOND_RESP_FILE="$TMP_DIR/second-replay-response.json"
SECOND_STATUS="$(curl -sS -o "$SECOND_RESP_FILE" -w "%{http_code}" \
  -X POST "http://127.0.0.1:${PORT}/v1/tool/exec" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$TOOL_REQUEST")"
SECOND_BODY="$(cat "$SECOND_RESP_FILE")"
echo "status: $SECOND_STATUS"
echo "body:   $SECOND_BODY"

if [[ "$SECOND_STATUS" != "202" ]]; then
  echo "ERROR: a second replay reused the one-shot approval"
  exit 1
fi
SECOND_APPROVAL_ID="$(python3 - "$SECOND_RESP_FILE" "$APPROVAL_ID" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    payload = json.load(handle)
value = payload.get("approval_id", "")
if payload.get("approval_status") != "pending" or not isinstance(value, str) or not value or value == sys.argv[2]:
    raise SystemExit(1)
print(value)
PY
)" || {
  echo "ERROR: second replay did not create a distinct pending approval"
  exit 1
}

# Resolve the deliberately created second request as denied so the isolated
# server finishes with no pending state.
SECOND_RESOLVE_STATUS="$(curl -sS -o /dev/null -w "%{http_code}" \
  -X POST "http://127.0.0.1:${PORT}/v1/approvals/${SECOND_APPROVAL_ID}/resolve" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"approved":false,"resolved_by":"openclaw-test-cleanup"}')"
if [[ "$SECOND_RESOLVE_STATUS" != "200" ]]; then
  echo "ERROR: could not resolve the second pending approval during cleanup"
  exit 1
fi

echo
echo "[8/8] Approval flow test completed"
echo "Expected: final approvals array is empty and all checks passed without ERROR"
FINAL_PENDING="$(curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:${PORT}/v1/approvals")"
if ! python3 - "$FINAL_PENDING" <<'PY'
import json
import sys

payload = json.loads(sys.argv[1])
raise SystemExit(0 if payload.get("approvals") == [] else 1)
PY
then
  echo "ERROR: approval flow left pending state behind"
  exit 1
fi
