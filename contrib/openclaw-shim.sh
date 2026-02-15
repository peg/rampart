#!/usr/bin/env bash
REAL_SHELL="/bin/bash"
RAMPART_URL="http://127.0.0.1:19090"
RAMPART_TOKEN="c86356c424aafc202ec88e7cbdc6ce3cb0484be26c89cac20254dce4b6774897"
RAMPART_MODE="enforce"
APPROVAL_POLL_INTERVAL=3
APPROVAL_TIMEOUT=300

if [ "$1" = "-c" ]; then
    shift
    CMD="$1"
    shift

    if ! command -v curl >/dev/null 2>&1; then
        exec "$REAL_SHELL" -c "$CMD" "$@"
    fi

    ENCODED=$(printf '%s' "$CMD" | base64 | tr -d '\n\r')
    PAYLOAD=$(printf '{"agent":"openclaw","session":"main","params":{"command_b64":"%s"}}' "$ENCODED")
    HTTP_CODE=$(curl -sS -o /tmp/.rampart-resp -w "%{http_code}" -X POST "${RAMPART_URL}/v1/tool/exec" \
        -H "Authorization: Bearer ${RAMPART_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD" 2>/dev/null)
    DECISION=$(cat /tmp/.rampart-resp 2>/dev/null)
    rm -f /tmp/.rampart-resp

    # Fail open if no response
    if [ -z "$DECISION" ]; then
        exec "$REAL_SHELL" -c "$CMD" "$@"
    fi

    # Check HTTP status — 403 means denied
    if [ "$RAMPART_MODE" = "enforce" ] && [ "$HTTP_CODE" = "403" ]; then
        MSG=$(printf '%s' "$DECISION" | sed -n 's/.*"message":"\([^"]*\)".*/\1/p' | head -n 1)
        if [ -z "$MSG" ]; then MSG="policy denied"; fi
        echo "rampart: blocked — ${MSG}" >&2
        exit 126
    fi

    # Check "decision":"deny" as fallback
    DENIED=$(printf '%s' "$DECISION" | sed -n 's/.*"decision":"\(deny\)".*/\1/p' | head -n 1)
    if [ "$RAMPART_MODE" = "enforce" ] && [ "$DENIED" = "deny" ]; then
        MSG=$(printf '%s' "$DECISION" | sed -n 's/.*"message":"\([^"]*\)".*/\1/p' | head -n 1)
        if [ -z "$MSG" ]; then MSG="policy denied"; fi
        echo "rampart: blocked — ${MSG}" >&2
        exit 126
    fi

    # Handle require_approval — block and poll until resolved
    APPROVAL_ID=$(printf '%s' "$DECISION" | sed -n 's/.*"approval_id":"\([^"]*\)".*/\1/p' | head -n 1)
    if [ -n "$APPROVAL_ID" ]; then
        MSG=$(printf '%s' "$DECISION" | sed -n 's/.*"message":"\([^"]*\)".*/\1/p' | head -n 1)
        if [ -z "$MSG" ]; then MSG="approval required"; fi
        echo "rampart: ⏳ waiting for approval — ${MSG}" >&2
        echo "rampart: approval id: ${APPROVAL_ID}" >&2

        ELAPSED=0
        while [ "$ELAPSED" -lt "$APPROVAL_TIMEOUT" ]; do
            sleep "$APPROVAL_POLL_INTERVAL"
            ELAPSED=$((ELAPSED + APPROVAL_POLL_INTERVAL))

            # Poll individual approval endpoint
            POLL_RESP=$(curl -sS "${RAMPART_URL}/v1/approvals/${APPROVAL_ID}" \
                -H "Authorization: Bearer ${RAMPART_TOKEN}" 2>/dev/null)
            STATUS=$(printf '%s' "$POLL_RESP" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p' | head -n 1)

            case "$STATUS" in
                approved)
                    echo "rampart: ✅ approved" >&2
                    exec "$REAL_SHELL" -c "$CMD" "$@"
                    ;;
                denied|expired)
                    echo "rampart: ❌ ${STATUS}" >&2
                    exit 126
                    ;;
                pending)
                    # Still waiting
                    ;;
                *)
                    # Unknown or error — keep polling
                    ;;
            esac
        done

        # Timed out waiting
        echo "rampart: ⏰ approval timed out after ${APPROVAL_TIMEOUT}s" >&2
        exit 126
    fi

    exec "$REAL_SHELL" -c "$CMD" "$@"
fi

exec "$REAL_SHELL" "$@"
