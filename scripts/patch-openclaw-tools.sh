#!/bin/bash
# patch-openclaw-tools.sh — Patch OpenClaw's file tools (Read/Write/Edit) to check Rampart
#
# Usage: rampart setup openclaw --patch-tools
#   Or:  bash scripts/patch-openclaw-tools.sh [--url URL] [--token TOKEN] [--restore]
#
# This patches pi-coding-agent's tool implementations to call rampart serve
# before executing file operations. Patches are fail-open: if rampart serve
# is unreachable, tools work normally.
#
# Re-run after OpenClaw upgrades — patches modify node_modules files.

set -e

RAMPART_URL="${RAMPART_URL:-http://127.0.0.1:19090}"
RAMPART_TOKEN="${RAMPART_TOKEN:-}"
RESTORE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --url) RAMPART_URL="$2"; shift 2 ;;
        --token) RAMPART_TOKEN="$2"; shift 2 ;;
        --restore) RESTORE=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Find pi-coding-agent tools directory
TOOLS_DIR=""
for d in \
    /usr/lib/node_modules/openclaw/node_modules/@mariozechner/pi-coding-agent/dist/core/tools \
    /usr/local/lib/node_modules/openclaw/node_modules/@mariozechner/pi-coding-agent/dist/core/tools \
    "$HOME/.npm-global/lib/node_modules/openclaw/node_modules/@mariozechner/pi-coding-agent/dist/core/tools"; do
    if [ -f "$d/read.js" ]; then
        TOOLS_DIR="$d"
        break
    fi
done

if [ -z "$TOOLS_DIR" ]; then
    echo "Error: Could not find OpenClaw's pi-coding-agent tools directory"
    echo "Searched: /usr/lib, /usr/local/lib, ~/.npm-global/lib"
    exit 1
fi

echo "Found tools: $TOOLS_DIR"

# Restore mode
if [ "$RESTORE" = true ]; then
    for tool in read write edit; do
        backup="$TOOLS_DIR/${tool}.js.rampart-backup"
        if [ -f "$backup" ]; then
            cp "$backup" "$TOOLS_DIR/${tool}.js"
            echo "Restored ${tool}.js"
        else
            echo "No backup for ${tool}.js"
        fi
    done
    echo "Done. Restart the gateway: openclaw gateway restart"
    exit 0
fi

# Check if already patched
if grep -q "RAMPART_.*_CHECK" "$TOOLS_DIR/read.js" 2>/dev/null; then
    echo "Already patched. Use --restore to remove patches first."
    exit 0
fi

# Backup originals
for tool in read write edit; do
    cp "$TOOLS_DIR/${tool}.js" "$TOOLS_DIR/${tool}.js.rampart-backup"
done
echo "Backups created"

# Generate the check snippet for each tool
patch_tool() {
    local tool="$1"
    local file="$TOOLS_DIR/${tool}.js"
    local marker="RAMPART_${tool^^}_CHECK"
    local param_destructure="$2"
    local next_line="$3"

    python3 -c "
import sys
with open('$file') as f:
    code = f.read()

url = '$RAMPART_URL'
token = '$RAMPART_TOKEN'

# Build token expression: prefer env var, fall back to provided token
token_expr = 'process.env.RAMPART_TOKEN' if not token else 'process.env.RAMPART_TOKEN || \"' + token + '\"'

orig = '''execute: async (_toolCallId, $param_destructure, signal) => {
            $next_line'''

patched = '''execute: async (_toolCallId, $param_destructure, signal) => {
            /* $marker */ try {
                const __rr = await fetch((process.env.RAMPART_URL || \"''' + url + '''\") + \"/v1/tool/$tool\", {
                    method: \"POST\",
                    headers: { \"Content-Type\": \"application/json\", \"Authorization\": \"Bearer \" + (''' + token_expr + ''') },
                    body: JSON.stringify({ agent: \"openclaw\", session: \"main\", params: { path } }),
                    signal: AbortSignal.timeout(3000)
                });
                if (__rr.status === 403) {
                    const __rd = await __rr.json().catch(() => ({}));
                    return { content: [{ type: \"text\", text: \"rampart: \" + (__rd.message || \"policy denied\") }] };
                }
            } catch (__re) { /* fail-open: if rampart serve is unreachable, allow */ }
            $next_line'''

if orig in code:
    code = code.replace(orig, patched, 1)
    with open('$file', 'w') as f:
        f.write(code)
    print('  ✅ $tool.js patched')
else:
    print('  ❌ $tool.js: injection point not found (version mismatch?)')
    sys.exit(1)
"
}

echo "Patching tools..."
patch_tool "read" "{ path, offset, limit }" "const absolutePath = resolveReadPath(path, cwd);"
patch_tool "write" "{ path, content }" "const absolutePath = resolveToCwd(path, cwd);"
patch_tool "edit" "{ path, oldText, newText }" "const absolutePath = resolveToCwd(path, cwd);"

echo ""
echo "All tools patched. Restart the gateway:"
echo "  openclaw gateway restart"
echo ""
echo "Note: Re-run this script after OpenClaw upgrades."
