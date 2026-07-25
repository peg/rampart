#!/usr/bin/env bash
# Copyright 2026 The Rampart Authors
# Licensed under the Apache License, Version 2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
harness="${repo_root}/scripts/compat-codex-host.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "${tmp}/source-codex" "${tmp}/runtime" "${tmp}/bin"
printf '{"test_token":"must-not-appear-in-artifacts"}\n' >"${tmp}/source-codex/auth.json"
chmod 600 "${tmp}/source-codex/auth.json"

cat >"${tmp}/bin/codex" <<'PY'
#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import sys

if "--version" in sys.argv:
    print("codex-cli test-double")
    raise SystemExit(0)

args = sys.argv[1:]
try:
    cwd = Path(args[args.index("-C") + 1])
except (ValueError, IndexError):
    raise SystemExit("fake codex: missing -C")
prompt = args[-1]
marker = (
    "rampart-host-canary"
    if "rampart-host-canary" in prompt
    else "rampart-host-allowed"
)

hooks = json.loads((Path(os.environ["CODEX_HOME"]) / "hooks.json").read_text())
tool_use_id = "call-deny" if marker.endswith("canary") else "call-allow"
session_id = "session-deny" if marker.endswith("canary") else "session-allow"
base = {
    "session_id": session_id,
    "cwd": str(cwd),
    "tool_name": "Bash",
    "tool_use_id": tool_use_id,
    "tool_input": {"command": f"printf {marker}"},
}

def invoke(event, response=None):
    payload = dict(base, hook_event_name=event)
    if response is not None:
        payload["tool_response"] = response
    entry = hooks["hooks"][event][0]["hooks"][0]
    result = subprocess.run(
        entry["command"],
        shell=True,
        cwd=cwd,
        env=os.environ,
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(
            f"fake codex: {event} hook failed: {result.returncode}: {result.stderr}"
        )
    return json.loads(result.stdout or "{}")

pre = invoke("PreToolUse")
specific = pre.get("hookSpecificOutput") or {}
if specific.get("permissionDecision") == "deny":
    print("hook: PreToolUse Blocked")
    print(specific.get("permissionDecisionReason", "denied"))
    raise SystemExit(0)

print("hook: PreToolUse Completed")
print(marker, end="")
invoke("PostToolUse", {"stdout": marker, "stderr": "", "exit_code": 0})
print("\nhook: PostToolUse Completed")
PY
chmod +x "${tmp}/bin/codex"

go build -o "${tmp}/bin/rampart" "${repo_root}/cmd/rampart"

if "$harness" --help | grep -q -- '--yes'; then
  :
else
  echo "test-compat-codex-host: help is missing opt-in guidance" >&2
  exit 1
fi

if TMPDIR="${tmp}/runtime" \
  "$harness" \
    --yes \
    --codex-bin "${tmp}/bin/codex" \
    --rampart-bin "${tmp}/bin/rampart" \
    --codex-home "${tmp}/source-codex" \
    --artifacts "${tmp}/artifacts" >"${tmp}/result.out" 2>"${tmp}/result.err"; then
  :
else
  cat "${tmp}/result.out" >&2
  cat "${tmp}/result.err" >&2
  exit 1
fi

python3 - "${tmp}/artifacts/summary.json" <<'PY'
import json
from pathlib import Path
import sys

summary = json.loads(Path(sys.argv[1]).read_text())
assert summary["result"] == "pass", summary
assert summary["source_codex_state_loaded"] == ["auth.json"], summary
assert summary["session_persistence"] == "ephemeral", summary
assert summary["user_config_loaded"] is False, summary
assert all(summary["checks"].values()), summary
PY

grep -q 'must-not-appear-in-artifacts' "${tmp}/source-codex/auth.json"
if grep -R -q 'must-not-appear-in-artifacts' "${tmp}/artifacts"; then
  echo "test-compat-codex-host: credential leaked into artifacts" >&2
  exit 1
fi
if find "${tmp}/runtime" -maxdepth 1 -type d -name 'rampart-codex-host.*' -print -quit | grep -q .; then
  echo "test-compat-codex-host: disposable credential runtime was not cleaned" >&2
  find "${tmp}/runtime" -maxdepth 1 -type d -name 'rampart-codex-host.*' -print >&2
  exit 1
fi

echo "test-compat-codex-host: PASS"
