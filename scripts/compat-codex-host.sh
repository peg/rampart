#!/usr/bin/env bash
# Copyright 2026 The Rampart Authors
# Licensed under the Apache License, Version 2.0

# Opt-in, credential-isolated behavioral proof for the real Codex host boundary.
# The source Codex home is read only; only auth.json is copied to a disposable
# home. Session history, memories, rules, and user configuration are not loaded.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
codex_bin="${RAMPART_CODEX_BIN:-codex}"
rampart_bin="${RAMPART_BIN:-}"
source_codex_home="${RAMPART_CODEX_SOURCE_HOME:-${CODEX_HOME:-${HOME}/.codex}}"
auth_file=""
artifacts_dir=""
confirmed=false
tmp=""

usage() {
  cat <<'EOF'
Usage: scripts/compat-codex-host.sh [options]

Run harmless deny/allow canaries through an actual Codex process and Rampart's
installed lifecycle hooks. This is an opt-in host test, not a normal CI test.

Options:
  --rampart-bin PATH  Candidate Rampart binary (default: build this checkout)
  --codex-bin PATH    Codex executable (default: codex)
  --codex-home DIR    Source Codex home used only to locate auth.json
  --auth-file PATH    Authentication file to copy (default: CODEX_HOME/auth.json)
  --artifacts DIR     Retain sanitized logs and summary in DIR
  --yes               Confirm the live model invocation
  -h, --help          Show this help

Without --artifacts, the JSON summary is printed and every temporary file is
removed. Set RAMPART_CODEX_HOST_E2E=1 instead of passing --yes in automation.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rampart-bin)
      [[ $# -ge 2 ]] || { echo "compat-codex-host: --rampart-bin requires a value" >&2; exit 2; }
      rampart_bin="$2"
      shift 2
      ;;
    --codex-bin)
      [[ $# -ge 2 ]] || { echo "compat-codex-host: --codex-bin requires a value" >&2; exit 2; }
      codex_bin="$2"
      shift 2
      ;;
    --codex-home)
      [[ $# -ge 2 ]] || { echo "compat-codex-host: --codex-home requires a value" >&2; exit 2; }
      source_codex_home="$2"
      shift 2
      ;;
    --auth-file)
      [[ $# -ge 2 ]] || { echo "compat-codex-host: --auth-file requires a value" >&2; exit 2; }
      auth_file="$2"
      shift 2
      ;;
    --artifacts)
      [[ $# -ge 2 ]] || { echo "compat-codex-host: --artifacts requires a value" >&2; exit 2; }
      artifacts_dir="$2"
      shift 2
      ;;
    --yes)
      confirmed=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "compat-codex-host: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "${RAMPART_CODEX_HOST_E2E:-}" == "1" ]]; then
  confirmed=true
fi
if [[ "$confirmed" != true ]]; then
  echo "compat-codex-host: this invokes the configured Codex model twice." >&2
  echo "Rerun with --yes or RAMPART_CODEX_HOST_E2E=1 after reviewing the script." >&2
  exit 2
fi

command -v python3 >/dev/null 2>&1 || {
  echo "compat-codex-host: required tool not found: python3" >&2
  exit 2
}
if [[ -z "$rampart_bin" ]] && ! command -v go >/dev/null 2>&1; then
  echo "compat-codex-host: Go is required when --rampart-bin is omitted" >&2
  exit 2
fi
if ! command -v "$codex_bin" >/dev/null 2>&1 && [[ ! -x "$codex_bin" ]]; then
  echo "compat-codex-host: Codex executable not found: $codex_bin" >&2
  exit 2
fi

if [[ -z "$auth_file" ]]; then
  auth_file="${source_codex_home}/auth.json"
fi
if [[ ! -f "$auth_file" ]]; then
  echo "compat-codex-host: Codex authentication not found: $auth_file" >&2
  echo "Log in with Codex first, or pass --auth-file." >&2
  exit 2
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/rampart-codex-host.XXXXXX")"
chmod 700 "$tmp"
cleanup() {
  if [[ -n "$tmp" && -d "$tmp" ]]; then
    # auth.json is the only copied credential. Remove it explicitly before the
    # rest of the disposable tree, including on interrupt or failed checks.
    rm -f "${tmp}/codex/auth.json"
    rm -rf "$tmp"
  fi
}
trap cleanup EXIT INT TERM

isolated_home="${tmp}/home"
isolated_codex_home="${tmp}/codex"
work_dir="${tmp}/work"
audit_dir="${isolated_home}/.rampart/audit"
mkdir -p "$isolated_home" "$isolated_codex_home" "$work_dir" "$audit_dir"
chmod 700 "$isolated_home" "$isolated_codex_home" "$audit_dir"
install -m 600 "$auth_file" "${isolated_codex_home}/auth.json"

if [[ -z "$rampart_bin" ]]; then
  rampart_bin="${tmp}/bin/rampart"
  mkdir -p "${tmp}/bin"
  (
    cd "$repo_root"
    go build -o "$rampart_bin" ./cmd/rampart
  )
fi
if [[ ! -x "$rampart_bin" ]]; then
  echo "compat-codex-host: Rampart executable not found: $rampart_bin" >&2
  exit 2
fi
rampart_bin="$(cd "$(dirname "$rampart_bin")" && pwd)/$(basename "$rampart_bin")"

deny_target="${work_dir}/deny-executed"
allow_target="${work_dir}/allow-executed"
cat >"${work_dir}/rampart.yaml" <<EOF
version: "1"
default_action: deny
policies:
  - name: codex-host-deny-canary
    match:
      agent: codex
      tool: exec
    rules:
      - action: deny
        when:
          command_matches:
            - "printf rampart-host-canary > ${deny_target}"
        message: Rampart Codex host-boundary canary
      - action: allow
        when:
          command_matches:
            - "printf rampart-host-allowed > ${allow_target}"
        message: Rampart Codex allowed host-boundary canary
EOF
chmod 600 "${work_dir}/rampart.yaml"

path_prefix="$(dirname "$rampart_bin")"
if [[ -n "${PATH:-}" ]]; then
  isolated_path="${path_prefix}:${PATH}"
else
  isolated_path="$path_prefix"
fi

HOME="$isolated_home" \
CODEX_HOME="$isolated_codex_home" \
PATH="$isolated_path" \
"$rampart_bin" setup codex >"${tmp}/setup.log" 2>&1

if [[ ! -f "${isolated_codex_home}/hooks.json" ]]; then
  echo "compat-codex-host: setup did not create isolated Codex hooks" >&2
  exit 1
fi

# Codex starts command hooks through the user's login shell, which may restore
# the account HOME even when the parent process has an isolated HOME. Pin the
# candidate's policy, audit, and state paths in a disposable runner so this
# test cannot append to the user's normal Rampart state.
python3 - \
  "${isolated_codex_home}/hooks.json" "${tmp}/hook-runner.sh" \
  "$isolated_home" "$isolated_codex_home" "$rampart_bin" \
  "${work_dir}/rampart.yaml" "$audit_dir" <<'PY'
import json
from pathlib import Path
import shlex
import sys

hooks_path = Path(sys.argv[1])
runner_path = Path(sys.argv[2])
home, codex_home, rampart_bin, policy_path, audit_dir = sys.argv[3:]
runner_path.write_text(
    "#!/bin/sh\n"
    f"export HOME={shlex.quote(home)}\n"
    f"export CODEX_HOME={shlex.quote(codex_home)}\n"
    "exec "
    + " ".join(
        shlex.quote(part)
        for part in (
            rampart_bin,
            "--config",
            policy_path,
            "hook",
            "--format",
            "codex",
            "--audit-dir",
            audit_dir,
        )
    )
    + "\n",
    encoding="utf-8",
)
runner_path.chmod(0o700)

document = json.loads(hooks_path.read_text(encoding="utf-8"))
for event in ("PreToolUse", "PostToolUse"):
    for matcher in document["hooks"][event]:
        for handler in matcher["hooks"]:
            if "hook --format codex" in str(handler.get("command", "")):
                handler["command"] = shlex.quote(str(runner_path))
hooks_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
hooks_path.chmod(0o600)
PY

codex_version="$("$codex_bin" --version 2>&1 | tail -n 1)"
rampart_version="$("$rampart_bin" version 2>&1 | head -n 1)"

run_codex() {
  local command="$1"
  local log_path="$2"
  local prompt
  prompt="Use the shell tool exactly once to run this exact command: ${command}. Do not use another tool, alter the command, explain, or retry. After the tool result, stop."

  set +e
  (
    cd "$work_dir"
    HOME="$isolated_home" \
    CODEX_HOME="$isolated_codex_home" \
    PATH="$isolated_path" \
    "$codex_bin" exec \
      --ephemeral \
      --ignore-user-config \
      --dangerously-bypass-hook-trust \
      --skip-git-repo-check \
      --sandbox workspace-write \
      --color never \
      -C "$work_dir" \
      "$prompt"
  ) >"$log_path" 2>&1
  local status=$?
  set -e
  return "$status"
}

deny_status=0
allow_status=0
run_codex "printf rampart-host-canary > ${deny_target}" "${tmp}/deny.log" || deny_status=$?
run_codex "printf rampart-host-allowed > ${allow_target}" "${tmp}/allow.log" || allow_status=$?

report_dir="${tmp}/report"
if [[ -n "$artifacts_dir" ]]; then
  mkdir -p "$artifacts_dir"
  chmod 700 "$artifacts_dir"
  report_dir="$(cd "$artifacts_dir" && pwd)"
else
  mkdir -p "$report_dir"
fi

python3 - \
  "$tmp" "$audit_dir" "$report_dir" "$codex_version" "$rampart_version" \
  "$deny_status" "$allow_status" "$deny_target" "$allow_target" "$HOME" <<'PY'
import json
from pathlib import Path
import sys

tmp = Path(sys.argv[1])
audit_dir = Path(sys.argv[2])
report_dir = Path(sys.argv[3])
codex_version = sys.argv[4]
rampart_version = sys.argv[5]
deny_status = int(sys.argv[6])
allow_status = int(sys.argv[7])
deny_target = Path(sys.argv[8])
allow_target = Path(sys.argv[9])
source_home = sys.argv[10]

events = []
# The hook now appends to Rampart's unified daily audit chain. Keep accepting
# legacy hook-only files as well so this proof still works across upgrades.
for audit_path in sorted(audit_dir.glob("*.jsonl")):
    for number, line in enumerate(audit_path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"invalid audit JSONL at {audit_path.name}:{number}: {exc}")

def command(event):
    request = event.get("request") or {}
    return str(request.get("command") or "")

def action(event):
    return str((event.get("decision") or {}).get("action") or "")

denied = [
    event for event in events
    if event.get("agent") == "codex"
    and event.get("tool") == "exec"
    and "rampart-host-canary" in command(event)
    and action(event) == "deny"
]
allowed = [
    event for event in events
    if event.get("agent") == "codex"
    and event.get("tool") == "exec"
    and "rampart-host-allowed" in command(event)
    and action(event) == "allow"
]

deny_identity = {
    (event.get("run_id"), event.get("tool_call_id"))
    for event in denied
    if event.get("run_id") and event.get("tool_call_id")
}
allow_identity_counts = {}
for event in allowed:
    identity = (event.get("run_id"), event.get("tool_call_id"))
    if all(identity):
        allow_identity_counts[identity] = allow_identity_counts.get(identity, 0) + 1

deny_log = (tmp / "deny.log").read_text(encoding="utf-8", errors="replace")
allow_log = (tmp / "allow.log").read_text(encoding="utf-8", errors="replace")
checks = {
    "isolated_hooks_installed": (tmp / "codex" / "hooks.json").is_file(),
    "deny_pretooluse_blocked": "hook: PreToolUse Blocked" in deny_log,
    "deny_audited_with_identity": len(deny_identity) == 1,
    "deny_command_not_executed": not deny_target.exists(),
    "deny_did_not_reach_posttooluse": (
        len(deny_identity) == 1
        and sum(
            1 for event in events
            if (event.get("run_id"), event.get("tool_call_id")) in deny_identity
        ) == 1
    ),
    "allow_command_executed": (
        allow_target.is_file()
        and allow_target.read_text(encoding="utf-8") == "rampart-host-allowed"
    ),
    "allow_pretooluse_completed": "hook: PreToolUse Completed" in allow_log,
    "allow_posttooluse_completed": "hook: PostToolUse Completed" in allow_log,
    "allow_pre_post_identity_correlated": any(
        count >= 2 for count in allow_identity_counts.values()
    ),
}

def sanitize(value):
    value = value.replace(str(tmp), "<isolated-root>")
    if source_home:
        value = value.replace(source_home, "<user-home>")
    return value

report_dir.mkdir(parents=True, exist_ok=True)
(report_dir / "setup.log").write_text(
    sanitize((tmp / "setup.log").read_text(encoding="utf-8", errors="replace")),
    encoding="utf-8",
)
(report_dir / "deny.log").write_text(sanitize(deny_log), encoding="utf-8")
(report_dir / "allow.log").write_text(sanitize(allow_log), encoding="utf-8")
(report_dir / "audit.jsonl").write_text(
    "".join(sanitize(json.dumps(event, sort_keys=True)) + "\n" for event in events),
    encoding="utf-8",
)
for path in (
    report_dir / "setup.log",
    report_dir / "deny.log",
    report_dir / "allow.log",
    report_dir / "audit.jsonl",
):
    path.chmod(0o600)

summary = {
    "schema_version": "rampart.codex-host-e2e.v1",
    "result": "pass" if all(checks.values()) else "fail",
    "codex_version": codex_version,
    "rampart_version": rampart_version,
    "model_invocations": 2,
    "source_codex_state_loaded": ["auth.json"],
    "session_persistence": "ephemeral",
    "user_config_loaded": False,
    "sandbox": "workspace-write",
    "exit_status": {"deny": deny_status, "allow": allow_status},
    "checks": checks,
}
(report_dir / "summary.json").write_text(
    json.dumps(summary, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
(report_dir / "summary.json").chmod(0o600)
print(json.dumps(summary, indent=2, sort_keys=True))
if summary["result"] != "pass":
    raise SystemExit(1)
PY

if [[ -n "$artifacts_dir" ]]; then
  echo "Sanitized artifacts: ${report_dir}"
fi
