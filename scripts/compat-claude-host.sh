#!/usr/bin/env bash
# Copyright 2026 The Rampart Authors
# Licensed under the Apache License, Version 2.0

# Opt-in behavioral proof through a real Claude Code process. Claude settings,
# sessions, memories, MCP servers, plugins, and project instructions are kept
# out of the disposable HOME. On hosts that store OAuth outside the HOME,
# Claude Code may use the account's OS keychain; an explicit credentials file
# can be copied into the disposable home when required.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
claude_bin="${RAMPART_CLAUDE_BIN:-claude}"
rampart_bin="${RAMPART_BIN:-}"
source_claude_home="${RAMPART_CLAUDE_SOURCE_HOME:-${HOME}/.claude}"
credentials_file=""
artifacts_dir=""
confirmed=false
tmp=""

usage() {
  cat <<'EOF'
Usage: scripts/compat-claude-host.sh [options]

Run harmless deny/allow canaries through an actual Claude Code process and
Rampart's installed lifecycle hooks. This is an opt-in host test, not normal CI.

Options:
  --rampart-bin PATH       Candidate Rampart binary (default: build checkout)
  --claude-bin PATH        Claude Code executable (default: claude)
  --claude-home DIR        Source home used only to locate .credentials.json
  --credentials-file PATH  Credential file to copy into the disposable home
  --artifacts DIR          Retain sanitized logs and summary in DIR
  --yes                    Confirm the two live model invocations
  -h, --help               Show this help

Without --artifacts, the JSON summary is printed and all temporary files are
removed. Set RAMPART_CLAUDE_HOST_E2E=1 instead of --yes in automation.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rampart-bin)
      [[ $# -ge 2 ]] || { echo "compat-claude-host: --rampart-bin requires a value" >&2; exit 2; }
      rampart_bin="$2"
      shift 2
      ;;
    --claude-bin)
      [[ $# -ge 2 ]] || { echo "compat-claude-host: --claude-bin requires a value" >&2; exit 2; }
      claude_bin="$2"
      shift 2
      ;;
    --claude-home)
      [[ $# -ge 2 ]] || { echo "compat-claude-host: --claude-home requires a value" >&2; exit 2; }
      source_claude_home="$2"
      shift 2
      ;;
    --credentials-file)
      [[ $# -ge 2 ]] || { echo "compat-claude-host: --credentials-file requires a value" >&2; exit 2; }
      credentials_file="$2"
      shift 2
      ;;
    --artifacts)
      [[ $# -ge 2 ]] || { echo "compat-claude-host: --artifacts requires a value" >&2; exit 2; }
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
      echo "compat-claude-host: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "${RAMPART_CLAUDE_HOST_E2E:-}" == "1" ]]; then
  confirmed=true
fi
if [[ "$confirmed" != true ]]; then
  echo "compat-claude-host: this invokes the configured Claude model twice." >&2
  echo "Rerun with --yes or RAMPART_CLAUDE_HOST_E2E=1 after reviewing the script." >&2
  exit 2
fi

command -v python3 >/dev/null 2>&1 || {
  echo "compat-claude-host: required tool not found: python3" >&2
  exit 2
}
if [[ -z "$rampart_bin" ]] && ! command -v go >/dev/null 2>&1; then
  echo "compat-claude-host: Go is required when --rampart-bin is omitted" >&2
  exit 2
fi
if ! command -v "$claude_bin" >/dev/null 2>&1 && [[ ! -x "$claude_bin" ]]; then
  echo "compat-claude-host: Claude Code executable not found: $claude_bin" >&2
  exit 2
fi

if [[ -z "$credentials_file" && -f "${source_claude_home}/.credentials.json" ]]; then
  credentials_file="${source_claude_home}/.credentials.json"
fi
if [[ -n "$credentials_file" && ! -f "$credentials_file" ]]; then
  echo "compat-claude-host: credentials file not found: $credentials_file" >&2
  exit 2
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/rampart-claude-host.XXXXXX")"
chmod 700 "$tmp"
cleanup() {
  if [[ -n "$tmp" && -d "$tmp" ]]; then
    rm -f "${tmp}/home/.claude/.credentials.json"
    rm -rf "$tmp"
  fi
}
trap cleanup EXIT INT TERM

isolated_home="${tmp}/home"
isolated_claude_home="${isolated_home}/.claude"
work_dir="${tmp}/work"
audit_dir="${isolated_home}/.rampart/audit"
mkdir -p "$isolated_claude_home" "$work_dir" "$audit_dir"
chmod 700 "$isolated_home" "$isolated_claude_home" "$work_dir" "$audit_dir"
if [[ -n "$credentials_file" ]]; then
  install -m 600 "$credentials_file" "${isolated_claude_home}/.credentials.json"
fi

if [[ -z "$rampart_bin" ]]; then
  rampart_bin="${tmp}/bin/rampart"
  mkdir -p "${tmp}/bin"
  (
    cd "$repo_root"
    go build -o "$rampart_bin" ./cmd/rampart
  )
fi
if [[ ! -x "$rampart_bin" ]]; then
  echo "compat-claude-host: Rampart executable not found: $rampart_bin" >&2
  exit 2
fi
rampart_bin="$(cd "$(dirname "$rampart_bin")" && pwd)/$(basename "$rampart_bin")"

deny_target="${work_dir}/deny-executed"
allow_target="${work_dir}/allow-executed"
cat >"${work_dir}/rampart.yaml" <<EOF
version: "1"
default_action: deny
policies:
  - name: claude-host-deny-canary
    match:
      agent: claude-code
      tool: exec
    rules:
      - action: deny
        when:
          command_matches:
            - "printf rampart-host-canary > ${deny_target}"
        message: Rampart Claude host-boundary canary
      - action: allow
        when:
          command_matches:
            - "printf rampart-host-allowed > ${allow_target}"
        message: Rampart Claude allowed host-boundary canary
EOF
chmod 600 "${work_dir}/rampart.yaml"

path_prefix="$(dirname "$rampart_bin")"
isolated_path="$path_prefix"
if [[ -n "${PATH:-}" ]]; then
  isolated_path="${isolated_path}:${PATH}"
fi

HOME="$isolated_home" \
PATH="$isolated_path" \
"$rampart_bin" setup claude-code >"${tmp}/setup.log" 2>&1

settings_path="${isolated_claude_home}/settings.json"
if [[ ! -f "$settings_path" ]]; then
  echo "compat-claude-host: setup did not create isolated Claude settings" >&2
  exit 1
fi

# Pin policy, audit, and HOME paths in a disposable runner. This remains safe if
# a host shell changes HOME before invoking the configured command.
python3 - \
  "$settings_path" "${tmp}/hook-runner.sh" "$isolated_home" \
  "$rampart_bin" "${work_dir}/rampart.yaml" "$audit_dir" <<'PY'
import json
from pathlib import Path
import shlex
import sys

settings_path = Path(sys.argv[1])
runner_path = Path(sys.argv[2])
home, rampart_bin, policy_path, audit_dir = sys.argv[3:]
runner_path.write_text(
    "#!/bin/sh\n"
    f"export HOME={shlex.quote(home)}\n"
    "exec "
    + " ".join(
        shlex.quote(part)
        for part in (
            rampart_bin,
            "--config",
            policy_path,
            "hook",
            "--format",
            "claude-code",
            "--audit-dir",
            audit_dir,
        )
    )
    + "\n",
    encoding="utf-8",
)
runner_path.chmod(0o700)

document = json.loads(settings_path.read_text(encoding="utf-8"))
for event in ("PreToolUse", "PostToolUse", "PostToolUseFailure"):
    entries = document.get("hooks", {}).get(event, [])
    if not entries:
        raise SystemExit(f"missing installed {event} hook")
    for matcher in entries:
        for handler in matcher.get("hooks", []):
            if "hook --format claude-code" in str(handler.get("command", "")):
                handler["command"] = shlex.quote(str(runner_path))
settings_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
settings_path.chmod(0o600)
PY

claude_version="$("$claude_bin" --version 2>&1 | tail -n 1)"
rampart_version="$("$rampart_bin" version 2>&1 | head -n 1)"

run_claude() {
  local command="$1"
  local log_path="$2"
  local debug_path="$3"
  local prompt
  prompt="Use the Bash tool exactly once to run this exact command: ${command}. Do not use another tool, alter the command, explain, or retry. After the tool result, stop."

  set +e
  (
    cd "$work_dir"
    HOME="$isolated_home" \
    PATH="$isolated_path" \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1 \
    CLAUDE_CODE_SKIP_PROMPT_HISTORY=1 \
    "$claude_bin" -p "$prompt" \
      --no-session-persistence \
      --setting-sources user \
      --settings "$settings_path" \
      --strict-mcp-config \
      --mcp-config '{"mcpServers":{}}' \
      --tools Bash \
      --disable-slash-commands \
      --no-chrome \
      --dangerously-skip-permissions \
      --effort low \
      --max-budget-usd 0.20 \
      --output-format stream-json \
      --include-hook-events \
      --verbose \
      --debug-file "$debug_path"
  ) >"$log_path" 2>&1
  local status=$?
  set -e
  return "$status"
}

deny_status=0
allow_status=0
run_claude "printf rampart-host-canary > ${deny_target}" "${tmp}/deny.log" "${tmp}/deny-debug.log" || deny_status=$?
run_claude "printf rampart-host-allowed > ${allow_target}" "${tmp}/allow.log" "${tmp}/allow-debug.log" || allow_status=$?

report_dir="${tmp}/report"
if [[ -n "$artifacts_dir" ]]; then
  mkdir -p "$artifacts_dir"
  chmod 700 "$artifacts_dir"
  report_dir="$(cd "$artifacts_dir" && pwd)"
else
  mkdir -p "$report_dir"
fi

python3 - \
  "$tmp" "$audit_dir" "$report_dir" "$claude_version" "$rampart_version" \
  "$deny_status" "$allow_status" "$deny_target" "$allow_target" "$HOME" \
  "$credentials_file" <<'PY'
import json
from pathlib import Path
import sys

tmp = Path(sys.argv[1])
audit_dir = Path(sys.argv[2])
report_dir = Path(sys.argv[3])
claude_version = sys.argv[4]
rampart_version = sys.argv[5]
deny_status = int(sys.argv[6])
allow_status = int(sys.argv[7])
deny_target = Path(sys.argv[8])
allow_target = Path(sys.argv[9])
source_home = sys.argv[10]
credentials_file = sys.argv[11]

events = []
for audit_path in sorted(audit_dir.glob("audit-hook-*.jsonl")):
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
    if event.get("agent") == "claude-code"
    and event.get("tool") == "exec"
    and "rampart-host-canary" in command(event)
    and action(event) == "deny"
]
allowed = [
    event for event in events
    if event.get("agent") == "claude-code"
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

checks = {
    "isolated_hooks_installed": (tmp / "home" / ".claude" / "settings.json").is_file(),
    "deny_pretooluse_blocked": len(denied) == 1,
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
    "allow_pre_post_identity_correlated": any(
        count >= 2 for count in allow_identity_counts.values()
    ),
}

def sanitize(value):
    value = value.replace(str(tmp), "<isolated-root>")
    if source_home:
        value = value.replace(source_home, "<user-home>")
    if credentials_file:
        value = value.replace(credentials_file, "<credential-file>")
    return value

report_dir.mkdir(parents=True, exist_ok=True)
for name in ("setup.log", "deny.log", "allow.log", "deny-debug.log", "allow-debug.log"):
    source = tmp / name
    if source.is_file():
        (report_dir / name).write_text(
            sanitize(source.read_text(encoding="utf-8", errors="replace")),
            encoding="utf-8",
        )
(report_dir / "audit.jsonl").write_text(
    "".join(sanitize(json.dumps(event, sort_keys=True)) + "\n" for event in events),
    encoding="utf-8",
)
for path in report_dir.iterdir():
    if path.is_file():
        path.chmod(0o600)

summary = {
    "schema_version": "rampart.claude-host-e2e.v1",
    "result": "pass" if all(checks.values()) else "fail",
    "claude_version": claude_version,
    "rampart_version": rampart_version,
    "model_invocations": 2,
    "source_claude_state_loaded": (
        [".credentials.json"] if credentials_file else ["os_keychain_only"]
    ),
    "session_persistence": False,
    "user_project_config_loaded": False,
    "mcp_servers_loaded": False,
    "tools_enabled": ["Bash"],
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
