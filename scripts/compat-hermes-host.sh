#!/usr/bin/env bash
# Copyright 2026 The Rampart Authors
# Licensed under the Apache License, Version 2.0

# Opt-in behavioral proof through a real Hermes model/tool loop. Only provider
# credentials and the model/provider/toolset selection are copied from the
# source Hermes home. Memories, sessions, rules, skills, gateways, MCP servers,
# workspaces, and the source plugin installation are not loaded.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
hermes_bin="${RAMPART_HERMES_BIN:-hermes}"
rampart_bin="${RAMPART_BIN:-}"
source_hermes_home="${RAMPART_HERMES_SOURCE_HOME:-${HERMES_HOME:-${HOME}/.hermes}}"
artifacts_dir=""
confirmed=false
copy_env=false
tmp=""
serve_pid=""

usage() {
  cat <<'EOF'
Usage: scripts/compat-hermes-host.sh [options]

Run harmless deny/allow canaries through an actual Hermes model/tool loop and
Rampart's native plugin. This is an opt-in host test, not normal CI.

Options:
  --rampart-bin PATH  Candidate Rampart binary (default: build this checkout)
  --hermes-bin PATH   Hermes executable (default: hermes)
  --hermes-home DIR   Source used only for config selection and credentials
  --copy-env          Also copy source .env (for env-only providers)
  --artifacts DIR     Retain sanitized logs and summary in DIR
  --yes               Confirm the two live model invocations
  -h, --help          Show this help

Without --artifacts, the JSON summary is printed and all temporary files are
removed. Set RAMPART_HERMES_HOST_E2E=1 instead of --yes in automation.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rampart-bin)
      [[ $# -ge 2 ]] || { echo "compat-hermes-host: --rampart-bin requires a value" >&2; exit 2; }
      rampart_bin="$2"
      shift 2
      ;;
    --hermes-bin)
      [[ $# -ge 2 ]] || { echo "compat-hermes-host: --hermes-bin requires a value" >&2; exit 2; }
      hermes_bin="$2"
      shift 2
      ;;
    --hermes-home)
      [[ $# -ge 2 ]] || { echo "compat-hermes-host: --hermes-home requires a value" >&2; exit 2; }
      source_hermes_home="$2"
      shift 2
      ;;
    --artifacts)
      [[ $# -ge 2 ]] || { echo "compat-hermes-host: --artifacts requires a value" >&2; exit 2; }
      artifacts_dir="$2"
      shift 2
      ;;
    --copy-env)
      copy_env=true
      shift
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
      echo "compat-hermes-host: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "${RAMPART_HERMES_HOST_E2E:-}" == "1" ]]; then
  confirmed=true
fi
if [[ "$confirmed" != true ]]; then
  echo "compat-hermes-host: this invokes the configured Hermes model twice." >&2
  echo "Rerun with --yes or RAMPART_HERMES_HOST_E2E=1 after reviewing the script." >&2
  exit 2
fi

for tool in python3 curl; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "compat-hermes-host: required tool not found: $tool" >&2
    exit 2
  }
done
if [[ -z "$rampart_bin" ]] && ! command -v go >/dev/null 2>&1; then
  echo "compat-hermes-host: Go is required when --rampart-bin is omitted" >&2
  exit 2
fi
if ! command -v "$hermes_bin" >/dev/null 2>&1 && [[ ! -x "$hermes_bin" ]]; then
  echo "compat-hermes-host: Hermes executable not found: $hermes_bin" >&2
  exit 2
fi
if [[ ! -f "${source_hermes_home}/config.yaml" ]]; then
  echo "compat-hermes-host: source Hermes config not found: ${source_hermes_home}/config.yaml" >&2
  exit 2
fi
if [[ ! -f "${source_hermes_home}/auth.json" && "$copy_env" != true ]]; then
  echo "compat-hermes-host: auth.json not found; pass --copy-env for an env-only provider" >&2
  exit 2
fi
if [[ "$copy_env" == true && ! -f "${source_hermes_home}/.env" ]]; then
  echo "compat-hermes-host: --copy-env requested but ${source_hermes_home}/.env does not exist" >&2
  exit 2
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/rampart-hermes-host.XXXXXX")"
chmod 700 "$tmp"
cleanup() {
  if [[ -n "$serve_pid" ]]; then
    kill "$serve_pid" >/dev/null 2>&1 || true
    wait "$serve_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$tmp" && -d "$tmp" ]]; then
    rm -f "${tmp}/hermes/auth.json" "${tmp}/hermes/.env"
    rm -rf "$tmp"
  fi
}
trap cleanup EXIT INT TERM

isolated_home="${tmp}/home"
isolated_hermes_home="${tmp}/hermes"
work_dir="${tmp}/work"
audit_dir="${isolated_home}/.rampart/audit"
plugin_dir="${isolated_hermes_home}/plugins/rampart"
mkdir -p "$isolated_home" "$isolated_hermes_home" "$work_dir" "$audit_dir"
chmod 700 "$isolated_home" "$isolated_hermes_home" "$work_dir" "$audit_dir"
if [[ -f "${source_hermes_home}/auth.json" ]]; then
  install -m 600 "${source_hermes_home}/auth.json" "${isolated_hermes_home}/auth.json"
fi
if [[ "$copy_env" == true ]]; then
  install -m 600 "${source_hermes_home}/.env" "${isolated_hermes_home}/.env"
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
  echo "compat-hermes-host: Rampart executable not found: $rampart_bin" >&2
  exit 2
fi
rampart_bin="$(cd "$(dirname "$rampart_bin")" && pwd)/$(basename "$rampart_bin")"

port="$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"
serve_url="http://127.0.0.1:${port}"
token="rampart-hermes-host-${port}"

deny_target="${work_dir}/deny-executed"
allow_target="${work_dir}/allow-executed"
cat >"${work_dir}/rampart.yaml" <<EOF
version: "1"
default_action: deny
policies:
  - name: hermes-host-deny-canary
    match:
      agent: hermes
      tool: exec
    rules:
      - action: deny
        when:
          command_matches:
            - "printf rampart-host-canary > ${deny_target}"
        message: Rampart Hermes host-boundary canary
      - action: allow
        when:
          command_matches:
            - "printf rampart-host-allowed > ${allow_target}"
        message: Rampart Hermes allowed host-boundary canary
EOF
chmod 600 "${work_dir}/rampart.yaml"

# Copy only non-secret model selection into a minimal config. PyYAML is already
# a Hermes dependency; fail before model invocation if it is unavailable.
python3 - \
  "${source_hermes_home}/config.yaml" "${isolated_hermes_home}/config.yaml" \
  "$serve_url" "$work_dir" <<'PY'
from pathlib import Path
import sys
try:
    import yaml
except ImportError as exc:
    raise SystemExit("compat-hermes-host: PyYAML is required") from exc

source = yaml.safe_load(Path(sys.argv[1]).read_text(encoding="utf-8")) or {}
model = source.get("model") if isinstance(source.get("model"), dict) else {}
default_model = model.get("default")
provider = model.get("provider")
if not isinstance(default_model, str) or not default_model:
    raise SystemExit("compat-hermes-host: source config has no model.default")
if not isinstance(provider, str) or not provider:
    raise SystemExit("compat-hermes-host: source config has no model.provider")
toolsets = source.get("toolsets")
if not isinstance(toolsets, list) or not toolsets:
    toolsets = ["hermes-cli"]

minimal = {
    "model": {"default": default_model, "provider": provider},
    "toolsets": toolsets,
    "agent": {"max_turns": 5},
    "terminal": {
        "backend": "local",
        "cwd": sys.argv[4],
        "home_mode": "auto",
        "env_passthrough": [],
        "shell_init_files": [],
        "auto_source_bashrc": False,
    },
    "memory": {"memory_enabled": False, "user_profile_enabled": False},
    "display": {"persist_prompts": False},
    "sessions": {"write_json_snapshots": False},
    "plugins": {
        "enabled": ["rampart"],
        "disabled": [],
        "entries": {
            "rampart": {
                "config": {
                    "serve_url": sys.argv[3],
                    "endpoint_mode": "preflight",
                    "timeout_ms": 2000,
                    "fail_open_tools": ["read_file", "search_files"],
                }
            }
        },
    },
    "mcp_servers": {},
}
Path(sys.argv[2]).write_text(yaml.safe_dump(minimal, sort_keys=False), encoding="utf-8")
Path(sys.argv[2]).chmod(0o600)
PY

HOME="$isolated_home" \
HERMES_HOME="$isolated_hermes_home" \
"$rampart_bin" setup hermes --plugin-dir "$plugin_dir" >"${tmp}/setup.log" 2>&1

HOME="$isolated_home" \
RAMPART_TOKEN="$token" \
"$rampart_bin" --config "${work_dir}/rampart.yaml" serve \
  --addr 127.0.0.1 \
  --port "$port" \
  --audit-dir "$audit_dir" \
  --no-openclaw-bridge >"${tmp}/serve.log" 2>&1 &
serve_pid=$!

healthy=false
for _ in $(seq 1 100); do
  if curl -fsS "${serve_url}/healthz" >/dev/null 2>&1; then
    healthy=true
    break
  fi
  if ! kill -0 "$serve_pid" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
if [[ "$healthy" != true ]]; then
  echo "compat-hermes-host: disposable Rampart service did not become healthy" >&2
  exit 1
fi

hermes_version="$("$hermes_bin" --version 2>&1 | head -n 1)"
rampart_version="$("$rampart_bin" version 2>&1 | head -n 1)"

run_hermes() {
  local command="$1"
  local log_path="$2"
  local prompt
  prompt="Use the terminal tool exactly once to run this exact command: ${command}. Do not use another tool, alter the command, explain, or retry. After the tool result, stop."

  set +e
  (
    cd "$work_dir"
    HOME="$isolated_home" \
    HERMES_HOME="$isolated_hermes_home" \
    RAMPART_TOKEN="$token" \
    RAMPART_HERMES_TOKEN_PATH="${isolated_home}/.rampart/token" \
    RAMPART_HERMES_URL="$serve_url" \
    "$hermes_bin" \
      --oneshot "$prompt" \
      --ignore-rules \
      --toolsets hermes-cli \
      --accept-hooks
  ) >"$log_path" 2>&1
  local status=$?
  set -e
  return "$status"
}

deny_status=0
allow_status=0
run_hermes "printf rampart-host-canary > ${deny_target}" "${tmp}/deny.log" || deny_status=$?
run_hermes "printf rampart-host-allowed > ${allow_target}" "${tmp}/allow.log" || allow_status=$?

# Stop the disposable service before collecting artifacts so its buffered audit
# sink is flushed to JSONL.
kill "$serve_pid" >/dev/null 2>&1 || true
wait "$serve_pid" >/dev/null 2>&1 || true
serve_pid=""

report_dir="${tmp}/report"
if [[ -n "$artifacts_dir" ]]; then
  mkdir -p "$artifacts_dir"
  chmod 700 "$artifacts_dir"
  report_dir="$(cd "$artifacts_dir" && pwd)"
else
  mkdir -p "$report_dir"
fi

python3 - \
  "$tmp" "$audit_dir" "$report_dir" "$hermes_version" "$rampart_version" \
  "$deny_status" "$allow_status" "$deny_target" "$allow_target" "$HOME" \
  "$source_hermes_home" "$token" <<'PY'
import json
from pathlib import Path
import sys

tmp = Path(sys.argv[1])
audit_dir = Path(sys.argv[2])
report_dir = Path(sys.argv[3])
hermes_version = sys.argv[4]
rampart_version = sys.argv[5]
deny_status = int(sys.argv[6])
allow_status = int(sys.argv[7])
deny_target = Path(sys.argv[8])
allow_target = Path(sys.argv[9])
source_home = sys.argv[10]
source_hermes_home = sys.argv[11]
token = sys.argv[12]

events = []
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
    if event.get("agent") == "hermes"
    and event.get("tool") == "exec"
    and "rampart-host-canary" in command(event)
    and action(event) == "deny"
]
allowed = [
    event for event in events
    if event.get("agent") == "hermes"
    and event.get("tool") == "exec"
    and "rampart-host-allowed" in command(event)
    and action(event) == "allow"
]

checks = {
    "isolated_plugin_installed": (tmp / "hermes" / "plugins" / "rampart" / "plugin.yaml").is_file(),
    "deny_pretoolcall_blocked": len(denied) == 1,
    "deny_command_not_executed": not deny_target.exists(),
    "allow_pretoolcall_audited": len(allowed) == 1,
    "allow_command_executed": (
        allow_target.is_file()
        and allow_target.read_text(encoding="utf-8") == "rampart-host-allowed"
    ),
    "tool_call_identity_recorded": (
        len(denied) == 1
        and len(allowed) == 1
        and all(event.get("tool_call_id") for event in denied + allowed)
    ),
}

def sanitize(value):
    for original, replacement in (
        (str(tmp), "<isolated-root>"),
        (source_hermes_home, "<source-hermes-home>"),
        (source_home, "<user-home>"),
        (token, "<rampart-token>"),
    ):
        if original:
            value = value.replace(original, replacement)
    return value

report_dir.mkdir(parents=True, exist_ok=True)
for name in ("setup.log", "serve.log", "deny.log", "allow.log"):
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

loaded = ["config.model", "config.provider", "config.toolsets"]
if (tmp / "hermes" / "auth.json").is_file():
    loaded.append("auth.json")
if (tmp / "hermes" / ".env").is_file():
    loaded.append(".env")
summary = {
    "schema_version": "rampart.hermes-host-e2e.v1",
    "result": "pass" if all(checks.values()) else "fail",
    "hermes_version": hermes_version,
    "rampart_version": rampart_version,
    "model_invocations": 2,
    "source_hermes_state_loaded": loaded,
    "source_memories_sessions_rules_loaded": False,
    "gateway_loaded": False,
    "mcp_servers_loaded": False,
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
