#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/lab/run-e2e.sh --sha <40-hex-sha> [options]

Run Rampart validation from an isolated git worktree and retain structured
logs beneath the lab root.

Options:
  --sha SHA                 Exact commit to test (required; 40 hex characters)
  --suite NAME              core | runtime | e2e | hermes-runtime | hermes | openclaw-runtime | openclaw | full
  --root PATH               Lab state root (default: ~/.local/state/rampart-lab)
  --no-fetch                Use only commits already present in the controller clone
  --keep-worktree           Retain the detached worktree after the run
  --hermes-python PATH      Test an existing Hermes Python environment
  --hermes-bin PATH         Hermes executable paired with --hermes-python
  --help                    Show this help

The OpenClaw runtime suites run only in a disposable official OpenClaw container.
They never target a primary OpenClaw home or restart host user services.
EOF
}

sha=""
suite="e2e"
lab_root="${RAMPART_LAB_ROOT:-${HOME}/.local/state/rampart-lab}"
fetch=1
keep_worktree=0
hermes_python=""
hermes_bin=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sha)
      [[ $# -ge 2 ]] || { echo "run-e2e: --sha requires a value" >&2; exit 2; }
      sha="$2"
      shift 2
      ;;
    --suite)
      [[ $# -ge 2 ]] || { echo "run-e2e: --suite requires a value" >&2; exit 2; }
      suite="$2"
      shift 2
      ;;
    --root)
      [[ $# -ge 2 ]] || { echo "run-e2e: --root requires a value" >&2; exit 2; }
      lab_root="$2"
      shift 2
      ;;
    --no-fetch)
      fetch=0
      shift
      ;;
    --keep-worktree)
      keep_worktree=1
      shift
      ;;
    --hermes-python)
      [[ $# -ge 2 ]] || { echo "run-e2e: --hermes-python requires a value" >&2; exit 2; }
      hermes_python="$2"
      shift 2
      ;;
    --hermes-bin)
      [[ $# -ge 2 ]] || { echo "run-e2e: --hermes-bin requires a value" >&2; exit 2; }
      hermes_bin="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "run-e2e: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! "$sha" =~ ^[0-9a-fA-F]{40}$ ]]; then
  echo "run-e2e: --sha must be an exact 40-character hexadecimal commit SHA" >&2
  exit 2
fi
sha="$(printf '%s' "$sha" | tr '[:upper:]' '[:lower:]')"

case "$suite" in
  core|runtime|e2e|hermes-runtime|hermes|openclaw-runtime|openclaw|full) ;;
  *)
    echo "run-e2e: unsupported suite: $suite" >&2
    exit 2
    ;;
esac

if [[ -n "$hermes_bin" && -z "$hermes_python" ]]; then
  echo "run-e2e: --hermes-bin requires --hermes-python" >&2
  exit 2
fi

isolated_path="${RAMPART_LAB_PATH:-/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin}"
for tool in git go python3; do
  PATH="${isolated_path}:${PATH:-}" command -v "$tool" >/dev/null 2>&1 || {
    echo "run-e2e: required tool not found: $tool (checked controller PATH plus $isolated_path)" >&2
    exit 2
  }
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
controller_repo="$(git -C "$script_dir" rev-parse --show-toplevel)"
controller_sha="$(git -C "$controller_repo" rev-parse HEAD)"
controller_dirty=false
if [[ -n "$(git -C "$controller_repo" status --porcelain --untracked-files=normal)" ]]; then
  controller_dirty=true
fi
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_id="${timestamp}-${sha:0:12}-$$"
run_root="${lab_root}/runs/${run_id}"
artifact_dir="${run_root}/artifacts"
worktree="${run_root}/worktree"
isolated_home="${run_root}/home"
tmp_dir="${run_root}/tmp"
events_file="${artifact_dir}/events.jsonl"
summary_file="${artifact_dir}/summary.json"
worktree_added=0
preload_server_pid=0
failed=0
started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

mkdir -p "$artifact_dir" "$isolated_home" "$tmp_dir"

json_string() {
  python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"
}

record_event() {
  local step="$1"
  local status="$2"
  local exit_code="$3"
  local at
  at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '{"time":%s,"step":%s,"status":%s,"exit_code":%d}\n' \
    "$(json_string "$at")" "$(json_string "$step")" "$(json_string "$status")" "$exit_code" >>"$events_file"
}

write_summary() {
  local exit_code="$1"
  local status="passed"
  [[ "$exit_code" -eq 0 ]] || status="failed"
  cat >"$summary_file" <<EOF
{
  "schema_version": 1,
  "run_id": $(json_string "$run_id"),
  "commit_sha": $(json_string "$sha"),
  "controller_commit_sha": $(json_string "$controller_sha"),
  "controller_dirty": $controller_dirty,
  "suite": $(json_string "$suite"),
  "status": $(json_string "$status"),
  "exit_code": $exit_code,
  "started_at": $(json_string "$started_at"),
  "finished_at": $(json_string "$(date -u +%Y-%m-%dT%H:%M:%SZ)"),
  "worktree_retained": $([[ "$keep_worktree" -eq 1 ]] && echo true || echo false)
}
EOF
}

cleanup() {
  local exit_code=$?
  trap - EXIT
  if [[ "$failed" -ne 0 && "$exit_code" -eq 0 ]]; then
    exit_code=1
  fi
  if [[ "$preload_server_pid" -gt 0 ]] && kill -0 "$preload_server_pid" 2>/dev/null; then
    kill "$preload_server_pid" 2>/dev/null || true
    wait "$preload_server_pid" 2>/dev/null || true
  fi
  if [[ "$worktree_added" -eq 1 && "$keep_worktree" -ne 1 ]]; then
    git -C "$controller_repo" worktree remove --force "$worktree" >/dev/null 2>&1 || exit_code=1
  fi
  write_summary "$exit_code"
  if command -v sha256sum >/dev/null 2>&1; then
    find "$artifact_dir" -type f ! -name checksums.txt -print0 | sort -z | xargs -0 sha256sum >"${artifact_dir}/checksums.txt"
  elif command -v shasum >/dev/null 2>&1; then
    find "$artifact_dir" -type f ! -name checksums.txt -print0 | sort -z | xargs -0 shasum -a 256 >"${artifact_dir}/checksums.txt"
  fi
  echo "run-e2e: status=$([[ "$exit_code" -eq 0 ]] && echo passed || echo failed) run_id=$run_id"
  echo "run-e2e: artifacts=$artifact_dir"
  exit "$exit_code"
}
trap cleanup EXIT

run_step() {
  local name="$1"
  shift
  local log="${artifact_dir}/${name}.log"
  local code
  record_event "$name" "started" 0
  echo "[lab] step=$name"
  set +e
  "$@" > >(tee "$log") 2>&1
  code=$?
  set -e
  if [[ "$code" -eq 0 ]]; then
    record_event "$name" "passed" 0
  else
    record_event "$name" "failed" "$code"
    failed=1
  fi
  return 0
}

isolated() {
  env -i \
    HOME="$isolated_home" \
    XDG_CONFIG_HOME="$isolated_home/.config" \
    XDG_CACHE_HOME="$isolated_home/.cache" \
    XDG_STATE_HOME="$isolated_home/.local/state" \
    TMPDIR="$tmp_dir" \
    GOCACHE="$run_root/go-build" \
    GOMODCACHE="${RAMPART_LAB_GOMODCACHE:-$lab_root/go-mod}" \
    PATH="$isolated_path" \
    LANG="${LANG:-C.UTF-8}" \
    CI=1 \
    "$@"
}

if [[ "$fetch" -eq 1 ]]; then
  run_step fetch git -C "$controller_repo" fetch --prune origin '+refs/heads/*:refs/remotes/origin/*'
  if [[ "$failed" -ne 0 ]]; then
    exit 1
  fi
fi

git -C "$controller_repo" cat-file -e "${sha}^{commit}" 2>/dev/null || {
  echo "run-e2e: commit is not present after fetch: $sha" >&2
  exit 2
}

run_step worktree git -C "$controller_repo" worktree add --detach "$worktree" "$sha"
if [[ "$failed" -ne 0 ]]; then
  exit 1
fi
worktree_added=1

python3 - \
  "$worktree" \
  "$sha" \
  "$suite" \
  "$hermes_python" \
  "$hermes_bin" \
  "$controller_sha" \
  "$controller_dirty" \
  >"${artifact_dir}/environment.json" <<'PY'
import json, os, platform, shutil, subprocess, sys

def version(executable, *arguments):
    if os.path.sep in executable:
        path = os.path.abspath(executable) if os.path.exists(executable) else None
    else:
        path = shutil.which(executable)
    if not path:
        return None
    try:
        result = subprocess.run(
            [path, *arguments],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"path": path, "version": "", "version_error": type(error).__name__}
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return {
        "path": path,
        "version": lines[0] if lines else "",
        "version_exit_code": result.returncode,
    }

hermes_python = sys.argv[4]
hermes_bin = sys.argv[5] or "hermes"
tools = {
    "go": version("go", "version"),
    "node": version("node", "--version"),
    "openclaw": version("openclaw", "--version"),
    "hermes": version(hermes_bin, "--version"),
}
if hermes_python:
    tools["hermes_python"] = version(hermes_python, "--version")

print(json.dumps({
    "schema_version": 1,
    "commit_sha": sys.argv[2],
    "controller": {
        "commit_sha": sys.argv[6],
        "dirty": sys.argv[7] == "true",
    },
    "suite": sys.argv[3],
    "worktree": sys.argv[1],
    "platform": platform.platform(),
    "machine": platform.machine(),
    "python": sys.version.split()[0],
    "tools": tools,
}, indent=2, sort_keys=True))
PY

run_core() {
  run_step go-test isolated bash -c 'cd "$1" && go test ./...' _ "$worktree"
  run_step go-vet isolated bash -c 'cd "$1" && go vet ./...' _ "$worktree"
  run_step go-build isolated bash -c 'cd "$1" && go build -o "$2" ./cmd/rampart' _ "$worktree" "${artifact_dir}/rampart"
  run_step policy-standard isolated "${artifact_dir}/rampart" --config "${worktree}/policies/standard.yaml" policy check
  run_step hermes-plugin-unit isolated bash -c 'cd "$1" && python3 -m unittest internal/plugin/hermes/test_hermes_plugin.py' _ "$worktree"
  if command -v node >/dev/null 2>&1; then
    run_step openclaw-plugin-smoke isolated node "${worktree}/internal/plugin/openclaw/smoke-test.mjs"
    run_step openclaw-plugin-aliases isolated node "${worktree}/internal/plugin/openclaw/tool-alias-test.mjs"
    run_step openclaw-plugin-provider-surface isolated node "${worktree}/internal/plugin/openclaw/provider-surface-replay.mjs"
    run_step openclaw-plugin-degraded isolated node "${worktree}/internal/plugin/openclaw/degraded-mode-test.mjs"
  else
    record_event "openclaw-plugin-tests" "failed" 127
    failed=1
  fi
}

run_preload() {
  local port
  local preload_home
  port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
  preload_home="${run_root}/preload-home"
  mkdir -p "${artifact_dir}/audit"
  mkdir -p "${preload_home}/.ssh"
  printf '%s\n' 'rampart-lab-private-credential-canary' >"${preload_home}/.ssh/id_rsa"
  chmod 600 "${preload_home}/.ssh/id_rsa"
  HOME="$preload_home" \
    XDG_CONFIG_HOME="$preload_home/.config" \
    XDG_CACHE_HOME="$preload_home/.cache" \
    XDG_STATE_HOME="$preload_home/.local/state" \
    RAMPART_TOKEN="rampart-lab-token" \
    "${artifact_dir}/rampart" --config "${worktree}/policies/standard.yaml" \
    serve --no-openclaw-bridge --mode enforce --port "$port" \
    --audit-dir "${artifact_dir}/audit" >"${artifact_dir}/preload-server.log" 2>&1 &
  preload_server_pid=$!
  for _ in $(seq 1 100); do
    if curl -fsS "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1; then
      break
    fi
    if ! kill -0 "$preload_server_pid" 2>/dev/null; then
      wait "$preload_server_pid" || true
      preload_server_pid=0
      echo "preload: Rampart server exited before becoming healthy" >&2
      return 1
    fi
    sleep 0.1
  done
  if ! curl -fsS "http://127.0.0.1:${port}/healthz" >/dev/null; then
    kill "$preload_server_pid" 2>/dev/null || true
    wait "$preload_server_pid" 2>/dev/null || true
    preload_server_pid=0
    echo "preload: Rampart server did not become healthy" >&2
    return 1
  fi
  set +e
  RAMPART_ADDR="127.0.0.1:${port}" \
    RAMPART_URL="http://127.0.0.1:${port}" \
    RAMPART_TOKEN="rampart-lab-token" \
    HOME="$preload_home" \
    XDG_CONFIG_HOME="$preload_home/.config" \
    XDG_CACHE_HOME="$preload_home/.cache" \
    XDG_STATE_HOME="$preload_home/.local/state" \
    RAMPART_PRELOAD_SOURCE_DIR="${worktree}/preload" \
    RAMPART_BLOCK_CMD="cat ${preload_home}/.ssh/id_rsa" \
    bash "${worktree}/preload/test_preload.sh"
  local code=$?
  set -e
  kill "$preload_server_pid" 2>/dev/null || true
  wait "$preload_server_pid" 2>/dev/null || true
  preload_server_pid=0
  return "$code"
}

run_e2e() {
  local approval_port
  if [[ ! -x "${artifact_dir}/rampart" ]]; then
    run_step go-build-runtime isolated bash -c 'cd "$1" && go build -o "$2" ./cmd/rampart' \
      _ "$worktree" "${artifact_dir}/rampart"
  fi
  approval_port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
  run_step approval-flow isolated env PORT="$approval_port" bash -c 'cd "$1" && bash "$2"' \
    _ "$worktree" "${worktree}/scripts/test-approval-flow.sh"
  if [[ "$(uname -s)" == "Linux" ]]; then
    run_step preload-enforcement run_preload
  else
    record_event "preload-enforcement" "failed" 2
    echo "[lab] preload-enforcement requires Linux" | tee "${artifact_dir}/preload-enforcement.log"
    failed=1
  fi
}

run_hermes() {
  local args=()
  local step="hermes-latest"
  if [[ -n "$hermes_python" ]]; then
    args+=(--hermes-python "$hermes_python")
    step="hermes-installed"
    if [[ -n "$hermes_bin" ]]; then
      args+=(--hermes-bin "$hermes_bin")
    fi
  fi
  run_step "$step" isolated env RAMPART_COMPAT_REPO_ROOT="$worktree" \
    python3 "${worktree}/scripts/compat-hermes-latest.py" "${args[@]}"
}

run_openclaw() {
  local container_binary="${artifact_dir}/rampart-openclaw-linux"
  local docker_arch
  local docker_machine
  if ! docker_machine="$(docker info --format '{{.Architecture}}')"; then
    echo "run-e2e: could not determine Docker architecture for OpenClaw suite" >&2
    failed=1
    return
  fi
  case "$docker_machine" in
    aarch64|arm64) docker_arch="arm64" ;;
    x86_64|amd64) docker_arch="amd64" ;;
    *)
      echo "run-e2e: unsupported Docker architecture for OpenClaw suite: ${docker_machine}" >&2
      failed=1
      return
      ;;
  esac
  if [[ ! -x "$container_binary" ]]; then
    run_step go-build-openclaw isolated env CGO_ENABLED=0 GOOS=linux GOARCH="$docker_arch" \
      bash -c 'cd "$1" && go build -o "$2" ./cmd/rampart' \
      _ "$worktree" "$container_binary"
  fi
  run_step openclaw-container \
    "${worktree}/scripts/lab/openclaw-container-acceptance.sh" \
    --rampart "$container_binary" \
    --artifact-dir "${artifact_dir}/openclaw-container"
}

case "$suite" in
  core)
    run_core
    ;;
  runtime)
    run_e2e
    ;;
  e2e)
    run_core
    run_e2e
    ;;
  hermes-runtime)
    run_hermes
    ;;
  hermes)
    run_core
    run_hermes
    ;;
  openclaw-runtime)
    run_openclaw
    ;;
  openclaw)
    run_core
    run_openclaw
    ;;
  full)
    run_core
    run_e2e
    run_hermes
    run_openclaw
    ;;
esac

exit "$failed"
