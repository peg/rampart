#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
runner="${repo_root}/scripts/lab/run-e2e.sh"
artifact_scanner="${repo_root}/scripts/lab/scan-artifacts.py"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

bash -n "$runner"
PYTHONPYCACHEPREFIX="${tmp}/pycache" python3 -m py_compile "$artifact_scanner"
bash -n "${repo_root}/scripts/lab/openclaw-container-acceptance.sh"
bash -n "${repo_root}/scripts/test-approval-flow.sh"
bash -n "${repo_root}/preload/test_preload.sh"
bash -n "${repo_root}/scripts/compat-codex-host.sh"
bash -n "${repo_root}/scripts/compat-claude-host.sh"
bash -n "${repo_root}/scripts/compat-hermes-host.sh"
grep -q 'default_action: deny' "${repo_root}/scripts/compat-claude-host.sh"
grep -q 'CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1' "${repo_root}/scripts/compat-claude-host.sh"
grep -q -- '--allowedTools "Bash(${command})"' "${repo_root}/scripts/compat-claude-host.sh"
grep -q 'keychain_unavailable_in_disposable_home' "${repo_root}/scripts/compat-claude-host.sh"
grep -q 'default_action: deny' "${repo_root}/scripts/compat-hermes-host.sh"
grep -q -- '--copy-env' "${repo_root}/scripts/compat-hermes-host.sh"
grep -q -- '--gateway' "${repo_root}/scripts/compat-hermes-host.sh"
grep -q 'API_SERVER_ENABLED=true' "${repo_root}/scripts/compat-hermes-host.sh"
grep -q '^umask 077$' "$runner"
grep -q 'scan-artifacts.py' "$runner"

mkdir -p "${tmp}/scan-clean" "${tmp}/scan-secret"
printf '%s\n' '{"status":"passed","token":"[REDACTED]"}' >"${tmp}/scan-clean/summary.json"
python3 "$artifact_scanner" --root "${tmp}/scan-clean" >"${tmp}/clean-scan.json"
grep -q '"status": "passed"' "${tmp}/clean-scan.json"
printf '%s%s\n' 'sk-proj-' 'abcdefghijklmnopqrstuvwxyz1234567890' >"${tmp}/scan-secret/provider.log"
if python3 "$artifact_scanner" --root "${tmp}/scan-secret" >"${tmp}/secret-scan.json"; then
  echo "test-run-e2e: credential scanner accepted a key-shaped value" >&2
  exit 1
fi
grep -q '"status": "failed"' "${tmp}/secret-scan.json"
grep -q '"kind": "openai_or_anthropic_key"' "${tmp}/secret-scan.json"
if grep -q 'abcdefghijklmnopqrstuvwxyz1234567890' "${tmp}/secret-scan.json"; then
  echo "test-run-e2e: credential scanner disclosed a matched value" >&2
  exit 1
fi
printf '\0%s%s\0' 'sk-proj-' 'abcdefghijklmnopqrstuvwxyz1234567890' >"${tmp}/scan-secret/provider.bin"
if python3 "$artifact_scanner" --root "${tmp}/scan-secret" >"${tmp}/binary-secret-scan.json"; then
  echo "test-run-e2e: credential scanner accepted a binary containing a key-shaped value" >&2
  exit 1
fi
grep -q '"path": "provider.bin"' "${tmp}/binary-secret-scan.json"

native_root="${tmp}/native-openclaw"
mkdir -p "${native_root}/home/.openclaw" "${native_root}/home/.codex"
chmod 700 "$native_root"
native_env=(
  env -i
  PATH="$PATH"
  HOME="${native_root}/home"
  CODEX_HOME="${native_root}/home/.codex"
  OPENCLAW_STATE_DIR="${native_root}/home/.openclaw"
  OPENCLAW_CONFIG_PATH="${native_root}/home/.openclaw/openclaw.json"
  RAMPART_OPENCLAW_ISOLATION_ROOT="$native_root"
  RAMPART_OPENCLAW_RUNTIME=1
  RAMPART_OPENCLAW_RESTART_SERVICES=
)
if "${native_env[@]}" node "${repo_root}/scripts/test-openclaw-codex-native-audit.mjs" \
  >"${tmp}/native-no-attestation.out" 2>"${tmp}/native-no-attestation.err"; then
  echo "test-run-e2e: native audit accepted missing credential attestation" >&2
  exit 1
fi
grep -q 'without credential-isolation.json' "${tmp}/native-no-attestation.err"
printf '%s\n' \
  '{"schema_version":1,"purpose":"rampart-openclaw-codex-e2e","credential_source":"dedicated-test-login","production_credentials_copied":false}' \
  >"${native_root}/credential-isolation.json"
chmod 600 "${native_root}/credential-isolation.json"
if "${native_env[@]}" RAMPART_KEEP_RUNTIME_ARTIFACTS=1 node \
  "${repo_root}/scripts/test-openclaw-codex-native-audit.mjs" \
  >"${tmp}/native-retention.out" 2>"${tmp}/native-retention.err"; then
  echo "test-run-e2e: native audit accepted raw credentialed artifacts" >&2
  exit 1
fi
grep -q 'raw runtime artifact retention is disabled' "${tmp}/native-retention.err"

isolated_path_line="$(grep -n '^isolated_path=' "$runner" | cut -d: -f1)"
tool_check_line="$(grep -n '^for tool in git go python3' "$runner" | cut -d: -f1)"
if [[ -z "$isolated_path_line" || -z "$tool_check_line" || "$isolated_path_line" -ge "$tool_check_line" ]]; then
  echo "test-run-e2e: isolated_path must be defined before tool discovery" >&2
  exit 1
fi

"$runner" --help >"${tmp}/help"
grep -q -- '--sha' "${tmp}/help"
grep -q -- '--hermes-python' "${tmp}/help"

python3 - "${repo_root}/scripts/compat-hermes-latest.py" "$tmp" <<'PY'
import importlib.util
import os
from pathlib import Path
import sys

script = Path(sys.argv[1])
tmp = Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("compat_hermes_latest_test", script)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
link = tmp / "venv-python"
link.symlink_to(sys.executable)
assert module.resolve_executable(str(link)) == link.absolute()
readonly_tree = tmp / "readonly-tree"
readonly_tree.mkdir()
readonly_file = readonly_tree / "module.txt"
readonly_file.write_text("module", encoding="utf-8")
readonly_file.chmod(0o444)
readonly_tree.chmod(0o555)
module.remove_temp_tree(readonly_tree)
assert not readonly_tree.exists()
PY

if "$runner" --sha main --no-fetch >"${tmp}/invalid.out" 2>"${tmp}/invalid.err"; then
  echo "test-run-e2e: invalid SHA unexpectedly succeeded" >&2
  exit 1
fi
grep -q 'exact 40-character hexadecimal commit SHA' "${tmp}/invalid.err"

grep -q 'openclaw-container-acceptance.sh' "$runner"
grep -q 'CGO_ENABLED=0 GOOS=linux GOARCH=' "$runner"
grep -q 'run_step go-test isolated env RAMPART_OPENCLAW_BIN=' "$runner"
if grep -Eq '\$\{controller_repo\}/(preload/test_preload\.sh|scripts/test-approval-flow\.sh|scripts/compat-hermes-latest\.py)' "$runner"; then
  echo "test-run-e2e: candidate harnesses must run from the detached worktree" >&2
  exit 1
fi
grep -q '"controller_commit_sha"' "$runner"
grep -q '"controller_dirty"' "$runner"
grep -q 'env -i PATH="$environment_probe_path"' "$runner"
"${repo_root}/scripts/lab/openclaw-container-acceptance.sh" --help >"${tmp}/openclaw-help"
grep -q -- '--rampart' "${tmp}/openclaw-help"
grep -q -- '--openclaw-version' "${tmp}/openclaw-help"
grep -q 'npm view' "${repo_root}/scripts/lab/openclaw-container-acceptance.sh"
grep -q 'npm install --global' "${repo_root}/scripts/lab/openclaw-container-acceptance.sh"

"${repo_root}/scripts/lab/test-compat-codex-host.sh"

echo "test-run-e2e: PASS"
