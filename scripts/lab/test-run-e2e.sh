#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
runner="${repo_root}/scripts/lab/run-e2e.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

bash -n "$runner"
bash -n "${repo_root}/scripts/test-approval-flow.sh"
bash -n "${repo_root}/preload/test_preload.sh"

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
PY

if "$runner" --sha main --no-fetch >"${tmp}/invalid.out" 2>"${tmp}/invalid.err"; then
  echo "test-run-e2e: invalid SHA unexpectedly succeeded" >&2
  exit 1
fi
grep -q 'exact 40-character hexadecimal commit SHA' "${tmp}/invalid.err"

sha="$(git -C "$repo_root" rev-parse HEAD)"
if "$runner" --sha "$sha" --suite openclaw --no-fetch >"${tmp}/unsafe.out" 2>"${tmp}/unsafe.err"; then
  echo "test-run-e2e: primary-state OpenClaw suite unexpectedly ran" >&2
  exit 1
fi
grep -q 'disabled until OpenClaw runs with isolated state' "${tmp}/unsafe.err"

echo "test-run-e2e: PASS"
