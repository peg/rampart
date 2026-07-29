#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: openclaw-container-acceptance.sh --rampart PATH --artifact-dir PATH [options]

Run the Rampart zero-configuration OpenClaw acceptance test in a disposable
official OpenClaw container. No host OpenClaw state, service, session, workspace,
memory, or credentials are mounted into the container.

Options:
  --rampart PATH       Native Linux Rampart candidate binary (required)
  --artifact-dir PATH  Directory for logs and JSON evidence (required)
  --image IMAGE        OpenClaw image (default: ghcr.io/openclaw/openclaw:latest)
  --help               Show this help
EOF
}

rampart_bin=""
artifact_dir=""
image="${RAMPART_OPENCLAW_IMAGE:-ghcr.io/openclaw/openclaw:latest}"
official_latest_image="ghcr.io/openclaw/openclaw:latest"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rampart)
      [[ $# -ge 2 ]] || { echo "openclaw-acceptance: --rampart requires a value" >&2; exit 2; }
      rampart_bin="$2"
      shift 2
      ;;
    --artifact-dir)
      [[ $# -ge 2 ]] || { echo "openclaw-acceptance: --artifact-dir requires a value" >&2; exit 2; }
      artifact_dir="$2"
      shift 2
      ;;
    --image)
      [[ $# -ge 2 ]] || { echo "openclaw-acceptance: --image requires a value" >&2; exit 2; }
      image="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "openclaw-acceptance: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ -n "$rampart_bin" ]] || { echo "openclaw-acceptance: --rampart is required" >&2; exit 2; }
[[ -x "$rampart_bin" ]] || { echo "openclaw-acceptance: candidate is not executable: $rampart_bin" >&2; exit 2; }
[[ -n "$artifact_dir" ]] || { echo "openclaw-acceptance: --artifact-dir is required" >&2; exit 2; }
command -v docker >/dev/null 2>&1 || { echo "openclaw-acceptance: docker is required" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "openclaw-acceptance: python3 is required" >&2; exit 2; }

mkdir -p "$artifact_dir"
artifact_dir="$(cd "$artifact_dir" && pwd)"
rampart_bin="$(cd "$(dirname "$rampart_bin")" && pwd)/$(basename "$rampart_bin")"
container="rampart-openclaw-accept-$PPID-$$"

cleanup() {
  local code=$?
  trap - EXIT
  if docker inspect "$container" >/dev/null 2>&1; then
    docker logs "$container" >"${artifact_dir}/container.log" 2>&1 || true
    docker rm -f "$container" >/dev/null 2>&1 || code=1
  fi
  exit "$code"
}
trap cleanup EXIT

requested_image="$image"
if [[ "$requested_image" == "$official_latest_image" ]]; then
  # A locally cached :latest is not evidence of current compatibility. Pull it
  # for every rolling-latest run, then execute the immutable digest we resolved.
  docker pull "$requested_image" | tee "${artifact_dir}/image-pull.log"
  image="$(docker image inspect \
    --format '{{range .RepoDigests}}{{println .}}{{end}}' \
    "$requested_image" | awk '/^ghcr\.io\/openclaw\/openclaw@sha256:/ { print; exit }')"
  if [[ -z "$image" ]]; then
    echo "openclaw-acceptance: official latest image did not resolve to a repository digest" >&2
    exit 1
  fi
elif ! docker image inspect "$requested_image" >/dev/null 2>&1; then
  docker pull "$requested_image" | tee "${artifact_dir}/image-pull.log"
fi
printf 'requested=%s\nresolved=%s\n' "$requested_image" "$image" \
  | tee "${artifact_dir}/image-reference.txt"
docker image inspect "$image" >"${artifact_dir}/image.json"

docker run -d \
  --name "$container" \
  --user node \
  -e HOME=/tmp/rampart-home \
  -e OPENCLAW_STATE_DIR=/tmp/openclaw-state \
  -v "${rampart_bin}:/usr/local/bin/rampart:ro" \
  --entrypoint sh \
  "$image" \
  -lc 'mkdir -p /tmp/rampart-home /tmp/openclaw-state /tmp/openclaw-workspace && sleep infinity' \
  >"${artifact_dir}/container-id.txt"

docker exec "$container" openclaw --version | tee "${artifact_dir}/openclaw-version.log"
docker exec "$container" openclaw config set gateway.mode local
docker exec "$container" openclaw config set gateway.bind loopback
docker exec "$container" openclaw config set gateway.port 19001
docker exec "$container" openclaw config set gateway.auth.mode token
docker exec "$container" openclaw config set gateway.auth.token rampart-container-fixture-token
docker exec "$container" openclaw config set agents.defaults.workspace '"/tmp/openclaw-workspace"' --strict-json

docker exec "$container" sh -lc 'env -u RAMPART_TOKEN rampart protect openclaw --no-restart --no-verify' \
  2>&1 | tee "${artifact_dir}/protect-first.log"

docker exec -d "$container" sh -lc 'openclaw gateway --port 19001 >/tmp/openclaw-gateway.log 2>&1'
healthy=0
for _ in $(seq 1 90); do
  if docker exec "$container" node -e 'fetch("http://127.0.0.1:19001/healthz").then((r)=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))' \
    >/dev/null 2>&1; then
    healthy=1
    break
  fi
  sleep 0.5
done
if [[ "$healthy" -ne 1 ]]; then
  docker exec "$container" sh -lc 'tail -100 /tmp/openclaw-gateway.log' | tee "${artifact_dir}/openclaw-gateway.log"
  echo "openclaw-acceptance: gateway did not become healthy" >&2
  exit 1
fi

docker exec "$container" rampart verify openclaw --json | tee "${artifact_dir}/verify.json"
python3 - "${artifact_dir}/verify.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
summary = report.get("summary", {})
if summary != {"checks": 12, "passed": 12, "failed": 0, "unverified": 0}:
    raise SystemExit(f"unexpected verification summary: {summary!r}")
if not report.get("safe_canaries"):
    raise SystemExit("verification did not assert safe canaries")
PY

# A second protect run proves managed policy replacement, plugin integrity
# detection, service discovery, and verification are idempotent.
docker exec "$container" rampart protect openclaw --no-restart \
  2>&1 | tee "${artifact_dir}/protect-idempotent.log"

docker exec "$container" openclaw config get plugins.entries.rampart \
  >"${artifact_dir}/openclaw-rampart-config.json"
docker exec "$container" sh -lc \
  'sha256sum /tmp/openclaw-state/extensions/rampart/index.js /tmp/rampart-home/.rampart/policies/guard.yaml /tmp/rampart-home/.rampart/policies/openclaw.yaml' \
  >"${artifact_dir}/installed-checksums.txt"
docker exec "$container" sh -lc 'cat /tmp/openclaw-gateway.log' >"${artifact_dir}/openclaw-gateway.log"

echo "openclaw-acceptance: PASS artifacts=${artifact_dir}"
