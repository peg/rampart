#!/usr/bin/env bash
# Copyright 2026 The Rampart Authors
# Licensed under the Apache License, Version 2.0

set -euo pipefail

image="${1:?usage: docker-smoke.sh IMAGE EXPECTED_VERSION}"
expected_version="${2:?usage: docker-smoke.sh IMAGE EXPECTED_VERSION}"
port="${RAMPART_DOCKER_SMOKE_PORT:-19090}"
token="rampart-docker-smoke-token"
work_dir="$(mktemp -d)"
audit_volume="rampart-smoke-audit-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-${RANDOM}"
container_id=""

cleanup() {
  if [[ -n "$container_id" ]]; then
    docker rm -f "$container_id" >/dev/null 2>&1 || true
  fi
  docker volume rm -f "$audit_volume" >/dev/null 2>&1 || true
  rm -rf "$work_dir"
}
trap cleanup EXIT

mkdir -p "$work_dir/policies"
cat >"$work_dir/policies/docker-smoke.yaml" <<'YAML'
version: "1"
default_action: allow
policies:
  - name: docker-smoke-mounted-policy
    description: Proves the container loads policy files from its documented HOME.
    priority: 1
    match:
      agent: docker-smoke
      tool: exec
    rules:
      - action: deny
        when:
          command_matches:
            - "echo docker-smoke-policy"
        message: "mounted Docker smoke policy"
YAML

docker run --rm "$image" version | tee "$work_dir/version.txt"
grep -F "rampart ${expected_version}" "$work_dir/version.txt"

docker volume create "$audit_volume" >/dev/null
container_id="$(docker run -d \
  -p "127.0.0.1:${port}:9090" \
  -e "RAMPART_TOKEN=${token}" \
  -v "$work_dir/policies:/home/nonroot/.rampart/policies:ro" \
  -v "$audit_volume:/home/nonroot/.rampart/audit" \
  "$image")"

healthy=0
for _ in $(seq 1 20); do
  if curl -fsS "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1; then
    healthy=1
    break
  fi
  sleep 1
done
if [[ "$healthy" -ne 1 ]]; then
  docker logs "$container_id"
  exit 1
fi

response="$(curl -fsS "http://127.0.0.1:${port}/v1/preflight/exec" \
  -H "Authorization: Bearer ${token}" \
  -H "Content-Type: application/json" \
  -d '{"agent":"docker-smoke","session":"ci","params":{"command":"echo docker-smoke-policy"}}')"
grep -F '"decision":"deny"' <<<"$response"
grep -F 'docker-smoke-mounted-policy' <<<"$response"

audit_output="$(docker run --rm \
  -v "$audit_volume:/home/nonroot/.rampart/audit:ro" \
  "$image" audit tail \
  --audit-dir /home/nonroot/.rampart/audit \
  --lines 10 \
  --no-color)"
grep -F 'echo docker-smoke-policy' <<<"$audit_output"

echo "Docker smoke passed: mounted policy loaded and audit event persisted."
