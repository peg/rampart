#!/bin/sh
set -eu

go_directive=$(sed -n 's/^go[[:space:]][[:space:]]*\([0-9][0-9.]*\)$/\1/p' go.mod)
toolchain_directive=$(sed -n 's/^toolchain[[:space:]][[:space:]]*go\([0-9][0-9.]*\)$/\1/p' go.mod)
toolchain_count=$(sed -n '/^toolchain[[:space:]]/p' go.mod | wc -l | tr -d ' ')
docker_version=$(sed -n 's/.*golang:\([0-9][0-9.]*\)-bookworm.*/\1/p' Dockerfile)

if [ -z "$go_directive" ]; then
  echo 'Could not read the Go toolchain version from go.mod.' >&2
  exit 1
fi

if [ "$toolchain_count" -gt 1 ] || { [ "$toolchain_count" -eq 1 ] && [ -z "$toolchain_directive" ]; }; then
  echo 'go.mod contains an unsupported or ambiguous toolchain directive.' >&2
  echo 'Rampart release builds must use one stable numeric Go toolchain.' >&2
  exit 1
fi

if [ -n "$toolchain_directive" ]; then
  effective_version=$toolchain_directive
else
  effective_version=$go_directive
fi

if [ -z "$docker_version" ]; then
  echo 'Could not read the Go toolchain version from Dockerfile.' >&2
  exit 1
fi

if [ "$effective_version" != "$docker_version" ]; then
  echo "Go toolchain mismatch: go.mod selects $effective_version but Dockerfile uses $docker_version." >&2
  echo 'Update the complete Rampart toolchain in one coordinated change.' >&2
  exit 1
fi

echo "Go toolchain pins agree on $effective_version."
