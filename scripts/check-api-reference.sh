#!/bin/sh
# Copyright 2026 The Rampart Authors
# Licensed under the Apache License, Version 2.0

set -eu

check_wrapper() {
  canonical="$1"
  wrapper="$2"
  include="--8<-- \"$canonical\""

  if [ ! -s "$canonical" ]; then
    echo "missing canonical document: $canonical" >&2
    exit 1
  fi
  if [ "$(grep -Fxc -- "$include" "$wrapper" || true)" -ne 1 ]; then
    echo "$wrapper must include $canonical exactly once through pymdownx.snippets" >&2
    exit 1
  fi
  if [ "$(grep -c '^--8<-- ' "$wrapper" || true)" -ne 1 ]; then
    echo "$wrapper must contain exactly one canonical-document include" >&2
    exit 1
  fi
}

check_wrapper "docs/API-REFERENCE.md" "docs-site/reference/api-reference.md"
check_wrapper "docs/ARCHITECTURE.md" "docs-site/reference/architecture.md"
check_wrapper "docs/THREAT-MODEL.md" "docs-site/reference/threat-model.md"

echo "Canonical repository documents and docs-site wrappers are linked."
