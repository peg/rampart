#!/bin/sh
# Copyright 2026 The Rampart Authors
# Licensed under the Apache License, Version 2.0

set -eu

canonical="docs/API-REFERENCE.md"
wrapper="docs-site/reference/api-reference.md"
include='--8<-- "docs/API-REFERENCE.md"'

if [ ! -s "$canonical" ]; then
  echo "missing canonical API reference: $canonical" >&2
  exit 1
fi

if [ "$(grep -Fxc -- "$include" "$wrapper" || true)" -ne 1 ]; then
  echo "$wrapper must include $canonical exactly once through pymdownx.snippets" >&2
  exit 1
fi

if [ "$(grep -c '^--8<-- ' "$wrapper" || true)" -ne 1 ]; then
  echo "$wrapper must contain exactly one generated-document include" >&2
  exit 1
fi

echo "API reference source and docs-site wrapper are linked."
