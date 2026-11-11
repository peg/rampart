#!/usr/bin/env bash
# Copyright 2026 The Rampart Authors
# Licensed under the Apache License, Version 2.0
#
# Fails unless the release tag on origin still resolves to the commit that
# was validated. Reads the remote, not local refs, so a tag moved after
# checkout is caught.

set -euo pipefail

tag="${1:?usage: check-release-tag.sh TAG EXPECTED_SHA}"
expected="${2:?usage: check-release-tag.sh TAG EXPECTED_SHA}"

refs="$(git ls-remote --tags origin "refs/tags/$tag" "refs/tags/$tag^{}")"
# An annotated tag lists its peeled commit as "<sha> refs/tags/TAG^{}".
actual="$(awk -v ref="refs/tags/$tag^{}" '$2 == ref { print $1 }' <<<"$refs")"
if [[ -z "$actual" ]]; then
  actual="$(awk -v ref="refs/tags/$tag" '$2 == ref { print $1 }' <<<"$refs")"
fi
if [[ "$actual" != "$expected" ]]; then
  echo "Tag $tag resolves to '${actual:-nothing}', not the validated $expected" >&2
  exit 1
fi
