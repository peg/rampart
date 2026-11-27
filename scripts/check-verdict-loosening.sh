#!/usr/bin/env bash
# Copyright 2026 The Rampart Authors
# Licensed under the Apache License, Version 2.0
#
# Usage: scripts/check-verdict-loosening.sh BASE_REF
#
# Compares policies/testdata/verdicts.tsv at BASE_REF with the working tree and
# exits 1 when a recorded verdict gets weaker (deny > ask > watch) or a recorded
# row disappears. Tightened and new rows pass. Ranks match verdictRank in
# policies/verdicts_test.go.

set -euo pipefail

base_ref="${1:?usage: $0 BASE_REF}"
file=policies/testdata/verdicts.tsv
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if ! git cat-file -e "$base_ref:$file" 2>/dev/null; then
  echo "No $file at $base_ref; nothing to compare."
  exit 0
fi

base_rows="$(mktemp)"
trap 'rm -f "$base_rows"' EXIT
git show "$base_ref:$file" >"$base_rows"

awk -F'\t' '
  function rank(a) {
    if (a == "deny") return 3
    if (a == "ask" || a == "require_approval" || a == "webhook") return 2
    if (a == "watch") return 1
    return 0
  }
  /^#/ || NF == 0 { next }
  FNR == NR { base[$1 FS $3] = $2; next }
  { head[$1 FS $3] = $2 }
  END {
    n = 0
    for (key in base) {
      split(key, part, FS)
      if (!(key in head)) {
        printf "%s: %s was %s, now unrecorded\n", part[1], part[2], base[key]
        n++
      } else if (rank(head[key]) < rank(base[key])) {
        printf "%s: %s was %s, now %s\n", part[1], part[2], base[key], head[key]
        n++
      }
    }
    if (n > 0) {
      printf "%d recorded verdicts got weaker or were removed.\n", n
      exit 1
    }
    print "No recorded verdict got weaker."
  }
' "$base_rows" "$file"
