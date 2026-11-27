#!/usr/bin/env bash
# Copyright 2026 The Rampart Authors
# Licensed under the Apache License, Version 2.0
#
# Usage: scripts/check-verdict-loosening.sh BASE_REF
#
# Compares policies/testdata/verdicts.tsv at BASE_REF with the working tree and
# exits 1 when a recorded verdict gets weaker (deny > ask > watch) or a recorded
# row disappears, unless policies/testdata/verdicts-loosened.tsv lists that
# exact change with a reason. Tightened and new rows pass. Ranks match
# verdictRank in policies/verdicts_test.go.

set -euo pipefail

base_ref="${1:?usage: $0 BASE_REF}"
file=policies/testdata/verdicts.tsv
ack=policies/testdata/verdicts-loosened.tsv
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if ! git cat-file -e "$base_ref:$file" 2>/dev/null; then
  echo "No $file at $base_ref; nothing to compare."
  exit 0
fi

base_rows="$(mktemp)"
trap 'rm -f "$base_rows"' EXIT
git show "$base_ref:$file" >"$base_rows"

awk -F'\t' -v ackfile="$ack" '
  function rank(a) {
    if (a == "deny") return 3
    if (a == "ask" || a == "require_approval" || a == "webhook") return 2
    if (a == "watch") return 1
    return 0
  }
  /^#/ || NF == 0 { next }
  FILENAME == ackfile {
    if (NF != 5 || $5 == "") {
      printf "%s:%d: want set<TAB>was<TAB>now<TAB>quoted command<TAB>reason\n", ackfile, FNR
      bad = 1
      next
    }
    acked[$1 FS $2 FS $3 FS $4] = 1
    next
  }
  FNR == NR { base[$1 FS $3] = $2; next }
  { head[$1 FS $3] = $2 }
  END {
    if (bad) exit 1
    n = 0
    reviewed = 0
    for (key in base) {
      split(key, part, FS)
      now = ""
      if (!(key in head)) {
        now = "unrecorded"
      } else if (rank(head[key]) < rank(base[key])) {
        now = head[key]
      }
      if (now == "") continue
      ackkey = part[1] FS base[key] FS now FS part[2]
      if (ackkey in acked) {
        used[ackkey] = 1
        reviewed++
        continue
      }
      printf "%s\t%s\t%s\t%s\n", part[1], base[key], now, part[2]
      n++
    }
    for (k in acked) {
      if (!(k in used)) {
        split(k, part, FS)
        printf "note: %s lists a change this branch does not make: %s %s -> %s %s\n", ackfile, part[1], part[2], part[3], part[4]
      }
    }
    if (n > 0) {
      printf "%d recorded verdicts got weaker or were removed without review.\n", n
      printf "If each is intended, add the rows above to %s with a reason as a fifth column.\n", ackfile
      exit 1
    }
    if (reviewed > 0) printf "%d weaker verdicts are listed in %s.\n", reviewed, ackfile
    print "No unreviewed verdict got weaker."
  }
' "$base_rows" "$file" "$ack"
