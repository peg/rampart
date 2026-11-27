#!/usr/bin/env bash
# Copyright 2026 The Rampart Authors
# Licensed under the Apache License, Version 2.0
#
# Usage: scripts/check-verdict-loosening.sh BASE_REF
#
# Compares policies/testdata/verdicts.tsv at BASE_REF with the working tree and
# exits 1 when a recorded verdict gets weaker (deny > ask) or a recorded row
# disappears, unless this change adds that exact change with a reason to
# policies/testdata/verdicts-loosened.tsv. Rows already listed at BASE_REF
# approve nothing, so each loosening is reviewed once.

set -euo pipefail

base_ref="${1:?usage: $0 BASE_REF}"
file=policies/testdata/verdicts.tsv
ack=policies/testdata/verdicts-loosened.tsv
cd "$(git rev-parse --show-toplevel)"

git rev-parse --verify --quiet "$base_ref^{commit}" >/dev/null || {
  echo "Base revision $base_ref is not available." >&2
  exit 1
}
if ! git cat-file -e "$base_ref:$file" 2>/dev/null; then
  echo "No $file at $base_ref; nothing to compare."
  exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
git show "$base_ref:$file" >"$tmp/base"
git show "$base_ref:$ack" >"$tmp/base-ack" 2>/dev/null || : >"$tmp/base-ack"

awk -F'\t' -v baseack="$tmp/base-ack" -v base="$tmp/base" -v ackfile="$ack" '
  function rank(a) {
    if (a == "deny") return 2
    if (a == "ask" || a == "require_approval") return 1
    return 0
  }
  /^#/ || NF == 0 { next }
  FILENAME == baseack { old[$1 FS $2 FS $3 FS $4] = 1; next }
  FILENAME == base { was[$1 FS $3] = $2; next }
  FILENAME == ackfile {
    if (NF != 5 || $5 == "") {
      printf "%s:%d: want set<TAB>was<TAB>now<TAB>quoted command<TAB>reason\n", ackfile, FNR
      bad = 1
    } else if (!(($1 FS $2 FS $3 FS $4) in old)) {
      acked[$1 FS $2 FS $3 FS $4] = 1
    }
    next
  }
  { now[$1 FS $3] = $2 }
  END {
    if (bad) exit 1
    n = 0
    for (key in was) {
      split(key, part, FS)
      if (!(key in now)) {
        to = "unrecorded"
      } else if (rank(now[key]) < rank(was[key])) {
        to = now[key]
      } else {
        continue
      }
      k = part[1] FS was[key] FS to FS part[2]
      if (k in acked) {
        delete acked[k]
        continue
      }
      printf "%s\t%s\t%s\t%s\n", part[1], was[key], to, part[2]
      n++
    }
    # Not an error: a release diff omits changes that were reverted before release.
    for (k in acked) printf "Note: %s lists a change this diff does not make: %s\n", ackfile, k
    if (n > 0) {
      printf "%d recorded verdicts got weaker or were removed without review.\n", n
      printf "If each is intended, add the rows above to %s with a reason as a fifth column.\n", ackfile
      exit 1
    }
    print "No unreviewed verdict got weaker."
  }
' "$tmp/base-ack" "$tmp/base" "$ack" "$file"
