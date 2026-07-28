#!/usr/bin/env bash
# Copyright 2026 The Rampart Authors
# Licensed under the Apache License, Version 2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) echo "installer test requires Linux or macOS" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "unsupported test architecture" >&2; exit 1 ;;
esac

version=9.9.9
asset="rampart_${version}_${os}_${arch}.tar.gz"
mkdir -p "$tmp/payload" "$tmp/fake-bin"
printf '%s\n' '#!/bin/sh' 'echo "rampart 9.9.9"' >"$tmp/payload/rampart"
chmod +x "$tmp/payload/rampart"
tar -czf "$tmp/$asset" -C "$tmp/payload" rampart
if command -v sha256sum >/dev/null 2>&1; then
  digest="$(sha256sum "$tmp/$asset" | awk '{print $1}')"
else
  digest="$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')"
fi
printf '%s  %s\n' "$digest" "$asset" >"$tmp/checksums-valid.txt"
printf '%s  %s\n' "$digest" "another-file.tar.gz" >"$tmp/checksums-wrong-entry.txt"
printf '%s  %s\n%s  %s\n' "$digest" "$asset" "$digest" "$asset" >"$tmp/checksums-duplicate.txt"

cat >"$tmp/fake-bin/curl" <<'SH'
#!/bin/sh
set -eu
dest=""
url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) dest="$2"; shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
case "$url" in
  */checksums.txt)
    case "${FAKE_CHECKSUM_MODE:-valid}" in
      missing) exit 22 ;;
      wrong-entry) cp "$FAKE_CHECKSUM_WRONG_ENTRY" "$dest" ;;
      duplicate) cp "$FAKE_CHECKSUM_DUPLICATE" "$dest" ;;
      *) cp "$FAKE_CHECKSUM_VALID" "$dest" ;;
    esac
    ;;
  *.tar.gz) cp "$FAKE_ARCHIVE" "$dest" ;;
  *) exit 22 ;;
esac
SH
chmod +x "$tmp/fake-bin/curl"

run_installer() {
  mode="$1"
  install_dir="$tmp/install-$mode"
  mkdir -p "$install_dir"
  FAKE_CHECKSUM_MODE="$mode" \
  FAKE_ARCHIVE="$tmp/$asset" \
  FAKE_CHECKSUM_VALID="$tmp/checksums-valid.txt" \
  FAKE_CHECKSUM_WRONG_ENTRY="$tmp/checksums-wrong-entry.txt" \
  FAKE_CHECKSUM_DUPLICATE="$tmp/checksums-duplicate.txt" \
  RAMPART_INSTALL_DIR="$install_dir" \
  HOME="$tmp/home-$mode" \
  PATH="$tmp/fake-bin:$PATH" \
    sh "$repo_root/install.sh" --version "v$version"
}

run_installer valid >"$tmp/valid.log" 2>&1
test -x "$tmp/install-valid/rampart"
grep -F 'Checksum verified' "$tmp/valid.log" >/dev/null

for mode in missing wrong-entry duplicate; do
  if run_installer "$mode" >"$tmp/$mode.log" 2>&1; then
    echo "installer unexpectedly accepted checksum mode: $mode" >&2
    exit 1
  fi
  if [[ -e "$tmp/install-$mode/rampart" ]]; then
    echo "installer wrote a binary after checksum failure: $mode" >&2
    exit 1
  fi
done

# Exercise the no-verifier branch with an intentionally minimal PATH that has
# every installer dependency except sha256sum/shasum.
mkdir -p "$tmp/nohash-bin"
for tool in awk chmod cp grep gzip id mkdir mktemp mv rm tar tr uname; do
  ln -s "$(command -v "$tool")" "$tmp/nohash-bin/$tool"
done
ln -s "$tmp/fake-bin/curl" "$tmp/nohash-bin/curl"
if FAKE_CHECKSUM_MODE=valid \
  FAKE_ARCHIVE="$tmp/$asset" \
  FAKE_CHECKSUM_VALID="$tmp/checksums-valid.txt" \
  FAKE_CHECKSUM_WRONG_ENTRY="$tmp/checksums-wrong-entry.txt" \
  FAKE_CHECKSUM_DUPLICATE="$tmp/checksums-duplicate.txt" \
  RAMPART_INSTALL_DIR="$tmp/install-nohash" \
  HOME="$tmp/home-nohash" \
  PATH="$tmp/nohash-bin" \
    /bin/sh "$repo_root/install.sh" --version "v$version" >"$tmp/nohash.log" 2>&1; then
  echo "installer unexpectedly proceeded without a SHA-256 tool" >&2
  exit 1
fi
grep -F 'No SHA-256 tool found' "$tmp/nohash.log" >/dev/null

echo "Installer checksum fail-closed tests passed."
