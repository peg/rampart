#!/usr/bin/env bash
# Copyright 2026 The Rampart Authors
# Licensed under the Apache License, Version 2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
installer_shell="${INSTALLER_SHELL:-sh}"
tmp="$(mktemp -d)"
cleanup_test() {
  status="$?"
  trap - EXIT
  rm -rf "$tmp"
  exit "$status"
}
trap cleanup_test EXIT

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
printf '%s\n' \
  '#!/bin/sh' \
  'if [ -n "${RAMPART_INSTALL_TRACE:-}" ]; then printf "%s|%s\n" "$0" "$*" >>"$RAMPART_INSTALL_TRACE"; fi' \
  'case "${1:-}" in
  version) echo "rampart 9.9.9" ;;
  serve)
    case "${2:-}" in
      stop) [ -n "${RAMPART_TEST_PID_PATH:-}" ] && rm -f "$RAMPART_TEST_PID_PATH" ;;
      --background)
        if [ -n "${RAMPART_TEST_PID_PATH:-}" ]; then
          mkdir -p "$(dirname "$RAMPART_TEST_PID_PATH")"
          printf "%s\n" "$$" >"$RAMPART_TEST_PID_PATH"
        fi
        ;;
    esac
    ;;
  *) exit 64 ;;
esac' >"$tmp/payload/rampart"
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

make_fixture() {
  name="$1"
  body="$2"
  mkdir -p "$tmp/payload-$name"
  printf '%s\n' '#!/bin/sh' "$body" >"$tmp/payload-$name/rampart"
  chmod +x "$tmp/payload-$name/rampart"
  tar -czf "$tmp/$name.tar.gz" -C "$tmp/payload-$name" rampart
  if command -v sha256sum >/dev/null 2>&1; then
    fixture_digest="$(sha256sum "$tmp/$name.tar.gz" | awk '{print $1}')"
  else
    fixture_digest="$(shasum -a 256 "$tmp/$name.tar.gz" | awk '{print $1}')"
  fi
  printf '%s  %s\n' "$fixture_digest" "$asset" >"$tmp/checksums-$name.txt"
}

make_fixture wrong-version 'echo "rampart 9.9.8"'
make_fixture wrong-identity 'echo "not-rampart 9.9.9"'
make_fixture post-activation-failure \
  'if [ "$0" = "${RAMPART_TEST_FINAL_PATH:-}" ]; then exit 70; fi
echo "rampart 9.9.9"'
make_fixture runtime-restart-failure \
  'if [ -n "${RAMPART_INSTALL_TRACE:-}" ]; then printf "candidate-restart|%s|%s\n" "$0" "$*" >>"$RAMPART_INSTALL_TRACE"; fi
case "${1:-}" in
  version) echo "rampart 9.9.9" ;;
  serve) [ "${2:-}" != "--background" ] || exit 75 ;;
  *) exit 64 ;;
esac'

mkdir -p "$tmp/payload-invalid"
printf '%s\n' 'this is not an executable image' >"$tmp/payload-invalid/rampart"
tar -czf "$tmp/invalid-executable.tar.gz" -C "$tmp/payload-invalid" rampart
if command -v sha256sum >/dev/null 2>&1; then
  invalid_digest="$(sha256sum "$tmp/invalid-executable.tar.gz" | awk '{print $1}')"
else
  invalid_digest="$(shasum -a 256 "$tmp/invalid-executable.tar.gz" | awk '{print $1}')"
fi
printf '%s  %s\n' "$invalid_digest" "$asset" >"$tmp/checksums-invalid-executable.txt"

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

cat >"$tmp/fake-bin/systemctl" <<'SH'
#!/bin/sh
set -eu
if [ -n "${RAMPART_SYSTEMCTL_TRACE:-}" ]; then
  printf '%s\n' "$*" >>"$RAMPART_SYSTEMCTL_TRACE"
fi
if [ "${1:-}" = "--user" ] && [ "${2:-}" = "is-active" ] && [ "${3:-}" = "--quiet" ]; then
  [ "${4:-}" = "${RAMPART_SYSTEMCTL_ACTIVE:-}" ]
  exit
fi
exit 0
SH
chmod +x "$tmp/fake-bin/systemctl"

cat >"$tmp/fake-bin/launchctl" <<'SH'
#!/bin/sh
set -eu
if [ -n "${RAMPART_LAUNCHCTL_TRACE:-}" ]; then
  printf '%s\n' "$*" >>"$RAMPART_LAUNCHCTL_TRACE"
fi
if [ "${1:-}" = "list" ]; then
  [ "${2:-}" = "${RAMPART_LAUNCHCTL_ACTIVE:-}" ]
  exit
fi
exit 0
SH
chmod +x "$tmp/fake-bin/launchctl"

run_installer_at() {
  mode="$1"
  install_dir="$2"
  mkdir -p "$install_dir"
  FAKE_CHECKSUM_MODE="$mode" \
  FAKE_ARCHIVE="$tmp/$asset" \
  FAKE_CHECKSUM_VALID="$tmp/checksums-valid.txt" \
  FAKE_CHECKSUM_WRONG_ENTRY="$tmp/checksums-wrong-entry.txt" \
  FAKE_CHECKSUM_DUPLICATE="$tmp/checksums-duplicate.txt" \
  RAMPART_INSTALL_DIR="$install_dir" \
  RAMPART_INSTALL_TRACE="${RAMPART_INSTALL_TRACE:-}" \
  RAMPART_TEST_FINAL_PATH="${RAMPART_TEST_FINAL_PATH:-}" \
  RAMPART_TEST_PID_PATH="${RAMPART_TEST_PID_PATH:-}" \
  RAMPART_SYSTEMCTL_ACTIVE="${RAMPART_SYSTEMCTL_ACTIVE:-}" \
  RAMPART_SYSTEMCTL_TRACE="${RAMPART_SYSTEMCTL_TRACE:-}" \
  RAMPART_LAUNCHCTL_ACTIVE="${RAMPART_LAUNCHCTL_ACTIVE:-}" \
  RAMPART_LAUNCHCTL_TRACE="${RAMPART_LAUNCHCTL_TRACE:-}" \
  HOME="${RAMPART_TEST_HOME:-$tmp/home-$mode}" \
  PATH="$tmp/fake-bin:$install_dir:$PATH" \
    "$installer_shell" "$repo_root/install.sh" --version "v$version"
}

run_installer() {
  mode="$1"
  run_installer_at "$mode" "$tmp/install-$mode"
}

run_fixture() {
  fixture="$1"
  install_dir="$2"
  FAKE_CHECKSUM_MODE=valid \
  FAKE_ARCHIVE="$tmp/$fixture.tar.gz" \
  FAKE_CHECKSUM_VALID="$tmp/checksums-$fixture.txt" \
  FAKE_CHECKSUM_WRONG_ENTRY="$tmp/checksums-wrong-entry.txt" \
  FAKE_CHECKSUM_DUPLICATE="$tmp/checksums-duplicate.txt" \
  RAMPART_INSTALL_DIR="$install_dir" \
  RAMPART_INSTALL_TRACE="${RAMPART_INSTALL_TRACE:-}" \
  RAMPART_TEST_FINAL_PATH="${RAMPART_TEST_FINAL_PATH:-}" \
  RAMPART_TEST_PID_PATH="${RAMPART_TEST_PID_PATH:-}" \
  RAMPART_SYSTEMCTL_ACTIVE="${RAMPART_SYSTEMCTL_ACTIVE:-}" \
  RAMPART_SYSTEMCTL_TRACE="${RAMPART_SYSTEMCTL_TRACE:-}" \
  RAMPART_LAUNCHCTL_ACTIVE="${RAMPART_LAUNCHCTL_ACTIVE:-}" \
  RAMPART_LAUNCHCTL_TRACE="${RAMPART_LAUNCHCTL_TRACE:-}" \
  HOME="${RAMPART_TEST_HOME:-$tmp/home-$fixture}" \
  PATH="$tmp/fake-bin:$install_dir:$PATH" \
    "$installer_shell" "$repo_root/install.sh" --version "v$version"
}

assert_no_transaction_artifacts() {
  install_dir="$1"
  if find "$install_dir" -maxdepth 1 -name '.rampart-install.*' -print -quit | grep -q .; then
    echo "installer left transaction artifacts in $install_dir" >&2
    exit 1
  fi
}

write_prior_install() {
  install_dir="$1"
  mkdir -p "$install_dir"
  printf '%s\n' \
    '#!/bin/sh' \
    'if [ -n "${RAMPART_INSTALL_TRACE:-}" ]; then printf "%s|%s\n" "$0" "$*" >>"$RAMPART_INSTALL_TRACE"; fi' \
    'case "${1:-}" in
  version) echo "rampart 9.9.7" ;;
  serve)
    case "${2:-}" in
      stop) [ -n "${RAMPART_TEST_PID_PATH:-}" ] && rm -f "$RAMPART_TEST_PID_PATH" ;;
      --background)
        if [ -n "${RAMPART_TEST_PID_PATH:-}" ]; then
          mkdir -p "$(dirname "$RAMPART_TEST_PID_PATH")"
          printf "%s\n" "$$" >"$RAMPART_TEST_PID_PATH"
        fi
        ;;
    esac
    ;;
  *) exit 64 ;;
esac' >"$install_dir/rampart"
  chmod +x "$install_dir/rampart"
}

# Reject caller-controlled release strings before they can become archive
# paths or URLs. This must happen even in dry-run mode.
for invalid_version in \
  'v../../tmp/rampart' \
  'v1.2' \
  'v01.2.3' \
  'v1.2.3/extra' \
  'v1.2.3-'; do
  if RAMPART_INSTALL_DRY_RUN=1 \
    RAMPART_INSTALL_DIR="$tmp/install-invalid-version" \
    HOME="$tmp/home-invalid-version" \
      "$installer_shell" "$repo_root/install.sh" --version "$invalid_version" >"$tmp/invalid-version.log" 2>&1; then
    echo "installer unexpectedly accepted invalid version: $invalid_version" >&2
    exit 1
  fi
  grep -F 'Invalid release version' "$tmp/invalid-version.log" >/dev/null
done

if RAMPART_INSTALL_DRY_RUN=1 \
  RAMPART_INSTALL_DIR="$tmp/install-missing-version" \
  HOME="$tmp/home-missing-version" \
    "$installer_shell" "$repo_root/install.sh" --version >"$tmp/missing-version.log" 2>&1; then
  echo "installer unexpectedly accepted --version without a value" >&2
  exit 1
fi
grep -F -- '--version requires a value' "$tmp/missing-version.log" >/dev/null

RAMPART_INSTALL_TRACE="$tmp/valid.trace" run_installer valid >"$tmp/valid.log" 2>&1
test -x "$tmp/install-valid/rampart"
grep -F 'Checksum verified' "$tmp/valid.log" >/dev/null
grep -F 'Candidate version verified' "$tmp/valid.log" >/dev/null
grep -F 'Ready!' "$tmp/valid.log" >/dev/null
sed -n '2p' "$tmp/valid.trace" | grep -F "$tmp/install-valid/.rampart-install." >/dev/null
sed -n '2p' "$tmp/valid.trace" | grep -F '|version' >/dev/null
sed -n '3p' "$tmp/valid.trace" | grep -Fx "$tmp/install-valid/rampart|version" >/dev/null
assert_no_transaction_artifacts "$tmp/install-valid"

# An upgrade refreshes only authenticated Rampart runtimes: the fixed manager
# definition must name this exact installed executable and invoke `serve`.
runtime_install="$tmp/install-managed-runtime"
runtime_home="$tmp/home-managed-runtime"
runtime_pid="$runtime_home/.rampart/serve.pid"
runtime_trace="$tmp/managed-runtime.trace"
manager_trace="$tmp/manager.trace"
write_prior_install "$runtime_install"
mkdir -p "$(dirname "$runtime_pid")"
printf '%s\n' 424242 >"$runtime_pid"

if [[ "$os" == linux ]]; then
  mkdir -p "$runtime_home/.config/systemd/user"
  printf '%s\n' \
    '[Service]' \
    "ExecStart=\"$runtime_install/rampart\" serve --port 9090" \
    >"$runtime_home/.config/systemd/user/rampart-serve.service"
  printf '%s\n' \
    '[Service]' \
    'ExecStart="/tmp/unrelated-rampart" serve --port 9091' \
    >"$runtime_home/.config/systemd/user/rampart-proxy.service"
  RAMPART_TEST_HOME="$runtime_home" \
  RAMPART_TEST_PID_PATH="$runtime_pid" \
  RAMPART_INSTALL_TRACE="$runtime_trace" \
  RAMPART_SYSTEMCTL_ACTIVE=rampart-serve.service \
  RAMPART_SYSTEMCTL_TRACE="$manager_trace" \
    run_installer_at runtime "$runtime_install" >"$tmp/managed-runtime.log" 2>&1
  grep -Fx -- '--user is-active --quiet rampart-serve.service' "$manager_trace" >/dev/null
  grep -Fx -- '--user stop rampart-serve.service' "$manager_trace" >/dev/null
  grep -Fx -- '--user start rampart-serve.service' "$manager_trace" >/dev/null
  if grep -Fq 'rampart-proxy.service' "$manager_trace"; then
    echo "installer touched an unrelated fixed-name systemd unit" >&2
    exit 1
  fi
else
  launch_dir="$runtime_home/Library/LaunchAgents"
  mkdir -p "$launch_dir"
  cat >"$launch_dir/sh.rampart.serve.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>sh.rampart.serve</string>
<key>ProgramArguments</key><array>
<string>$runtime_install/rampart</string><string>serve</string><string>--port</string><string>9090</string>
</array>
</dict></plist>
PLIST
  cat >"$launch_dir/com.rampart.proxy.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.rampart.proxy</string>
<key>ProgramArguments</key><array><string>/tmp/unrelated-rampart</string><string>serve</string></array>
</dict></plist>
PLIST
  RAMPART_TEST_HOME="$runtime_home" \
  RAMPART_TEST_PID_PATH="$runtime_pid" \
  RAMPART_INSTALL_TRACE="$runtime_trace" \
  RAMPART_LAUNCHCTL_ACTIVE=sh.rampart.serve \
  RAMPART_LAUNCHCTL_TRACE="$manager_trace" \
    run_installer_at runtime "$runtime_install" >"$tmp/managed-runtime.log" 2>&1
  grep -Fx 'list sh.rampart.serve' "$manager_trace" >/dev/null
  grep -Fx "unload $launch_dir/sh.rampart.serve.plist" "$manager_trace" >/dev/null
  grep -Fx "load $launch_dir/sh.rampart.serve.plist" "$manager_trace" >/dev/null
  if grep -Fq 'com.rampart.proxy' "$manager_trace"; then
    echo "installer touched an unrelated fixed-name launchd definition" >&2
    exit 1
  fi
fi

grep -Fx "$runtime_install/rampart|serve stop" "$runtime_trace" >/dev/null
grep -Fx "$runtime_install/rampart|serve --background" "$runtime_trace" >/dev/null
"$runtime_install/rampart" version | grep -F 'rampart 9.9.9' >/dev/null
assert_no_transaction_artifacts "$runtime_install"

for mode in missing wrong-entry duplicate; do
  if run_installer "$mode" >"$tmp/$mode.log" 2>&1; then
    echo "installer unexpectedly accepted checksum mode: $mode" >&2
    exit 1
  fi
  if [[ -e "$tmp/install-$mode/rampart" ]]; then
    echo "installer wrote a binary after checksum failure: $mode" >&2
    exit 1
  fi
  if grep -Fq 'Ready!' "$tmp/$mode.log"; then
    echo "installer printed Ready after checksum failure: $mode" >&2
    exit 1
  fi
done

# A correctly checksummed executable must still identify itself as the exact
# requested release before the existing binary is touched.
for fixture in wrong-version wrong-identity invalid-executable; do
  install_dir="$tmp/install-$fixture"
  write_prior_install "$install_dir"
  if run_fixture "$fixture" "$install_dir" >"$tmp/$fixture.log" 2>&1; then
    echo "installer unexpectedly accepted invalid candidate: $fixture" >&2
    exit 1
  fi
  "$install_dir/rampart" version | grep -F 'rampart 9.9.7' >/dev/null
  grep -F 'Downloaded Rampart candidate failed validation' "$tmp/$fixture.log" >/dev/null
  if grep -Fq 'Ready!' "$tmp/$fixture.log"; then
    echo "installer printed Ready after candidate validation failed: $fixture" >&2
    exit 1
  fi
  assert_no_transaction_artifacts "$install_dir"
done

# The candidate is checked again through its final path. If that check fails,
# the installer restores the prior binary and withholds the success message.
rollback_dir="$tmp/install-post-activation-failure"
write_prior_install "$rollback_dir"
rollback_home="$tmp/home-post-activation-failure"
rollback_pid="$rollback_home/.rampart/serve.pid"
rollback_trace="$tmp/post-activation-failure.trace"
mkdir -p "$(dirname "$rollback_pid")"
printf '%s\n' 424243 >"$rollback_pid"
if RAMPART_TEST_HOME="$rollback_home" \
  RAMPART_TEST_PID_PATH="$rollback_pid" \
  RAMPART_INSTALL_TRACE="$rollback_trace" \
  RAMPART_TEST_FINAL_PATH="$rollback_dir/rampart" \
  run_fixture post-activation-failure "$rollback_dir" >"$tmp/post-activation-failure.log" 2>&1; then
  echo "installer unexpectedly accepted a broken activated candidate" >&2
  exit 1
fi
"$rollback_dir/rampart" version | grep -F 'rampart 9.9.7' >/dev/null
grep -F 'restored the previous Rampart binary' "$tmp/post-activation-failure.log" >/dev/null
grep -Fx "$rollback_dir/rampart|serve stop" "$rollback_trace" >/dev/null
grep -Fx "$rollback_dir/rampart|serve --background" "$rollback_trace" >/dev/null
if grep -Fq 'Ready!' "$tmp/post-activation-failure.log"; then
  echo "installer printed Ready after rollback" >&2
  exit 1
fi
assert_no_transaction_artifacts "$rollback_dir"

# Runtime recovery is part of the binary transaction. If the activated
# candidate cannot restore a previously running background server, roll the
# binary back and restart that server through the old executable.
restart_failure_dir="$tmp/install-runtime-restart-failure"
restart_failure_home="$tmp/home-runtime-restart-failure"
restart_failure_pid="$restart_failure_home/.rampart/serve.pid"
restart_failure_trace="$tmp/runtime-restart-failure.trace"
write_prior_install "$restart_failure_dir"
mkdir -p "$(dirname "$restart_failure_pid")"
printf '%s\n' 424244 >"$restart_failure_pid"
if RAMPART_TEST_HOME="$restart_failure_home" \
  RAMPART_TEST_PID_PATH="$restart_failure_pid" \
  RAMPART_INSTALL_TRACE="$restart_failure_trace" \
  run_fixture runtime-restart-failure "$restart_failure_dir" >"$tmp/runtime-restart-failure.log" 2>&1; then
  echo "installer unexpectedly committed a candidate whose runtime restart failed" >&2
  exit 1
fi
"$restart_failure_dir/rampart" version | grep -F 'rampart 9.9.7' >/dev/null
grep -F 'previously active managed runtime did not restart. Rolling back' "$tmp/runtime-restart-failure.log" >/dev/null
grep -F 'restored the previous Rampart binary' "$tmp/runtime-restart-failure.log" >/dev/null
grep -Fx "candidate-restart|$restart_failure_dir/rampart|serve --background" "$restart_failure_trace" >/dev/null
grep -Fx "$restart_failure_dir/rampart|serve --background" "$restart_failure_trace" >/dev/null
assert_no_transaction_artifacts "$restart_failure_dir"

# Refuse a pre-existing symlink rather than silently replacing its topology or
# guessing whether the link target is the installation the caller intended.
symlink_dir="$tmp/install-symlink-refusal"
symlink_target_dir="$tmp/prior-symlink-target"
mkdir -p "$symlink_dir" "$symlink_target_dir"
printf '%s\n' '#!/bin/sh' 'echo "rampart 9.9.7"' >"$symlink_target_dir/rampart-old"
chmod +x "$symlink_target_dir/rampart-old"
ln -s "$symlink_target_dir/rampart-old" "$symlink_dir/rampart"
if run_installer_at valid "$symlink_dir" >"$tmp/symlink-refusal.log" 2>&1; then
  echo "installer unexpectedly replaced a symlink install path" >&2
  exit 1
fi
grep -F 'Refusing to replace symlink install path' "$tmp/symlink-refusal.log" >/dev/null
test -L "$symlink_dir/rampart"
test "$(readlink "$symlink_dir/rampart")" = "$symlink_target_dir/rampart-old"
"$symlink_dir/rampart" version | grep -F 'rampart 9.9.7' >/dev/null
assert_no_transaction_artifacts "$symlink_dir"

# A directory destination changes `mv` semantics from replacement to moving
# inside the directory. Refuse both a real directory and a symlink resolving to
# a directory before either can receive candidate or rollback files.
directory_target_install="$tmp/install-directory-target"
mkdir -p "$directory_target_install/rampart"
printf '%s\n' 'preserve-me' >"$directory_target_install/rampart/marker"
if run_installer_at valid "$directory_target_install" >"$tmp/directory-target.log" 2>&1; then
  echo "installer unexpectedly accepted a directory destination" >&2
  exit 1
fi
grep -F 'Refusing to replace directory install path' "$tmp/directory-target.log" >/dev/null
test "$(cat "$directory_target_install/rampart/marker")" = 'preserve-me'
test "$(find "$directory_target_install/rampart" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" = 1
assert_no_transaction_artifacts "$directory_target_install"

directory_symlink_install="$tmp/install-directory-symlink"
directory_symlink_target="$tmp/install-directory-symlink-target"
mkdir -p "$directory_symlink_install" "$directory_symlink_target"
printf '%s\n' 'preserve-me' >"$directory_symlink_target/marker"
ln -s "$directory_symlink_target" "$directory_symlink_install/rampart"
if run_installer_at valid "$directory_symlink_install" >"$tmp/directory-symlink.log" 2>&1; then
  echo "installer unexpectedly accepted a symlink-to-directory destination" >&2
  exit 1
fi
grep -F 'Refusing to replace symlink install path' "$tmp/directory-symlink.log" >/dev/null
test -L "$directory_symlink_install/rampart"
test "$(readlink "$directory_symlink_install/rampart")" = "$directory_symlink_target"
test "$(cat "$directory_symlink_target/marker")" = 'preserve-me'
test "$(find "$directory_symlink_target" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" = 1
assert_no_transaction_artifacts "$directory_symlink_install"

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

echo "Installer integrity and transaction tests passed."
