#!/usr/bin/env python3
"""Fail closed when a Rampart lab artifact tree contains credential material.

The report intentionally records only finding types and relative file paths.
Matched values are never printed or written back into the artifact tree.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys


SENSITIVE_FILENAMES = {
    ".env",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".credentials.json",
    "auth.json",
    "auth-profiles.json",
    "cookies.json",
    "credentials.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "oauth.json",
    "oauth_tokens.json",
    "service-account.json",
    "token",
}

# Keep these signatures specific enough for logs and JSON evidence. Broad
# entropy guesses create noisy false positives and make a fail-closed gate
# tempting to bypass. Generic assignments cover opaque provider refresh tokens.
SIGNATURES = (
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----")),
    ("github_token", re.compile(r"(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("openai_or_anthropic_key", re.compile(r"(?<![A-Za-z0-9])sk-(?:proj-|svcacct-|ant-)?[A-Za-z0-9_-]{20,}")),
    ("aws_access_key", re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")),
    ("google_api_key", re.compile(r"(?<![A-Za-z0-9])AIza[A-Za-z0-9_-]{30,}")),
    ("slack_token", re.compile(r"(?<![A-Za-z0-9])xox[a-z]-[A-Za-z0-9-]{20,}")),
    ("tailscale_auth_key", re.compile(r"(?<![A-Za-z0-9])tskey-[A-Za-z0-9_-]{20,}")),
    ("npm_token", re.compile(r"(?<![A-Za-z0-9])npm_[A-Za-z0-9]{20,}")),
    ("gitlab_token", re.compile(r"(?<![A-Za-z0-9])glpat-[A-Za-z0-9_-]{20,}")),
    ("jwt", re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])")),
    ("authorization_header", re.compile(r"(?i)\bauthorization\s*[:=]\s*(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{12,}={0,2}")),
    ("credentialed_url", re.compile(r"[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@", re.IGNORECASE)),
    (
        "secret_assignment",
        re.compile(
            r"(?ix)"
            r"(?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|"
            r"client[_-]?secret|gateway[_-]?token|rampart[_-]?token|password)"
            r"[\"']?\s*[:=]\s*[\"']?"
            r"(?!\[?redacted\]?|<redacted>|null\b|none\b|false\b|true\b)"
            r"[A-Za-z0-9._~+/-]{12,}={0,2}",
        ),
    ),
)

SELF_REPORT_NAMES = {"credential-scan.json", "checksums.txt"}
OPAQUE_ARCHIVE_SUFFIXES = {".7z", ".bz2", ".gz", ".tar", ".tgz", ".xz", ".zip"}


def readable_content(path):
    size = path.stat().st_size
    with path.open("rb") as handle:
        data = handle.read()
    try:
        return "text", data.decode("utf-8"), size
    except UnicodeDecodeError:
        # Provider keys and serialized credentials are ASCII even when they
        # land in an otherwise binary file. Scan printable runs instead of
        # silently declaring executables or archives safe.
        runs = re.findall(rb"[\x20-\x7e]{8,}", data)
        return "binary", "\n".join(run.decode("ascii") for run in runs), size


def scan(root):
    findings = []
    files_checked = 0
    bytes_checked = 0
    binary_files_scanned = 0

    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            findings.append({"path": relative, "kind": "symlink_not_allowed"})
            continue
        if not path.is_file() or path.name in SELF_REPORT_NAMES:
            continue
        if path.name.lower() in SENSITIVE_FILENAMES:
            findings.append({"path": relative, "kind": "sensitive_filename"})
        if path.suffix.lower() in OPAQUE_ARCHIVE_SUFFIXES:
            findings.append({"path": relative, "kind": "opaque_archive_not_allowed"})

        content_kind, content, size = readable_content(path)
        if content_kind == "binary":
            binary_files_scanned += 1
        files_checked += 1
        bytes_checked += size
        for kind, signature in SIGNATURES:
            # Generic key/value vocabulary is common in compiled programs and
            # loses the line/field structure that makes it meaningful in text.
            # Keep scanning binaries for concrete provider tokens, JWTs,
            # credentialed URLs, authorization headers, and private keys.
            if content_kind == "binary" and kind == "secret_assignment":
                continue
            if signature.search(content):
                findings.append({"path": relative, "kind": kind})

    # One entry per kind/path keeps the report useful without disclosing the
    # number or content of individual credentials in a compromised file.
    unique_findings = sorted({(f["path"], f["kind"]) for f in findings})
    findings = [{"path": path, "kind": kind} for path, kind in unique_findings]
    return {
        "schema_version": 1,
        "status": "passed" if not findings else "failed",
        "files_checked": files_checked,
        "bytes_checked": bytes_checked,
        "binary_files_scanned": binary_files_scanned,
        "finding_count": len(findings),
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    if not root.is_dir():
        parser.error(f"artifact root is not a directory: {root}")

    report = scan(root)
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
