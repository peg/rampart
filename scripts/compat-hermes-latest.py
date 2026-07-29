#!/usr/bin/env python3
"""Validate Rampart's Hermes plugin against an isolated Hermes runtime.

This harness is intentionally isolated. It creates a temporary home/HERMES_HOME,
installs the candidate Rampart plugin there, and exercises Hermes' real plugin
discovery plus pre_tool_call dispatcher without touching a live Hermes gateway.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import textwrap
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


REPO_ROOT = Path(
    os.environ.get("RAMPART_COMPAT_REPO_ROOT", Path(__file__).resolve().parents[1])
).expanduser().absolute()

PLAIN_CHILD_ENV_KEYS = (
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "SHELL",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TERM",
    "CI",
    "GITHUB_ACTIONS",
    "RUNNER_OS",
    "NO_PROXY",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "PIP_CERT",
)

URL_CHILD_ENV_KEYS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "PIP_INDEX_URL",
    "PIP_EXTRA_INDEX_URL",
    "GOPROXY",
)


def credential_free_url_setting(value: str) -> str:
    """Return a URL/list setting only when none of its entries has userinfo."""

    value = value.strip()
    if not value or "@" in value:
        return ""
    for item in re.split(r"[\s,|]+", value):
        if not item or item in {"direct", "off"}:
            continue
        parsed = urllib.parse.urlsplit(item)
        # Forward only standard credential-free URLs. Query strings and
        # fragments commonly carry opaque access tokens even without userinfo.
        if (
            parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or not parsed.scheme
        ):
            return ""
    return value


def build_compat_env(source: dict[str, str], home: Path, temp_dir: Path) -> dict[str, str]:
    """Build a credential-free child environment with isolated state paths."""

    env: dict[str, str] = {}
    for key in PLAIN_CHILD_ENV_KEYS:
        if source.get(key):
            env[key] = source[key]
    for key in URL_CHILD_ENV_KEYS:
        value = credential_free_url_setting(source.get(key, ""))
        if value:
            env[key] = value

    no_proxy = [
        entry.strip()
        for entry in (source.get("NO_PROXY") or source.get("no_proxy") or "").split(",")
        if entry.strip()
    ]
    for host in ("127.0.0.1", "localhost", "::1"):
        if host not in no_proxy:
            no_proxy.append(host)
    env["NO_PROXY"] = ",".join(no_proxy)
    env["no_proxy"] = env["NO_PROXY"]

    env.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "TMPDIR": str(temp_dir),
            "TMP": str(temp_dir),
            "TEMP": str(temp_dir),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "XDG_DATA_HOME": str(home / ".local" / "share"),
            "XDG_STATE_HOME": str(home / ".local" / "state"),
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PYTHONNOUSERSITE": "1",
        }
    )
    return env


def remove_temp_tree(path: Path) -> None:
    """Remove Go module caches even though downloaded module files are read-only."""

    def make_writable_and_retry(func: Any, item: str, _: Any) -> None:
        parent = Path(item).parent
        os.chmod(parent, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        os.chmod(item, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        func(item)

    shutil.rmtree(path, onerror=make_writable_and_retry)


class RampartStub(BaseHTTPRequestHandler):
    requests_seen: list[dict[str, Any]] = []

    def do_POST(self) -> None:  # noqa: N802, inherited name
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {}

        params = payload.get("params") if isinstance(payload, dict) else {}
        if not isinstance(params, dict):
            params = {}
        command = str(params.get("command") or "")
        record = {
            "path": self.path,
            "agent": payload.get("agent") if isinstance(payload, dict) else None,
            "session": payload.get("session") if isinstance(payload, dict) else None,
            "tool_call_id_present": bool(payload.get("tool_call_id")) if isinstance(payload, dict) else False,
            "enforce": payload.get("enforce") if isinstance(payload, dict) else None,
            "command_marker": _marker_from_command(command),
            "policy_path": str(params.get("path") or ""),
        }
        self.requests_seen.append(record)

        status = 200
        policy_path = str(params.get("path") or "").replace("\\", "/")
        if policy_path == "secrets/.env" or policy_path.endswith("/secrets/.env"):
            body = {
                "decision": "deny",
                "allowed": False,
                "message": "protected compatibility path",
                "policy": "compat-path-deny",
                "audit_id": "compat-audit-path-deny",
            }
        elif "rampart-deny-marker" in command:
            body = {
                "decision": "deny",
                "allowed": False,
                "message": "blocked by compatibility harness",
                "policy": "compat-deny",
                "audit_id": "compat-audit-deny",
            }
        elif "rampart-ask-marker" in command:
            body = {
                "decision": "ask",
                "allowed": False,
                "message": "requires compatibility harness approval",
                "matched_policies": ["compat-ask"],
                "audit_id": "compat-audit-ask",
            }
        elif "rampart-auth-error-marker" in command:
            status = 401
            body = {
                "error": "invalid authorization token",
                "message": "invalid authorization token",
            }
        else:
            body = {
                "decision": "allow",
                "allowed": True,
                "message": "allowed by compatibility harness",
                "audit_id": "compat-audit-allow",
            }

        encoded = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: Any) -> None:
        _ = (format, args)
        return


def _marker_from_command(command: str) -> str:
    for marker in ("rampart-deny-marker", "rampart-ask-marker", "rampart-allow-marker", "rampart-auth-error-marker"):
        if marker in command:
            return marker
    return ""


def run(cmd: list[str], *, env: dict[str, str], cwd: Path = REPO_ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )


def resolve_executable(value: str) -> Path:
    if not value:
        raise ValueError("empty executable path")
    if os.sep not in value and (os.altsep is None or os.altsep not in value):
        found = shutil.which(value)
        if found:
            return Path(found)
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    path = path.absolute()
    if not path.exists():
        raise FileNotFoundError(f"executable not found: {value}")
    return path


def make_venv(
    root: Path,
    package: str,
    env: dict[str, str],
    base_python: str | None = None,
) -> tuple[Path, Path]:
    venv_dir = root / "venv"
    resolved_python = resolve_executable(base_python or sys.executable)
    run([str(resolved_python), "-m", "venv", str(venv_dir)], env=env, cwd=root)
    python = venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    hermes = venv_dir / ("Scripts/hermes.exe" if os.name == "nt" else "bin/hermes")
    run([str(python), "-m", "pip", "install", "--upgrade", "pip"], env=env, cwd=root)
    run([str(python), "-m", "pip", "install", package], env=env, cwd=root)
    return python, hermes


def distribution_version(python: Path, distribution: str, env: dict[str, str]) -> str:
    result = run(
        [
            str(python),
            "-c",
            "import importlib.metadata; print(importlib.metadata.version(" + repr(distribution) + "))",
        ],
        env=env,
    )
    return result.stdout.strip()


def pypi_latest_version(distribution: str, env: dict[str, str]) -> str:
    name = urllib.parse.quote(distribution, safe="")
    request = urllib.request.Request(
        f"https://pypi.org/pypi/{name}/json",
        headers={"User-Agent": "rampart-hermes-compat/1"},
    )
    proxies: dict[str, str] = {}
    all_proxy = env.get("all_proxy") or env.get("ALL_PROXY")
    for scheme in ("http", "https"):
        value = (
            env.get(f"{scheme}_proxy")
            or env.get(f"{scheme.upper()}_PROXY")
            or all_proxy
        )
        if value:
            proxies[scheme] = value
    opener = urllib.request.build_opener(urllib.request.ProxyHandler(proxies))
    with opener.open(request, timeout=15) as response:
        payload = json.load(response)
    return str(payload["info"]["version"])


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def write_hermes_config(hermes_home: Path, serve_url: str) -> None:
    hermes_home.mkdir(parents=True, exist_ok=True)
    (hermes_home / "config.yaml").write_text(
        textwrap.dedent(
            f"""
            plugins:
              enabled:
                - rampart
              entries:
                rampart:
                  config:
                    serve_url: {serve_url}
                    endpoint_mode: preflight
                    timeout_ms: 1000
                    fail_open_tools:
                      - read_file
                      - search_files
            """
        ).lstrip(),
        encoding="utf-8",
    )


def child_probe_code(unused_port: int) -> str:
    return textwrap.dedent(
        f"""
        import json
        import os
        from hermes_cli.plugins import discover_plugins, get_plugin_manager, get_pre_tool_call_block_message

        discover_plugins(force=True)
        manager = get_plugin_manager()
        loaded = manager._plugins.get('rampart')
        if loaded is None:
            raise SystemExit('rampart plugin was not discovered')
        if not loaded.enabled:
            raise SystemExit(f'rampart plugin discovered but not enabled: {{loaded.error}}')
        hooks = manager._hooks.get('pre_tool_call') or []
        if not hooks:
            raise SystemExit('rampart plugin did not register a pre_tool_call hook')

        def block(tool, args, call_id):
            return get_pre_tool_call_block_message(
                tool,
                args,
                task_id='compat-task',
                session_id='compat-session',
                tool_call_id=call_id,
            )

        deny = block('terminal', {{'command': 'printf rampart-deny-marker'}}, 'compat-deny-call')
        if not deny or 'blocked by compatibility harness' not in deny or 'compat-audit-deny' not in deny:
            raise SystemExit(f'deny did not block as expected: {{deny!r}}')

        ask = block('terminal', {{'command': 'printf rampart-ask-marker'}}, 'compat-ask-call')
        if not ask or 'approval required' not in ask or 'does not yet resume' not in ask or 'compat-audit-ask' not in ask:
            raise SystemExit(f'ask did not block with no-resume message: {{ask!r}}')

        allow = block('terminal', {{'command': 'printf rampart-allow-marker'}}, 'compat-allow-call')
        if allow is not None:
            raise SystemExit(f'allow should continue without a block message: {{allow!r}}')

        auth_error = block('terminal', {{'command': 'printf rampart-auth-error-marker'}}, 'compat-auth-error-call')
        if not auth_error or 'invalid authorization token' not in auth_error:
            raise SystemExit(f'auth error did not fail closed: {{auth_error!r}}')

        patch = block(
            'patch',
            {{
                'mode': 'patch',
                'patch': (
                    '*** Begin Patch\\n'
                    '*** Add File: safe.txt\\n'
                    '+safe\\n'
                    '*** Update File: secrets/.env\\n'
                    '@@\\n-old\\n+new\\n'
                    '*** End Patch'
                ),
            }},
            'compat-patch-call',
        )
        if not patch or 'protected compatibility path' not in patch or 'compat-audit-path-deny' not in patch:
            raise SystemExit(f'multi-path patch did not block protected second target: {{patch!r}}')

        os.environ['RAMPART_HERMES_URL'] = 'http://127.0.0.1:{unused_port}'
        os.environ['RAMPART_HERMES_TIMEOUT_MS'] = '250'
        fail_closed = block('terminal', {{'command': 'printf rampart-fail-closed-marker'}}, 'compat-fail-closed-call')
        if not fail_closed or 'unavailable' not in fail_closed:
            raise SystemExit(f'mutating terminal did not fail closed: {{fail_closed!r}}')

        fail_open = block('read_file', {{'path': '/tmp/rampart-compat-read.txt'}}, 'compat-fail-open-call')
        if fail_open is not None:
            raise SystemExit(f'configured read_file fail-open should continue: {{fail_open!r}}')

        print(json.dumps({{
            'ok': True,
            'plugin_version': loaded.manifest.version,
            'hooks_registered': loaded.hooks_registered,
            'pre_tool_call_hooks': len(hooks),
            'deny_blocked': True,
            'ask_blocked_without_resume': True,
            'allow_continued': True,
            'auth_error_fail_closed': True,
            'multi_path_patch_deny_wins': True,
            'mutating_fail_closed': True,
            'configured_read_fail_open': True,
        }}, sort_keys=True))
        """
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Rampart's Hermes plugin against an isolated latest Hermes runtime.")
    parser.add_argument("--package", default="hermes-agent", help="pip package spec to install, default: hermes-agent")
    parser.add_argument("--python", help="Base Python interpreter used to create the isolated environment")
    parser.add_argument("--hermes-python", help="Use an existing Python interpreter with Hermes installed instead of creating a venv")
    parser.add_argument("--hermes-bin", help="Hermes executable to report version from when --hermes-python is used")
    parser.add_argument("--keep-temp", action="store_true", help="Keep the temporary directory for debugging")
    args = parser.parse_args()

    temp = Path(tempfile.mkdtemp(prefix="rampart-hermes-compat-"))
    try:
        home = temp / "home"
        child_temp = temp / "tmp"
        home.mkdir(parents=True, exist_ok=True)
        child_temp.mkdir(parents=True, exist_ok=True)
        env = build_compat_env(dict(os.environ), home, child_temp)

        installed_package_version = None
        published_package_version = None
        if args.hermes_python:
            hermes_python = resolve_executable(args.hermes_python)
            hermes_bin_path = resolve_executable(args.hermes_bin) if args.hermes_bin else None
            if hermes_bin_path is None:
                hermes_bin = shutil.which("hermes")
                hermes_bin_path = Path(hermes_bin) if hermes_bin else None
        else:
            hermes_python, hermes_bin_path = make_venv(temp, args.package, env, args.python)
            if args.package == "hermes-agent":
                installed_package_version = distribution_version(hermes_python, "hermes-agent", env)
                published_package_version = pypi_latest_version("hermes-agent", env)
                if installed_package_version != published_package_version:
                    raise RuntimeError(
                        "hermes-agent resolved to "
                        f"{installed_package_version}, but PyPI latest is {published_package_version}; "
                        "use a Python version supported by the latest Hermes release"
                    )

        hermes_home = temp / "hermes-home"
        plugin_dir = hermes_home / "plugins" / "rampart"

        server = ThreadingHTTPServer(("127.0.0.1", 0), RampartStub)
        serve_url = f"http://127.0.0.1:{server.server_address[1]}"
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            write_hermes_config(hermes_home, serve_url)
            env.update(
                {
                    "HERMES_HOME": str(hermes_home),
                    "RAMPART_TOKEN": "compat-test-token",
                    "RAMPART_HERMES_URL": serve_url,
                    "RAMPART_HERMES_TIMEOUT_MS": "1000",
                    "PYTHONWARNINGS": "ignore::DeprecationWarning",
                }
            )

            run(
                [
                    "go",
                    "run",
                    "./cmd/rampart",
                    "setup",
                    "hermes",
                    "--plugin-dir",
                    str(plugin_dir),
                ],
                env=env,
            )

            hermes_version = "unavailable"
            if hermes_bin_path:
                try:
                    version_result = run([str(hermes_bin_path), "--version"], env=env, cwd=temp)
                    hermes_version = (version_result.stdout or version_result.stderr).strip().splitlines()[0]
                except Exception:
                    hermes_version = "version command failed"

            probe = run([str(hermes_python), "-c", child_probe_code(free_port())], env=env, cwd=temp)
            child_summary = json.loads(probe.stdout.strip().splitlines()[-1])

            paths = {entry["path"] for entry in RampartStub.requests_seen}
            if "/v1/preflight/exec" not in paths:
                raise RuntimeError(f"expected /v1/preflight/exec request, saw {sorted(paths)}")
            if any(entry["enforce"] is not True for entry in RampartStub.requests_seen):
                raise RuntimeError("every Hermes pre-tool policy request must carry enforce=true")
            markers = {entry["command_marker"] for entry in RampartStub.requests_seen}
            expected = {"rampart-deny-marker", "rampart-ask-marker", "rampart-allow-marker", "rampart-auth-error-marker"}
            if not expected.issubset(markers):
                raise RuntimeError(f"expected request markers {sorted(expected)}, saw {sorted(markers)}")
            patch_paths = [
                entry["policy_path"]
                for entry in RampartStub.requests_seen
                if entry["path"] == "/v1/preflight/edit"
            ]
            normalized_patch_paths = [path.replace("\\", "/") for path in patch_paths]
            if (
                len(normalized_patch_paths) != 2
                or not (normalized_patch_paths[0] == "safe.txt" or normalized_patch_paths[0].endswith("/safe.txt"))
                or not (
                    normalized_patch_paths[1] == "secrets/.env"
                    or normalized_patch_paths[1].endswith("/secrets/.env")
                )
            ):
                raise RuntimeError(f"expected both patch targets in order, saw {patch_paths}")

            print(
                json.dumps(
                    {
                        "ok": True,
                        "hermes_version": hermes_version,
                        "installed_package_version": installed_package_version,
                        "published_package_version": published_package_version,
                        "hermes_home_isolated": str(hermes_home),
                        "plugin_dir": str(plugin_dir),
                        "requests_seen": RampartStub.requests_seen,
                        "dispatcher": child_summary,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
    finally:
        if args.keep_temp:
            print(f"kept temporary directory: {temp}", file=sys.stderr)
        else:
            remove_temp_tree(temp)


if __name__ == "__main__":
    raise SystemExit(main())
