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
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import venv
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]


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
            "command_marker": _marker_from_command(command),
        }
        self.requests_seen.append(record)

        if "rampart-deny-marker" in command:
            body = {
                "decision": "deny",
                "message": "blocked by compatibility harness",
                "policy": "compat-deny",
                "audit_id": "compat-audit-deny",
            }
        elif "rampart-ask-marker" in command:
            body = {
                "decision": "ask",
                "message": "requires compatibility harness approval",
                "matched_policies": ["compat-ask"],
                "audit_id": "compat-audit-ask",
            }
        else:
            body = {
                "decision": "allow",
                "message": "allowed by compatibility harness",
                "audit_id": "compat-audit-allow",
            }

        encoded = json.dumps(body).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: Any) -> None:
        _ = (format, args)
        return


def _marker_from_command(command: str) -> str:
    for marker in ("rampart-deny-marker", "rampart-ask-marker", "rampart-allow-marker"):
        if marker in command:
            return marker
    return ""


def run(cmd: list[str], *, env: dict[str, str] | None = None, cwd: Path = REPO_ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )


def make_venv(root: Path, package: str) -> tuple[Path, Path]:
    venv_dir = root / "venv"
    venv.EnvBuilder(with_pip=True, clear=True).create(venv_dir)
    python = venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    hermes = venv_dir / ("Scripts/hermes.exe" if os.name == "nt" else "bin/hermes")
    run([str(python), "-m", "pip", "install", "--upgrade", "pip"], cwd=root)
    run([str(python), "-m", "pip", "install", package], cwd=root)
    return python, hermes


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
            'mutating_fail_closed': True,
            'configured_read_fail_open': True,
        }}, sort_keys=True))
        """
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Rampart's Hermes plugin against an isolated latest Hermes runtime.")
    parser.add_argument("--package", default="hermes-agent", help="pip package spec to install, default: hermes-agent")
    parser.add_argument("--hermes-python", help="Use an existing Python interpreter with Hermes installed instead of creating a venv")
    parser.add_argument("--hermes-bin", help="Hermes executable to report version from when --hermes-python is used")
    parser.add_argument("--keep-temp", action="store_true", help="Keep the temporary directory for debugging")
    args = parser.parse_args()

    temp = Path(tempfile.mkdtemp(prefix="rampart-hermes-compat-"))
    try:
        if args.hermes_python:
            hermes_python = Path(args.hermes_python).resolve()
            hermes_bin = Path(args.hermes_bin).resolve() if args.hermes_bin else shutil.which("hermes")
            hermes_bin_path = Path(hermes_bin) if hermes_bin else None
        else:
            hermes_python, hermes_bin_path = make_venv(temp, args.package)

        hermes_home = temp / "hermes-home"
        plugin_dir = hermes_home / "plugins" / "rampart"

        server = ThreadingHTTPServer(("127.0.0.1", 0), RampartStub)
        serve_url = f"http://127.0.0.1:{server.server_address[1]}"
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            write_hermes_config(hermes_home, serve_url)
            env = os.environ.copy()
            env.update(
                {
                    "HOME": str(temp / "home"),
                    "HERMES_HOME": str(hermes_home),
                    "RAMPART_TOKEN": "compat-test-token",
                    "RAMPART_HERMES_URL": serve_url,
                    "RAMPART_HERMES_TIMEOUT_MS": "1000",
                    "PYTHONWARNINGS": "ignore::DeprecationWarning",
                }
            )
            Path(env["HOME"]).mkdir(parents=True, exist_ok=True)

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
            markers = {entry["command_marker"] for entry in RampartStub.requests_seen}
            expected = {"rampart-deny-marker", "rampart-ask-marker", "rampart-allow-marker"}
            if not expected.issubset(markers):
                raise RuntimeError(f"expected request markers {sorted(expected)}, saw {sorted(markers)}")

            print(
                json.dumps(
                    {
                        "ok": True,
                        "hermes_version": hermes_version,
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
            shutil.rmtree(temp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
