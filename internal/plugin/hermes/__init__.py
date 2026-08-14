# Copyright 2026 The Rampart Authors
# Licensed under the Apache License, Version 2.0
"""Experimental Rampart policy gate for Hermes Agent.

The plugin is intentionally conservative:

* It uses Hermes' ``pre_tool_call`` hook and returns only host control
  directives: block, native approval, or no directive.
* It defaults to ``/v1/preflight/{tool}`` so Rampart does not create a second,
  hidden approval queue alongside Hermes' native approval UI.
* It passes Hermes' native ``tool_call_id`` as top-level Rampart metadata so
  Rampart audit IDs can be correlated with the exact Hermes tool call.
* On compatible Hermes installations, ``ask`` / ``require_approval`` decisions return
  Hermes' native ``approve`` directive so the host pauses and resumes the exact
  tool call. Older hosts that lack that directive fail closed with an upgrade
  message instead of silently executing the call.
* If Rampart serve is unavailable, every tool fails closed by default. Advanced
  operators may explicitly opt selected tools into degraded fail-open behavior.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import ipaddress
import inspect
import json
import logging
import os
import re
import socket
import textwrap
import unicodedata
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import quote, urlsplit

VERSION = "1.7.0"

DEFAULT_SERVE_URL = "http://127.0.0.1:9090"
DEFAULT_TIMEOUT_MS = 3000
DEFAULT_ENDPOINT_MODE = "preflight"
DEFAULT_AGENT_NAME = "hermes"
MAX_PATCH_PATHS = 100
MAX_RESPONSE_BYTES = 1024 * 1024
# Native approval keys are persisted by Hermes for session and "always"
# choices. Refuse unusually large, unrepresentable calls rather than doing
# unbounded serialization on the execution boundary.
MAX_APPROVAL_IDENTITY_BYTES = 64 * 1024
MAX_APPROVAL_IDENTITY_DEPTH = 32

# The default integration is an enforcement boundary, so service outages deny
# every tool. Advanced operators may explicitly opt selected read-only tools
# into degraded fail-open behavior, but Rampart does not assume a file read is
# harmless: it may target credentials or agent state.
DEFAULT_FAIL_OPEN_TOOLS: frozenset[str] = frozenset()

TOOL_MAP = {
    # Shell/code execution.
    "terminal": "exec",
    "execute_code": "exec",
    # File access.
    "read_file": "read",
    "search_files": "read",
    "write_file": "write",
    "patch": "edit",
    # Process/session control.
    "process": "process",
    "cronjob": "process",
    # Browser and web surfaces.
    "browser_back": "browser",
    "browser_cdp": "browser",
    "browser_click": "browser",
    "browser_console": "browser",
    "browser_dialog": "browser",
    "browser_get_images": "browser",
    "browser_navigate": "browser",
    "browser_press": "browser",
    "browser_scroll": "browser",
    "browser_snapshot": "browser",
    "browser_type": "browser",
    "browser_vision": "browser",
    "web_extract": "web_fetch",
    "web_fetch": "web_fetch",
    "web_search": "web_search",
    # Outbound messaging/media and agent state.
    "send_message": "message",
    "text_to_speech": "message",
    "memory": "write",
    "todo": "write",
    # Images/vision.
    "vision_analyze": "image",
}
SUPPORTED_HERMES_TOOLS = frozenset(TOOL_MAP)

SENSITIVE_KEY_MARKERS = (
    "token",
    "secret",
    "password",
    "authorization",
    "api_key",
    "apikey",
    "private_key",
)

_APPROVAL_REDACTIONS = (
    # Quoted JSON/YAML keys need their own rule: the quote between the key and
    # colon prevents the generic assignment rules below from seeing them.
    # Keep this display-only and deliberately conservative; the exact original
    # arguments remain available to policy evaluation and the HMAC identity.
    (
        re.compile(
            r'''(?ix)
            (
              ["']
              [a-z0-9_.-]*
              (?:api[-_]?key|apikey|authorization|auth(?:orization)?[-_]?token|access[-_]?token|
                 access[-_]?key|token|secret|password|passwd|credentials?|private[-_]?key)
              [a-z0-9_.-]*
              ["']\s*:\s*
            )
            (?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,}\]]+)
            '''
        ),
        r"\1[REDACTED]",
    ),
    # Shell environment assignments, including AWS_SECRET_ACCESS_KEY,
    # OPENAI_API_KEY, and GITHUB_TOKEN. At this display edge, a value that
    # merely looks secret is treated exactly like a credential.
    (
        re.compile(
            r"(?i)(\b[A-Z][A-Z0-9_]*(?:API_KEY|APIKEY|TOKEN|SECRET|PASSWORD|PASSWD|ACCESS_KEY|CREDENTIALS?)\s*=\s*)(?:\"[^\"]*\"|'[^']*'|[^\s;|&]+)"
        ),
        r"\1[REDACTED]",
    ),
    # Common secret-bearing flags and HTTP header forms. Header values may be
    # quoted as curl arguments, so stop before either quote as well as space.
    (
        re.compile(
            r"(?i)(--(?:api[-_]?key|auth(?:orization)?[-_]?token|access[-_]?token|password|token|secret|user)(?:=|\s+))(?:\"[^\"]*\"|'[^']*'|[^\s]+)"
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)((?:proxy[-_])?authorization\s*[:=]\s*(?:(?:bearer|basic|token)\s+)?)(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)((?:x[-_])?(?:api[-_]?key|auth[-_]?token|access[-_]?token)\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)(\b(?:api[-_]?key|auth(?:orization)?[-_]?token|access[-_]?token|password|token|secret)\b\s*[=:]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s&]+)"
        ),
        r"\1[REDACTED]",
    ),
    # curl's short form has no key name to trigger the assignment rules, and
    # curl accepts both "-u user:pass" and the attached "-uuser:pass" form.
    (
        re.compile(r"(?i)((?:^|\s)-u)(?:\s+|(?=[^\s]))(?:\"[^\"]*\"|'[^']*'|[^\s]+)"),
        r"\1 [REDACTED]",
    ),
    # Shell tools also accept URL-like credential userinfo without a scheme,
    # for example ``ssh user:password@host``. It is not found by urlsplit or
    # the ``//userinfo@`` rule, so hide the entire userinfo component here.
    (
        re.compile(r"(?i)(?<![a-z0-9])[^\s/:@]+:[^\s/@]+@(?=[a-z0-9.\[\]-])"),
        "[REDACTED]@",
    ),
    (re.compile(r"(?i)(//)[^/\s@]+@"), r"\1[REDACTED]@"),
    (re.compile(r"\b(?:gh[opurs]_[A-Za-z0-9]+|xox[aboprs]-[A-Za-z0-9-]+|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b"), "[REDACTED]"),
)
_URL_REFERENCE = re.compile(
    r"(?i)\b(?:[a-z][a-z0-9+.-]*://|(?:mailto|data|urn):)[^\s<>'\"]+"
)
_ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)?)?")

logger = logging.getLogger(__name__)


class RampartUnavailable(RuntimeError):
    """Rampart serve could not be reached or returned a server-side failure."""


class RampartInvalidResponse(RuntimeError):
    """Rampart configuration or response is invalid and must fail closed."""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Keep policy credentials bound to the configured control endpoint."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


# Rampart's managed Hermes integration accepts loopback policy endpoints only.
# Do not let ambient HTTP(S)_PROXY settings turn that direct local boundary into
# a credential-bearing request to another process or host.
_NO_REDIRECT_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    _NoRedirectHandler(),
)


@dataclass(frozen=True)
class PluginConfig:
    serve_url: str = DEFAULT_SERVE_URL
    timeout_ms: int = DEFAULT_TIMEOUT_MS
    endpoint_mode: str = DEFAULT_ENDPOINT_MODE
    fail_open_tools: frozenset[str] = DEFAULT_FAIL_OPEN_TOOLS
    token_path: Path = Path.home() / ".rampart" / "token"
    agent_name: str = DEFAULT_AGENT_NAME

    @property
    def timeout_seconds(self) -> float:
        return max(0.1, self.timeout_ms / 1000.0)


def _load_hermes_plugin_config() -> dict[str, Any]:
    """Load plugins.entries.rampart.config from Hermes if available.

    Tests and static inspection should not require Hermes to be installed, so all
    imports are intentionally local and fail closed to an empty config.
    """

    try:
        from hermes_cli.config import cfg_get, load_config  # type: ignore

        raw = cfg_get(load_config(), "plugins", "entries", "rampart", "config", default={})
        return raw if isinstance(raw, dict) else {}
    except Exception:
        return {}


def _first_present(config: Mapping[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in config:
            return config[key]
    return default


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def load_config(overrides: Mapping[str, Any] | None = None) -> PluginConfig:
    """Resolve plugin config from Hermes config, optional overrides, and env."""

    raw: dict[str, Any] = dict(_load_hermes_plugin_config())
    if overrides:
        raw.update(dict(overrides))

    serve_url = os.getenv("RAMPART_HERMES_URL") or os.getenv("RAMPART_URL") or os.getenv("RAMPART_SERVE_URL") or _first_present(
        raw, "serve_url", "serveUrl", "url", default=DEFAULT_SERVE_URL
    )
    if not isinstance(serve_url, str) or not serve_url.strip():
        serve_url = DEFAULT_SERVE_URL
    serve_url = serve_url.rstrip("/")

    timeout_raw = os.getenv("RAMPART_HERMES_TIMEOUT_MS") or _first_present(
        raw, "timeout_ms", "timeoutMs", default=DEFAULT_TIMEOUT_MS
    )
    try:
        timeout_ms = int(timeout_raw)
    except (TypeError, ValueError):
        timeout_ms = DEFAULT_TIMEOUT_MS
    timeout_ms = min(max(timeout_ms, 100), 30_000)

    endpoint_mode = os.getenv("RAMPART_HERMES_ENDPOINT_MODE") or _first_present(
        raw, "endpoint_mode", "endpointMode", default=DEFAULT_ENDPOINT_MODE
    )
    if not isinstance(endpoint_mode, str):
        endpoint_mode = DEFAULT_ENDPOINT_MODE
    endpoint_mode = endpoint_mode.strip().lower()
    if endpoint_mode not in {"preflight", "tool"}:
        endpoint_mode = DEFAULT_ENDPOINT_MODE

    fail_open_raw = os.getenv("RAMPART_HERMES_FAIL_OPEN_TOOLS")
    if fail_open_raw is not None:
        fail_open_tools = frozenset(_split_csv(fail_open_raw))
    else:
        configured = _first_present(raw, "fail_open_tools", "failOpenTools", default=None)
        if isinstance(configured, str):
            fail_open_tools = frozenset(_split_csv(configured))
        elif isinstance(configured, (list, tuple, set)):
            fail_open_tools = frozenset(str(item) for item in configured if str(item).strip())
        else:
            fail_open_tools = DEFAULT_FAIL_OPEN_TOOLS

    token_path_raw = os.getenv("RAMPART_HERMES_TOKEN_PATH") or _first_present(
        raw, "token_path", "tokenPath", default=str(Path.home() / ".rampart" / "token")
    )
    token_path = Path(str(token_path_raw)).expanduser()

    agent_name = os.getenv("RAMPART_HERMES_AGENT") or _first_present(
        raw, "agent", "agent_name", "agentName", default=DEFAULT_AGENT_NAME
    )
    if not isinstance(agent_name, str) or not agent_name.strip():
        agent_name = DEFAULT_AGENT_NAME

    return PluginConfig(
        serve_url=serve_url,
        timeout_ms=timeout_ms,
        endpoint_mode=endpoint_mode,
        fail_open_tools=fail_open_tools,
        token_path=token_path,
        agent_name=agent_name,
    )


def _load_token(config: PluginConfig) -> str | None:
    env_token = os.getenv("RAMPART_TOKEN")
    if env_token:
        return env_token.strip()
    try:
        token = config.token_path.read_text(encoding="utf-8").strip()
        return token or None
    except OSError:
        return None


def _preview(value: Any, max_chars: int = 240) -> str | None:
    if value is None:
        return None
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    if not text:
        return None
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 1].rstrip() + "…"


def _clean_approval_display(value: Any) -> str | None:
    """Remove formatting characters that could change prompt interpretation."""

    if value is None:
        return None
    # Approval messages are rendered by Hermes. Remove ANSI, C0/C1 control,
    # and Unicode format characters (including bidi overrides) before any
    # human-facing truncation or redaction so a policy response cannot spoof
    # another action or conceal a credential in the prompt.
    text = _ANSI_ESCAPE.sub("�", str(value))
    text = "".join(
        " " if char in "\r\n\t" else "�"
        if unicodedata.category(char) in {"Cc", "Cf", "Cs"}
        else char
        for char in text
    )
    return " ".join(text.split()) or None


def _redact_approval_text(value: Any, max_chars: int = 240) -> str | None:
    """Return a one-line human summary without common credential material."""

    text = _clean_approval_display(value)
    if text is None:
        return None
    if len(text) > max_chars * 4:
        text = text[: max_chars * 4]
    text = _URL_REFERENCE.sub(_redact_url_reference, text)
    for pattern, replacement in _APPROVAL_REDACTIONS:
        text = pattern.sub(replacement, text)
    return _preview(text, max_chars)


def _redact_url_reference(match: re.Match[str]) -> str:
    """Replace an embedded URL with the same conservative approval display."""

    return _safe_url_display(match.group(0))


def _safe_url_display(value: Any) -> str:
    """Render only an HTTP(S) origin for approval UI."""

    if not isinstance(value, str) or not value.strip():
        return "<missing URL>"
    # Apply character handling before urlsplit; it otherwise accepts some
    # leading controls and can render a different-looking target than Hermes.
    cleaned = _clean_approval_display(value)
    if cleaned is None:
        return "<missing URL>"
    try:
        parsed = urlsplit(cleaned)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return "<invalid URL>"
    if parsed.scheme in {"http", "https"} and hostname:
        display_host = f"[{hostname}]" if ":" in hostname else hostname
        origin = f"{parsed.scheme}://{display_host}"
        if port is not None:
            origin += f":{port}"
        # Paths, queries, and fragments commonly contain signed object names,
        # reset tokens, and private resource IDs. The exact URL stays in the
        # HMAC-bound identity; no part beyond the origin reaches the prompt.
        return origin
    if parsed.scheme:
        return f"<non-HTTP URL ({parsed.scheme.lower()}) redacted>"
    return "<invalid URL>"


def _approval_action_summary(
    tool_name: str,
    rampart_tool: str,
    args: Mapping[str, Any] | None,
    resolved_params: Mapping[str, Any],
) -> str:
    """Describe the represented action without exposing content-bearing fields."""

    raw_args = args if isinstance(args, Mapping) else {}
    if tool_name == "terminal":
        command = _redact_approval_text(raw_args.get("command"), 240)
        return f"terminal command: {command or '<missing command>'}"
    if tool_name.startswith("browser_"):
        action = tool_name.removeprefix("browser_") or "action"
        if "url" in raw_args:
            return f"browser {action}: {_safe_url_display(raw_args.get('url'))}"
        ref = _redact_approval_text(raw_args.get("ref"), 80)
        return f"browser {action}" + (f" target {ref}" if ref else "")
    if rampart_tool in {"read", "write", "edit"}:
        paths = resolved_params.get("touched_paths")
        if isinstance(paths, list) and paths:
            shown = [(_redact_approval_text(path, 100) or "<invalid path>") for path in paths[:3]]
            suffix = f" (+{len(paths) - 3} more)" if len(paths) > 3 else ""
            return f"{rampart_tool} paths: {', '.join(shown)}{suffix}"
        path = _redact_approval_text(resolved_params.get("path"), 180)
        return f"{rampart_tool} path: {path or '<missing path>'}"
    if rampart_tool in {"fetch", "web_fetch"}:
        return f"{rampart_tool}: {_safe_url_display(raw_args.get('url'))}"
    if rampart_tool == "message":
        target = _redact_approval_text(raw_args.get("target"), 120)
        return f"message target: {target or '<unspecified>'}"
    action = _redact_approval_text(resolved_params.get("action"), 80)
    return f"{tool_name}" + (f" action: {action}" if action else "")


def _byte_len(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, bytes):
        return len(value)
    return len(str(value).encode("utf-8"))


def _line_count(value: Any) -> int:
    if value is None:
        return 0
    return len(str(value).splitlines())


def _safe_scalar(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, Mapping):
        return f"<mapping keys={len(value)}>"
    if isinstance(value, (list, tuple, set, frozenset)):
        return f"<sequence items={len(value)}>"
    return f"<{type(value).__name__}>"


def _generic_metadata(args: Mapping[str, Any]) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    for key, value in args.items():
        lower = str(key).lower()
        if any(marker in lower for marker in SENSITIVE_KEY_MARKERS):
            metadata[key] = "<redacted>"
        elif lower in {"content", "data", "text", "message", "prompt", "old_string", "new_string", "patch"}:
            metadata[f"{key}_bytes"] = _byte_len(value)
            if lower in {"message", "prompt"}:
                metadata[f"{key}_preview"] = _preview(value, 120)
        else:
            metadata[key] = _safe_scalar(value)
    return metadata


def _patch_touched_paths(patch_text: Any) -> list[str]:
    if not isinstance(patch_text, str):
        return []
    paths: list[str] = []
    for line in patch_text.splitlines():
        if (
            line.startswith("*** Update File: ")
            or line.startswith("*** Add File: ")
            or line.startswith("*** Delete File: ")
            or line.startswith("*** Move to: ")
        ):
            path = line.split(": ", 1)[1].strip()
            if path and path not in paths:
                paths.append(path)
                # Preserve one over the limit so evaluation can fail closed
                # instead of silently ignoring a later protected target.
                if len(paths) > MAX_PATCH_PATHS:
                    break
    return paths


def normalize_tool_call(tool_name: str, args: Mapping[str, Any] | None) -> tuple[str, dict[str, Any]]:
    """Map a Hermes tool call to a Rampart tool class with sanitized params."""

    original_tool = tool_name if isinstance(tool_name, str) and tool_name else "unknown"
    raw_args: Mapping[str, Any] = args if isinstance(args, Mapping) else {}
    rampart_tool = TOOL_MAP.get(original_tool, original_tool)

    params: dict[str, Any]
    if original_tool == "terminal":
        params = {
            "command": raw_args.get("command", ""),
            "workdir": raw_args.get("workdir"),
            "timeout": raw_args.get("timeout"),
            "background": bool(raw_args.get("background", False)),
            "pty": bool(raw_args.get("pty", False)),
            "notify_on_complete": bool(raw_args.get("notify_on_complete", False)),
        }
        if raw_args.get("watch_patterns"):
            params["watch_patterns_count"] = len(raw_args.get("watch_patterns") or [])
    elif original_tool == "execute_code":
        code = raw_args.get("code", "")
        params = {
            "command": "python execute_code",
            "script_preview": _preview(code, 240),
            "script_bytes": _byte_len(code),
            "script_lines": _line_count(code),
        }
    elif original_tool == "read_file":
        params = {
            "path": raw_args.get("path", ""),
            "offset": raw_args.get("offset"),
            "limit": raw_args.get("limit"),
        }
    elif original_tool == "search_files":
        params = {
            "path": raw_args.get("path", "."),
            "pattern": raw_args.get("pattern", ""),
            "target": raw_args.get("target", "content"),
            "file_glob": raw_args.get("file_glob"),
            "output_mode": raw_args.get("output_mode"),
            "limit": raw_args.get("limit"),
            "offset": raw_args.get("offset"),
        }
    elif original_tool == "write_file":
        content = raw_args.get("content", "")
        params = {
            "path": raw_args.get("path", ""),
            "content_bytes": _byte_len(content),
            "content_lines": _line_count(content),
        }
    elif original_tool == "patch":
        mode = raw_args.get("mode", "replace")
        patch_text = raw_args.get("patch", "")
        params = {
            "mode": mode,
            "path": raw_args.get("path"),
            "replace_all": bool(raw_args.get("replace_all", False)),
            "old_string_bytes": _byte_len(raw_args.get("old_string")),
            "new_string_bytes": _byte_len(raw_args.get("new_string")),
            "patch_bytes": _byte_len(patch_text),
            "touched_paths": _patch_touched_paths(patch_text),
        }
    elif original_tool.startswith("browser_"):
        action = original_tool.removeprefix("browser_")
        params = {
            "action": action,
            "url": raw_args.get("url"),
            "ref": raw_args.get("ref"),
            "key": raw_args.get("key"),
            "direction": raw_args.get("direction"),
            "expression_preview": _preview(raw_args.get("expression"), 200),
            "text_bytes": _byte_len(raw_args.get("text")) if "text" in raw_args else None,
        }
    elif original_tool == "process":
        params = {
            "action": raw_args.get("action"),
            "session_id": raw_args.get("session_id"),
            "timeout": raw_args.get("timeout"),
            "data_bytes": _byte_len(raw_args.get("data")) if "data" in raw_args else None,
        }
    elif original_tool == "cronjob":
        prompt = raw_args.get("prompt", "")
        params = {
            "action": raw_args.get("action"),
            "job_id": raw_args.get("job_id"),
            "schedule": raw_args.get("schedule"),
            "name": raw_args.get("name"),
            "prompt_bytes": _byte_len(prompt),
            "prompt_preview": _preview(prompt, 120),
            "no_agent": bool(raw_args.get("no_agent", False)),
        }
    elif original_tool == "send_message":
        message = raw_args.get("message", "")
        params = {
            "action": raw_args.get("action", "send"),
            "target": raw_args.get("target"),
            "message_bytes": _byte_len(message),
            "message_preview": _preview(message, 120),
            "has_media": "MEDIA:" in message if isinstance(message, str) else False,
        }
    elif original_tool == "memory":
        params = {
            "action": raw_args.get("action"),
            "target": raw_args.get("target"),
            "content_bytes": _byte_len(raw_args.get("content")) if "content" in raw_args else None,
        }
    else:
        params = _generic_metadata(raw_args)

    params = {key: value for key, value in params.items() if value is not None}
    params["hermes_tool"] = original_tool
    params["rampart_tool"] = rampart_tool
    return rampart_tool, params


def _resolve_hermes_path(path: Any, task_id: str) -> str:
    """Resolve a policy path through Hermes' own task-CWD path pipeline."""

    if not isinstance(path, str) or not path.strip():
        return ""
    try:
        # Hermes file tools use this helper immediately before filesystem I/O.
        # Import lazily so Rampart's static/unit tests do not require Hermes.
        from tools.file_tools import _resolve_path_for_task  # type: ignore

        return str(_resolve_path_for_task(path, task_id or "default"))
    except ImportError:
        # Standalone tests and source inspection run without Hermes installed.
        # Honor its documented terminal CWD fallback when one is available;
        # otherwise preserve the path for compatibility with direct unit calls.
        base = os.getenv("TERMINAL_CWD", "").strip()
        if base and not Path(path).expanduser().is_absolute():
            return str((Path(base).expanduser() / path).resolve(strict=False))
        if Path(path).expanduser().is_absolute():
            return str(Path(path).expanduser().resolve(strict=False))
        return path


def _resolve_policy_paths(
    rampart_tool: str,
    params: Mapping[str, Any],
    task_id: str,
) -> dict[str, Any]:
    resolved = dict(params)
    if rampart_tool not in {"read", "write", "edit"}:
        return resolved

    touched_paths = resolved.get("touched_paths")
    if isinstance(touched_paths, list) and touched_paths:
        resolved_paths = [_resolve_hermes_path(path, task_id) for path in touched_paths]
        if any(not path for path in resolved_paths):
            raise ValueError("Hermes supplied an invalid patch target")
        resolved["touched_paths"] = resolved_paths
        resolved["path"] = resolved_paths[0]
        return resolved

    path = _resolve_hermes_path(resolved.get("path"), task_id)
    if not path:
        raise ValueError("Hermes supplied a file tool without a valid path")
    resolved["path"] = path
    return resolved


def _build_payload(
    config: PluginConfig,
    params: Mapping[str, Any],
    *,
    session_id: str = "",
    task_id: str = "",
    tool_call_id: str = "",
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "agent": config.agent_name,
        "session": session_id or "",
        "run_id": task_id or "",
        "params": dict(params),
    }
    if tool_call_id:
        payload["tool_call_id"] = tool_call_id
    if config.endpoint_mode == "preflight":
        # Hermes calls this hook at the actual execution boundary. Tell Rampart
        # to consume once:true grants and record call_count state while retaining
        # preflight's no-hidden-approval behavior.
        payload["enforce"] = True
    return payload


def _endpoint_url(config: PluginConfig, rampart_tool: str) -> str:
    endpoint = "tool" if config.endpoint_mode == "tool" else "preflight"
    return f"{config.serve_url}/v1/{endpoint}/{quote(rampart_tool, safe='')}"


def _is_trusted_serve_url(value: str) -> bool:
    """Return true only for loopback HTTP(S) policy endpoints."""

    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            return False
        hostname = (parsed.hostname or "").rstrip(".").lower()
        # Force port parsing now so malformed values cannot reach urlopen.
        _ = parsed.port
        if hostname == "localhost":
            return True
        return ipaddress.ip_address(hostname).is_loopback
    except (ValueError, TypeError):
        return False


def _decode_http_error(exc: urllib.error.HTTPError) -> dict[str, Any]:
    raw_body = exc.read(MAX_RESPONSE_BYTES + 1)
    if len(raw_body) > MAX_RESPONSE_BYTES:
        return {
            "decision": "deny",
            "allowed": False,
            "message": "Rampart error response exceeded the size limit",
        }
    body = raw_body.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(body) if body else {}
    except json.JSONDecodeError:
        parsed = {}
    if isinstance(parsed, dict):
        message = parsed.get("message") or parsed.get("error") or body or f"Rampart returned HTTP {exc.code}"
        parsed["decision"] = "deny"
        parsed["allowed"] = False
        parsed["message"] = str(message)
        return parsed
    return {"decision": "deny", "allowed": False, "message": body or f"Rampart returned HTTP {exc.code}"}


def post_to_rampart(config: PluginConfig, rampart_tool: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    if not _is_trusted_serve_url(config.serve_url):
        raise RampartInvalidResponse("Rampart serve URL must use a loopback HTTP(S) address")
    token = _load_token(config)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(
        _endpoint_url(config, rampart_tool),
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with _NO_REDIRECT_OPENER.open(request, timeout=config.timeout_seconds) as response:
            raw_data = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw_data) > MAX_RESPONSE_BYTES:
                raise RampartInvalidResponse("Rampart response exceeded the size limit")
            data = raw_data.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        try:
            if 400 <= exc.code < 500:
                return _decode_http_error(exc)
            if 300 <= exc.code < 400:
                raise RampartInvalidResponse(
                    f"Rampart refused redirect response HTTP {exc.code}"
                ) from exc
            raise RampartUnavailable(f"Rampart returned HTTP {exc.code}") from exc
        finally:
            if exc.fp is not None:
                exc.close()
    except (urllib.error.URLError, TimeoutError, socket.timeout, OSError) as exc:
        raise RampartUnavailable(str(exc)) from exc

    try:
        parsed = json.loads(data) if data else {}
    except json.JSONDecodeError as exc:
        raise RampartInvalidResponse("Rampart returned invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise RampartInvalidResponse("Rampart returned non-object JSON")
    return parsed


def _block(message: str) -> dict[str, str]:
    return {"action": "block", "message": message}


def _hermes_supports_native_approval() -> bool:
    """Return whether this Hermes runtime owns plugin approval/resume.

    Older Hermes releases understand only ``action=block``. Returning a newer
    directive to one of those hosts could be ignored and fail open, so feature
    detection is a security boundary rather than a convenience check.
    """

    try:
        import hermes_cli.plugins as hermes_plugins  # type: ignore
    except (ImportError, AttributeError):
        return False

    directive_type = getattr(hermes_plugins, "_PreToolCallDirective", None)
    directive_fields = getattr(directive_type, "__dataclass_fields__", {})
    public_getter = getattr(hermes_plugins, "get_pre_tool_call_directive", None)
    details_getter = getattr(
        hermes_plugins, "_get_pre_tool_call_directive_details", None
    )
    resolver = getattr(hermes_plugins, "resolve_pre_tool_block", None)
    if not (
        callable(public_getter)
        and callable(details_getter)
        and callable(resolver)
        and "rule_key" in directive_fields
    ):
        return False

    # A field on the directive alone is not a capability guarantee. Prove the
    # two released-v2026.8.3 data-flow legs from installed source: the private
    # dispatcher copies the hook's ``result["rule_key"]`` into the directive,
    # and the resolver supplies ``details.rule_key`` to the approval gate. If
    # source is unavailable or a future host delegates this differently, fail
    # closed until that contract is reviewed instead of guessing from names.
    try:
        details_tree = ast.parse(textwrap.dedent(inspect.getsource(details_getter)))
        resolver_tree = ast.parse(textwrap.dedent(inspect.getsource(resolver)))
    except (OSError, TypeError, SyntaxError, IndentationError):
        return False

    def call_name(node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""

    result_rule_key_is_captured = any(
        isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "rule_key"
            for target in node.targets
        )
        and any(
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Attribute)
            and child.func.attr == "get"
            and child.args
            and isinstance(child.args[0], ast.Constant)
            and child.args[0].value == "rule_key"
            for child in ast.walk(node.value)
        )
        for node in ast.walk(details_tree)
    )
    captured_rule_key_reaches_directive = any(
        isinstance(node, ast.Call)
        and call_name(node) == "_PreToolCallDirective"
        and any(
            keyword.arg == "rule_key"
            and isinstance(keyword.value, ast.Name)
            and keyword.value.id == "rule_key"
            for keyword in node.keywords
        )
        for node in ast.walk(details_tree)
    )
    resolver_loads_same_details = any(
        isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "details"
            for target in node.targets
        )
        and isinstance(node.value, ast.Call)
        and call_name(node.value) == "_get_pre_tool_call_directive_details"
        for node in ast.walk(resolver_tree)
    )
    details_rule_key_reaches_gate = any(
        isinstance(node, ast.Call)
        and call_name(node) == "request_tool_approval"
        and any(
            keyword.arg == "rule_key"
            and any(
                isinstance(child, ast.Attribute)
                and isinstance(child.value, ast.Name)
                and child.value.id == "details"
                and child.attr == "rule_key"
                for child in ast.walk(keyword.value)
            )
            for keyword in node.keywords
        )
        for node in ast.walk(resolver_tree)
    )
    return (
        result_rule_key_is_captured
        and captured_rule_key_reaches_directive
        and resolver_loads_same_details
        and details_rule_key_reaches_gate
    )


def _effective_terminal_cwd(task_id: str) -> str | None:
    """Mirror Hermes' no-workdir CWD resolution for approval identity."""

    try:
        import tools.terminal_tool as hermes_terminal  # type: ignore
        from tools.approval import get_current_session_key  # type: ignore

        get_config = getattr(hermes_terminal, "_get_env_config")
        resolve_overrides = getattr(hermes_terminal, "resolve_task_overrides")
        get_session_cwd = getattr(hermes_terminal, "get_session_cwd")
        resolve_cwd = getattr(hermes_terminal, "_resolve_command_cwd")
        container_backends = getattr(hermes_terminal, "_CONTAINER_BACKENDS")
        unusable_container_cwd = getattr(
            hermes_terminal, "_is_unusable_container_cwd"
        )
        if not all(
            callable(item)
            for item in (
                get_config,
                resolve_overrides,
                get_session_cwd,
                resolve_cwd,
                unusable_container_cwd,
                get_current_session_key,
            )
        ):
            return None

        config = get_config()
        overrides = resolve_overrides(task_id)
        if not isinstance(config, Mapping) or not isinstance(overrides, Mapping):
            return None
        env_type = config.get("env_type")
        cwd = overrides.get("cwd") or get_session_cwd(task_id) or config.get("cwd")
        if not isinstance(env_type, str) or not isinstance(cwd, str) or not cwd:
            return None
        if env_type in container_backends and unusable_container_cwd(cwd):
            cwd = config.get("cwd")
            if not isinstance(cwd, str) or not cwd:
                return None
        session_key = get_current_session_key(default="") or (task_id or "")
        effective_cwd = resolve_cwd(
            workdir=None,
            default_cwd=cwd,
            session_key=session_key,
        )
    except (ImportError, AttributeError, KeyError, OSError, TypeError, ValueError):
        return None
    return effective_cwd if isinstance(effective_cwd, str) and effective_cwd else None


def _approval_rule_key(
    config: PluginConfig,
    tool_name: str,
    args: Mapping[str, Any] | None,
    resolved_params: Mapping[str, Any],
    task_id: str,
) -> str | None:
    """Bind Hermes session/always approval to one exact represented call.

    Hermes uses ``rule_key`` as the persistence grain for native approval.
    Bind both the original arguments and Rampart's resolved policy identity so
    an approval for a relative file path cannot follow the same spelling into a
    different task directory. HMAC makes the persisted key opaque: raw command
    arguments and file contents are never written to Hermes configuration.

    A token is required for this persistent identity. A local policy service
    without one can still allow or deny, but an ``ask`` fails closed rather than
    storing a plain, dictionary-attackable digest of sensitive arguments.
    """

    token = _load_token(config)
    if not token:
        return None
    token_bytes = token.encode("utf-8")
    if len(token_bytes) > 4096:
        return None
    identity = {
        "tool": tool_name,
        "args": args or {},
        "resolved_params": resolved_params,
        # Relative terminal/file semantics depend on the task workspace. A
        # session or persistent approval must not silently cross that boundary.
        "task_id": task_id,
    }
    if tool_name == "terminal":
        raw_args = args if isinstance(args, Mapping) else {}
        workdir = raw_args.get("workdir")
        if workdir:
            # Hermes passes an explicit relative workdir through to the
            # execution backend, where its meaning depends on mutable ambient
            # state. Native persistent approval cannot safely key that call by
            # spelling alone. Accept only an absolute path on this platform.
            if not isinstance(workdir, str) or not os.path.isabs(workdir):
                return None
            terminal_cwd = workdir
        else:
            # Hermes treats a missing/empty workdir as the mutable session CWD.
            # Bind the same effective value its terminal dispatcher will use.
            # If host internals cannot resolve it exactly, do not mint a key
            # that Hermes could persist across a different directory.
            if workdir is not None and workdir != "":
                return None
            terminal_cwd = _effective_terminal_cwd(task_id)
            if terminal_cwd is None:
                return None
        identity["effective_terminal_cwd"] = terminal_cwd
    if not _approval_identity_within_bounds(identity):
        return None
    try:
        encoded = json.dumps(
            identity,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        return None
    if len(encoded) > MAX_APPROVAL_IDENTITY_BYTES:
        return None
    digest = hmac.new(token_bytes, encoded, hashlib.sha256).hexdigest()
    return f"rampart:{tool_name}:{digest}"


def _approval_identity_within_bounds(value: Any) -> bool:
    """Bound approval-key work before JSON serialization copies tool input."""

    remaining = MAX_APPROVAL_IDENTITY_BYTES
    stack: list[tuple[Any, int]] = [(value, 0)]
    seen: set[int] = set()
    while stack:
        current, depth = stack.pop()
        if depth > MAX_APPROVAL_IDENTITY_DEPTH:
            return False
        if current is None or isinstance(current, (bool, float)):
            remaining -= len(str(current))
        elif isinstance(current, int):
            # Avoid converting an attacker-controlled arbitrary-precision
            # integer to a potentially enormous decimal string just to reject
            # it. The bit bound is conservative relative to the byte budget.
            if current.bit_length() > max(remaining, 0) * 4:
                return False
            try:
                remaining -= len(str(current))
            except ValueError:
                return False
        elif isinstance(current, str):
            if len(current) > remaining:
                return False
            remaining -= len(current.encode("utf-8"))
        elif isinstance(current, Mapping):
            identity = id(current)
            if identity in seen:
                return False
            seen.add(identity)
            remaining -= len(current) * 2
            for key, item in current.items():
                if not isinstance(key, str):
                    return False
                stack.append((key, depth + 1))
                stack.append((item, depth + 1))
        elif isinstance(current, (list, tuple)):
            identity = id(current)
            if identity in seen:
                return False
            seen.add(identity)
            remaining -= len(current)
            stack.extend((item, depth + 1) for item in current)
        else:
            return False
        if remaining < 0:
            return False
    return True


def _decision_from_result(result: Mapping[str, Any]) -> str:
    decision = result.get("decision")
    if result.get("error"):
        return "deny"
    allowed = result.get("allowed")
    if not isinstance(allowed, bool):
        return "deny"
    if not isinstance(decision, str):
        return "deny"
    decision = decision.strip().lower()
    if decision not in {"allow", "watch", "log", "ask", "require_approval", "deny"}:
        return "deny"
    # A contradictory response is not a valid authorization. This also keeps a
    # malformed/partially upgraded local service from accidentally failing open.
    if allowed != (decision in {"allow", "watch", "log"}):
        return "deny"
    return decision


def _decision_rank(result: Mapping[str, Any]) -> int:
    decision = _decision_from_result(result)
    if decision == "deny":
        return 3
    if decision in {"ask", "require_approval"}:
        return 2
    if decision in {"allow", "watch", "log"}:
        return 1
    # Unknown service decisions are treated as blocking, so rank them with deny.
    return 3


def _policy_param_variants(rampart_tool: str, params: Mapping[str, Any]) -> list[dict[str, Any]]:
    touched_paths = params.get("touched_paths")
    if rampart_tool != "edit" or not isinstance(touched_paths, list) or not touched_paths:
        return [dict(params)]
    variants: list[dict[str, Any]] = []
    for path in touched_paths:
        variant = dict(params)
        variant["path"] = path
        variants.append(variant)
    return variants


def _audit_suffix(result: Mapping[str, Any]) -> str:
    audit_id = _redact_approval_text(result.get("audit_id"), 120)
    if audit_id:
        return f" [audit_id: {audit_id}]"
    return ""


def evaluate_pre_tool_call(
    tool_name: str,
    args: Mapping[str, Any] | None,
    *,
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    config_overrides: Mapping[str, Any] | None = None,
    requester: Callable[[PluginConfig, str, Mapping[str, Any]], Mapping[str, Any]] | None = None,
) -> dict[str, str] | None:
    """Evaluate a Hermes tool call and return a Hermes control directive or None."""

    if not isinstance(tool_name, str) or tool_name not in SUPPORTED_HERMES_TOOLS:
        display_name = tool_name if isinstance(tool_name, str) and tool_name else "unknown"
        return _block(
            f"rampart: unsupported Hermes tool {display_name} — update Rampart or add a typed integration before using this capability"
        )

    config = load_config(config_overrides)
    rampart_tool, params = normalize_tool_call(tool_name, args)
    params = _resolve_policy_paths(rampart_tool, params, task_id)
    caller = requester or post_to_rampart

    touched_paths = params.get("touched_paths")
    if isinstance(touched_paths, list) and len(touched_paths) > MAX_PATCH_PATHS:
        return _block(
            f"rampart: patch touches more than {MAX_PATCH_PATHS} paths — refusing batched edit until it is split into smaller calls"
        )

    result: Mapping[str, Any] = {"decision": "allow", "allowed": True}
    selected_rank = 0
    for policy_params in _policy_param_variants(rampart_tool, params):
        payload = _build_payload(
            config,
            policy_params,
            session_id=session_id,
            task_id=task_id,
            tool_call_id=tool_call_id,
        )
        try:
            candidate = caller(config, rampart_tool, payload)
        except RampartInvalidResponse:
            return _block("rampart: invalid policy response — refusing tool call")
        except RampartUnavailable:
            if tool_name in config.fail_open_tools or rampart_tool in config.fail_open_tools:
                logger.warning("Rampart unavailable for %s/%s; configured fail-open", tool_name, rampart_tool)
                continue
            return _block(
                f"rampart: unavailable ({tool_name}→{rampart_tool}) — policy service could not be reached; refusing sensitive tool call"
            )
        if not isinstance(candidate, Mapping):
            return _block("rampart: invalid policy response — refusing tool call")
        rank = _decision_rank(candidate)
        if rank > selected_rank:
            result = candidate
            selected_rank = rank
        if _decision_from_result(candidate) == "deny":
            break

    decision = _decision_from_result(result)
    if decision in {"allow", "watch", "log"}:
        return None

    reason = _redact_approval_text(
        result.get("message") or result.get("reason") or "policy violation",
        240,
    ) or "policy violation"
    policy = result.get("policy") or result.get("matched_policies")
    audit_suffix = _audit_suffix(result)
    policy_suffix = ""
    if isinstance(policy, str) and policy:
        policy_suffix = f" [policy: {_redact_approval_text(policy, 120) or '<redacted>'}]"
    elif isinstance(policy, list) and policy:
        policy_suffix = f" [policy: {_redact_approval_text(policy[0], 120) or '<redacted>'}]"

    if decision in {"ask", "require_approval"}:
        action_summary = _approval_action_summary(tool_name, rampart_tool, args, params)
        message = (
            "rampart: approval required"
            f" for {tool_name}→{rampart_tool}{policy_suffix}{audit_suffix} — {reason}. "
            f"Action: {action_summary}."
        )
        if not _hermes_supports_native_approval():
            return _block(
                message
                + " This Hermes version does not support plugin-owned approval/resume; "
                "upgrade Hermes before retrying."
            )
        rule_key = _approval_rule_key(config, tool_name, args, params, task_id)
        if rule_key is None:
            return _block(
                message
                + " Rampart could not derive a non-secret approval key for the exact tool call."
            )
        return {"action": "approve", "message": message, "rule_key": rule_key}

    return _block(f"rampart: {reason}{policy_suffix}{audit_suffix}")


def register(ctx: Any) -> None:
    """Hermes plugin entrypoint."""

    def _pre_tool_call(
        tool_name: str,
        args: Mapping[str, Any] | None = None,
        task_id: str = "",
        session_id: str = "",
        tool_call_id: str = "",
        **_: Any,
    ) -> dict[str, str] | None:
        try:
            return evaluate_pre_tool_call(
                tool_name,
                args,
                task_id=task_id,
                session_id=session_id,
                tool_call_id=tool_call_id,
            )
        except Exception as exc:
            # Hermes currently skips a callback that raises and continues tool
            # execution. Convert adapter faults into an explicit veto so ordinary
            # malformed inputs cannot bypass Rampart through that host behavior.
            logger.warning("Rampart Hermes adapter error (%s); blocking tool call", type(exc).__name__)
            return _block("rampart: policy adapter error — refusing tool call")

    ctx.register_hook("pre_tool_call", _pre_tool_call)
