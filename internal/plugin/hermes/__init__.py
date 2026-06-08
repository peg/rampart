# Copyright 2026 The Rampart Authors
# Licensed under the Apache License, Version 2.0
"""Experimental Rampart policy gate for Hermes Agent.

The plugin is intentionally conservative:

* It uses Hermes' ``pre_tool_call`` hook and only returns a block directive.
* It defaults to ``/v1/preflight/{tool}`` so Rampart does not create a hidden
  approval queue while Hermes lacks a plugin-owned approval/resume primitive.
* It passes Hermes' native ``tool_call_id`` as top-level Rampart metadata so
  Rampart audit IDs can be correlated with the exact Hermes tool call.
* ``ask`` / ``require_approval`` decisions block with a clear message instead
  of polling or creating a second approval surface, and include Rampart's
  ``audit_id`` when available.
* If Rampart serve is unavailable, mutating/high-risk tools fail closed and only
  explicitly configured read-only tools fail open.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import quote

VERSION = "1.2.0"

DEFAULT_SERVE_URL = "http://127.0.0.1:9090"
DEFAULT_TIMEOUT_MS = 3000
DEFAULT_ENDPOINT_MODE = "preflight"
DEFAULT_AGENT_NAME = "hermes"

# Read-only tools that may proceed when Rampart is unavailable. Operators can
# narrow this with plugins.entries.rampart.config.fail_open_tools or
# RAMPART_HERMES_FAIL_OPEN_TOOLS. Sensitive tools are intentionally absent.
DEFAULT_FAIL_OPEN_TOOLS = frozenset(
    {
        "read_file",
        "search_files",
        "browser_snapshot",
        "browser_get_images",
        "browser_vision",
        "vision_analyze",
    }
)

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

SENSITIVE_KEY_MARKERS = (
    "token",
    "secret",
    "password",
    "authorization",
    "api_key",
    "apikey",
    "private_key",
)

logger = logging.getLogger(__name__)


class RampartUnavailable(RuntimeError):
    """Rampart serve could not be reached or returned an unusable response."""


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
    return _preview(value)


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
        if line.startswith("*** Update File: ") or line.startswith("*** Add File: ") or line.startswith("*** Delete File: "):
            path = line.split(": ", 1)[1].strip()
            if path and path not in paths:
                paths.append(path)
    return paths[:20]


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
    return payload


def _endpoint_url(config: PluginConfig, rampart_tool: str) -> str:
    endpoint = "tool" if config.endpoint_mode == "tool" else "preflight"
    return f"{config.serve_url}/v1/{endpoint}/{quote(rampart_tool, safe='')}"


def _decode_http_error(exc: urllib.error.HTTPError) -> dict[str, Any]:
    body = exc.read().decode("utf-8", errors="replace")
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
        with urllib.request.urlopen(request, timeout=config.timeout_seconds) as response:
            data = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        if exc.code in {401, 403}:
            return _decode_http_error(exc)
        raise RampartUnavailable(f"Rampart returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, socket.timeout, OSError) as exc:
        raise RampartUnavailable(str(exc)) from exc

    try:
        parsed = json.loads(data) if data else {}
    except json.JSONDecodeError as exc:
        raise RampartUnavailable("Rampart returned invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise RampartUnavailable("Rampart returned non-object JSON")
    return parsed


def _block(message: str) -> dict[str, str]:
    return {"action": "block", "message": message}


def _decision_from_result(result: Mapping[str, Any]) -> str:
    decision = result.get("decision")
    if isinstance(decision, str) and decision:
        return decision.lower()
    if result.get("error"):
        return "deny"
    if result.get("allowed") is False:
        return "deny"
    return "allow"


def _audit_suffix(result: Mapping[str, Any]) -> str:
    audit_id = result.get("audit_id")
    if isinstance(audit_id, str) and audit_id.strip():
        return f" [audit_id: {audit_id.strip()}]"
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
    """Evaluate a Hermes tool call and return a Hermes block directive or None."""

    config = load_config(config_overrides)
    rampart_tool, params = normalize_tool_call(tool_name, args)
    payload = _build_payload(
        config,
        params,
        session_id=session_id,
        task_id=task_id,
        tool_call_id=tool_call_id,
    )
    caller = requester or post_to_rampart

    try:
        result = caller(config, rampart_tool, payload)
    except RampartUnavailable as exc:
        if tool_name in config.fail_open_tools or rampart_tool in config.fail_open_tools:
            logger.warning("Rampart unavailable for %s/%s; configured fail-open", tool_name, rampart_tool)
            return None
        return _block(
            f"rampart: unavailable ({tool_name}→{rampart_tool}) — policy service could not be reached; refusing sensitive tool call"
        )

    decision = _decision_from_result(result)
    if decision in {"allow", "watch", "log"}:
        return None

    reason = str(result.get("message") or result.get("reason") or "policy violation")
    policy = result.get("policy") or result.get("matched_policies")
    audit_suffix = _audit_suffix(result)
    policy_suffix = ""
    if isinstance(policy, str) and policy:
        policy_suffix = f" [policy: {policy}]"
    elif isinstance(policy, list) and policy:
        policy_suffix = f" [policy: {policy[0]}]"

    if decision in {"ask", "require_approval"}:
        return _block(
            "rampart: approval required"
            f" for {tool_name}→{rampart_tool}{policy_suffix}{audit_suffix} — {reason}. "
            "Hermes Rampart integration is experimental and does not yet resume plugin-driven approvals; "
            "adjust policy or use a first-class Hermes approval flow before retrying."
        )

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
        return evaluate_pre_tool_call(
            tool_name,
            args,
            task_id=task_id,
            session_id=session_id,
            tool_call_id=tool_call_id,
        )

    ctx.register_hook("pre_tool_call", _pre_tool_call)
