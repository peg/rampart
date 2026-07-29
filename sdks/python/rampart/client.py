# Copyright 2026 The Rampart Authors
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""HTTP client for the Rampart policy engine API."""

from __future__ import annotations

import base64
import ipaddress
import os
import threading
from typing import Any, AsyncIterator, Dict, Iterator, Optional, Union
from urllib.parse import quote, urlsplit

import httpx

from .types import Decision, RampartConnectionError, RampartServerError

MAX_RESPONSE_BYTES = 1024 * 1024


class _InvalidControlResponse(Exception):
    pass


class _LimitedSyncStream(httpx.SyncByteStream):
    def __init__(self, stream: httpx.SyncByteStream, limit: int):
        self._stream = stream
        self._limit = limit

    def __iter__(self) -> Iterator[bytes]:
        total = 0
        for chunk in self._stream:
            total += len(chunk)
            if total > self._limit:
                self._stream.close()
                raise _InvalidControlResponse(
                    "Rampart response exceeded the size limit"
                )
            yield chunk

    def close(self) -> None:
        self._stream.close()


class _LimitedAsyncStream(httpx.AsyncByteStream):
    def __init__(self, stream: httpx.AsyncByteStream, limit: int):
        self._stream = stream
        self._limit = limit

    async def __aiter__(self) -> AsyncIterator[bytes]:
        total = 0
        async for chunk in self._stream:
            total += len(chunk)
            if total > self._limit:
                await self._stream.aclose()
                raise _InvalidControlResponse(
                    "Rampart response exceeded the size limit"
                )
            yield chunk

    async def aclose(self) -> None:
        await self._stream.aclose()


class _LimitedTransport(httpx.BaseTransport):
    def __init__(self, inner: httpx.BaseTransport, limit: int):
        self._inner = inner
        self._limit = limit

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        response = self._inner.handle_request(request)
        encoding = response.headers.get("content-encoding", "").strip().lower()
        if encoding not in {"", "identity"}:
            response.stream.close()
            raise _InvalidControlResponse(
                "Rampart control responses must not use content encoding"
            )
        return httpx.Response(
            status_code=response.status_code,
            headers=response.headers,
            stream=_LimitedSyncStream(response.stream, self._limit),
            extensions=response.extensions,
        )

    def close(self) -> None:
        self._inner.close()


class _LimitedAsyncTransport(httpx.AsyncBaseTransport):
    def __init__(self, inner: httpx.AsyncBaseTransport, limit: int):
        self._inner = inner
        self._limit = limit

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self._inner.handle_async_request(request)
        encoding = response.headers.get("content-encoding", "").strip().lower()
        if encoding not in {"", "identity"}:
            await response.stream.aclose()
            raise _InvalidControlResponse(
                "Rampart control responses must not use content encoding"
            )
        return httpx.Response(
            status_code=response.status_code,
            headers=response.headers,
            stream=_LimitedAsyncStream(response.stream, self._limit),
            extensions=response.extensions,
        )

    async def aclose(self) -> None:
        await self._inner.aclose()


def _validate_base_url(value: str) -> str:
    """Validate the endpoint that receives policy credentials and tool data."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError("Rampart URL must be a non-empty absolute HTTP(S) URL")
    raw = value.strip()
    try:
        parsed = urlsplit(raw)
        port = parsed.port  # Force validation of malformed ports.
    except ValueError as exc:
        raise ValueError(f"Invalid Rampart URL: {exc}") from exc

    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Rampart URL must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Rampart URL must not contain embedded credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("Rampart URL must not contain a query string or fragment")
    if port is not None and not 0 < port < 65536:
        raise ValueError("Rampart URL contains an invalid port")

    hostname = parsed.hostname.rstrip(".").lower()
    loopback = hostname == "localhost"
    if not loopback:
        try:
            loopback = ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            loopback = False
    if parsed.scheme == "http" and not loopback:
        raise ValueError(
            "Refusing to send Rampart control data over non-loopback HTTP; use HTTPS"
        )
    return raw.rstrip("/")


class RampartClient:
    """HTTP client for communicating with a Rampart server.

    Provides methods to check tool calls against policies and query server health.
    Supports both synchronous and asynchronous operation via the async client.

    The client fails open by default - if the server is unreachable, tool calls
    are allowed to proceed. This ensures agent operation continues even if the
    policy server is down.

    Args:
        url: Base URL of the Rampart server (default: http://localhost:9090)
        token: Bearer token for authentication (default: reads from the
            RAMPART_TOKEN environment variable)
        fail_open: Whether to allow calls when server is unreachable (default: True)
        timeout: Request timeout in seconds (default: 30)

    Example:
        >>> client = RampartClient()
        >>> decision = client.check_exec("rm -rf /")
        >>> if not decision.allowed:
        ...     print(f"Command blocked: {decision.message}")
    """

    def __init__(
        self,
        url: Optional[str] = None,
        token: Optional[str] = None,
        fail_open: bool = True,
        timeout: float = 30.0,
    ):
        raw_url = (
            url
            if url is not None
            else os.environ.get("RAMPART_URL", "http://localhost:9090")
        )
        raw_token = token if token is not None else os.environ.get("RAMPART_TOKEN")
        self.token = raw_token.strip() if raw_token and raw_token.strip() else None
        self.fail_open = fail_open

        self.url = _validate_base_url(raw_url)

        # Build headers
        headers = {
            "Content-Type": "application/json",
            # The response limiter counts wire bytes. Refuse compression so a
            # tiny encoded body cannot expand beyond the in-memory limit.
            "Accept-Encoding": "identity",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        self._client_headers = headers
        self._client_timeout = httpx.Timeout(timeout)
        # Allocate each transport only when its API is used. A synchronous SDK
        # user should not have to discover and close an unused async pool (and
        # vice versa).
        self._client: Optional[httpx.Client] = None
        self._async_client: Optional[httpx.AsyncClient] = None
        self._client_init_lock = threading.Lock()

    def _sync_client(self) -> httpx.Client:
        if self._client is None:
            with self._client_init_lock:
                if self._client is None:
                    self._client = httpx.Client(
                        headers=self._client_headers,
                        timeout=self._client_timeout,
                        follow_redirects=False,
                        trust_env=False,
                        transport=_LimitedTransport(
                            httpx.HTTPTransport(), MAX_RESPONSE_BYTES
                        ),
                    )
        return self._client

    def _async_http_client(self) -> httpx.AsyncClient:
        if self._async_client is None:
            with self._client_init_lock:
                if self._async_client is None:
                    self._async_client = httpx.AsyncClient(
                        headers=self._client_headers,
                        timeout=self._client_timeout,
                        follow_redirects=False,
                        trust_env=False,
                        transport=_LimitedAsyncTransport(
                            httpx.AsyncHTTPTransport(), MAX_RESPONSE_BYTES
                        ),
                    )
        return self._async_client

    def __enter__(self) -> RampartClient:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    async def __aenter__(self) -> RampartClient:
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()

    def close(self) -> None:
        """Close the synchronous HTTP client, if it was used."""
        if self._client is not None:
            self._client.close()

    async def aclose(self) -> None:
        """Close both HTTP clients after asynchronous use."""
        if self._client is not None:
            self._client.close()
        if self._async_client is not None:
            await self._async_client.aclose()

    def health(self) -> bool:
        """Check if the Rampart server is healthy.

        Returns:
            True if the server responds to the health check, False otherwise.
        """
        try:
            response = self._sync_client().get(f"{self.url}/healthz")
            return bool(response.status_code == 200)
        except Exception:
            return False

    async def ahealth(self) -> bool:
        """Async version of health()."""
        try:
            response = await self._async_http_client().get(f"{self.url}/healthz")
            return bool(response.status_code == 200)
        except Exception:
            return False

    def preflight(
        self,
        tool: str,
        params: Dict[str, Any],
        agent: Optional[str] = None,
        session: Optional[str] = None,
    ) -> Decision:
        """Check if a tool call would be allowed without executing it.

        Args:
            tool: Name of the tool to check
            params: Parameters for the tool call
            agent: Agent identifier (default: "unknown-agent")
            session: Session identifier (default: "unknown-session")

        Returns:
            Decision object with the policy evaluation result

        Raises:
            RampartConnectionError: If fail_open=False and server is unreachable
            RampartServerError: If the server returns an error response
        """
        return self._make_request("preflight", tool, params, agent, session)

    async def apreflight(
        self,
        tool: str,
        params: Dict[str, Any],
        agent: Optional[str] = None,
        session: Optional[str] = None,
    ) -> Decision:
        """Async version of preflight()."""
        return await self._amake_request("preflight", tool, params, agent, session)

    def enforce(
        self,
        tool: str,
        params: Dict[str, Any],
        agent: Optional[str] = None,
        session: Optional[str] = None,
    ) -> Decision:
        """Authorize an actual tool invocation and consume stateful rules.

        Unlike :meth:`preflight`, this records call-count state and atomically
        consumes a matching ``once: true`` authorization.
        """
        return self._make_request(
            "preflight", tool, params, agent, session, enforce=True
        )

    async def aenforce(
        self,
        tool: str,
        params: Dict[str, Any],
        agent: Optional[str] = None,
        session: Optional[str] = None,
    ) -> Decision:
        """Async version of enforce()."""
        return await self._amake_request(
            "preflight", tool, params, agent, session, enforce=True
        )

    def check_exec(
        self,
        command: Union[str, bytes],
        agent: Optional[str] = None,
        session: Optional[str] = None,
        use_b64: bool = False,
    ) -> Decision:
        """Check if an exec command would be allowed.

        Args:
            command: Command to execute (string or bytes)
            agent: Agent identifier (default: "unknown-agent")
            session: Session identifier (default: "unknown-session")
            use_b64: Whether to use base64 encoding for the command

        Returns:
            Decision object with the policy evaluation result
        """
        if isinstance(command, bytes):
            command = command.decode("utf-8")

        if use_b64:
            command_b64 = base64.b64encode(command.encode("utf-8")).decode("ascii")
            params = {"command_b64": command_b64}
        else:
            params = {"command": command}

        return self.preflight("exec", params, agent, session)

    async def acheck_exec(
        self,
        command: Union[str, bytes],
        agent: Optional[str] = None,
        session: Optional[str] = None,
        use_b64: bool = False,
    ) -> Decision:
        """Async version of check_exec()."""
        if isinstance(command, bytes):
            command = command.decode("utf-8")

        if use_b64:
            command_b64 = base64.b64encode(command.encode("utf-8")).decode("ascii")
            params = {"command_b64": command_b64}
        else:
            params = {"command": command}

        return await self.apreflight("exec", params, agent, session)

    def check_read(
        self,
        path: str,
        agent: Optional[str] = None,
        session: Optional[str] = None,
    ) -> Decision:
        """Check if reading a file would be allowed.

        Args:
            path: File path to read
            agent: Agent identifier (default: "unknown-agent")
            session: Session identifier (default: "unknown-session")

        Returns:
            Decision object with the policy evaluation result
        """
        return self.preflight("read", {"path": path}, agent, session)

    async def acheck_read(
        self,
        path: str,
        agent: Optional[str] = None,
        session: Optional[str] = None,
    ) -> Decision:
        """Async version of check_read()."""
        return await self.apreflight("read", {"path": path}, agent, session)

    def check_write(
        self,
        path: str,
        content: Optional[str] = None,
        agent: Optional[str] = None,
        session: Optional[str] = None,
    ) -> Decision:
        """Check if writing to a file would be allowed.

        Args:
            path: File path to write
            content: Content to write (optional, may be used by policies)
            agent: Agent identifier (default: "unknown-agent")
            session: Session identifier (default: "unknown-session")

        Returns:
            Decision object with the policy evaluation result
        """
        params = {"path": path}
        if content is not None:
            params["content"] = content

        return self.preflight("write", params, agent, session)

    async def acheck_write(
        self,
        path: str,
        content: Optional[str] = None,
        agent: Optional[str] = None,
        session: Optional[str] = None,
    ) -> Decision:
        """Async version of check_write()."""
        params = {"path": path}
        if content is not None:
            params["content"] = content

        return await self.apreflight("write", params, agent, session)

    def check_fetch(
        self,
        url: str,
        agent: Optional[str] = None,
        session: Optional[str] = None,
    ) -> Decision:
        """Check if fetching a URL would be allowed.

        Args:
            url: URL to fetch
            agent: Agent identifier (default: "unknown-agent")
            session: Session identifier (default: "unknown-session")

        Returns:
            Decision object with the policy evaluation result
        """
        return self.preflight("fetch", {"url": url}, agent, session)

    async def acheck_fetch(
        self,
        url: str,
        agent: Optional[str] = None,
        session: Optional[str] = None,
    ) -> Decision:
        """Async version of check_fetch()."""
        return await self.apreflight("fetch", {"url": url}, agent, session)

    def _make_request(
        self,
        endpoint: str,
        tool: str,
        params: Dict[str, Any],
        agent: Optional[str],
        session: Optional[str],
        enforce: bool = False,
    ) -> Decision:
        """Make a synchronous request to the Rampart API."""
        request_data: Dict[str, Any] = {
            "agent": agent or "unknown-agent",
            "session": session or "unknown-session",
            "params": params,
        }
        if enforce:
            request_data["enforce"] = True

        try:
            response = self._sync_client().post(
                f"{self.url}/v1/{endpoint}/{quote(tool, safe='')}",
                json=request_data,
            )
            return self._decision_from_response(response)

        except _InvalidControlResponse as exc:
            raise RampartServerError(0, str(exc)) from exc
        except httpx.RequestError as e:
            # Network/connection error
            if not self.fail_open:
                raise RampartConnectionError(
                    f"Failed to connect to Rampart server: {e}"
                )
            # Fail open: allow the call
            return Decision(
                allowed=True,
                action="allow",
                message="fail-open: connection error",
                policies=[],
                eval_duration_ms=0.0,
            )

    async def _amake_request(
        self,
        endpoint: str,
        tool: str,
        params: Dict[str, Any],
        agent: Optional[str],
        session: Optional[str],
        enforce: bool = False,
    ) -> Decision:
        """Make an asynchronous request to the Rampart API."""
        request_data: Dict[str, Any] = {
            "agent": agent or "unknown-agent",
            "session": session or "unknown-session",
            "params": params,
        }
        if enforce:
            request_data["enforce"] = True

        try:
            response = await self._async_http_client().post(
                f"{self.url}/v1/{endpoint}/{quote(tool, safe='')}",
                json=request_data,
            )
            return self._decision_from_response(response)

        except _InvalidControlResponse as exc:
            raise RampartServerError(0, str(exc)) from exc
        except httpx.RequestError as e:
            # Network/connection error
            if not self.fail_open:
                raise RampartConnectionError(
                    f"Failed to connect to Rampart server: {e}"
                )
            # Fail open: allow the call
            return Decision(
                allowed=True,
                action="allow",
                message="fail-open: connection error",
                policies=[],
                eval_duration_ms=0.0,
            )

    def _decision_from_response(self, response: httpx.Response) -> Decision:
        """Validate and convert a response without duplicating sync/async logic."""
        if response.status_code != 200:
            # Authentication, authorization, malformed requests, and other
            # client errors must never become authorization via fail-open.
            if response.status_code < 500 or not self.fail_open:
                raise RampartServerError(response.status_code, response.text)
            return Decision(
                allowed=True,
                action="allow",
                message="fail-open: server error",
                policies=[],
                eval_duration_ms=0.0,
            )

        try:
            data = response.json()
        except (TypeError, ValueError) as exc:
            raise RampartServerError(200, f"invalid JSON response: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("allowed"), bool):
            raise RampartServerError(200, "invalid decision response schema")

        action = data.get("decision", data.get("action", "deny"))
        valid_actions = {
            "allow",
            "deny",
            "ask",
            "require_approval",
            "watch",
            "log",
            "webhook",
        }
        if not isinstance(action, str) or action not in valid_actions:
            raise RampartServerError(200, "invalid decision action")
        if data["allowed"] != (action in {"allow", "watch", "log"}):
            raise RampartServerError(200, "inconsistent decision response")
        message = data.get("message", "")
        if not isinstance(message, str):
            raise RampartServerError(200, "invalid decision message")

        raw_policies = data.get("matched_policies") or data.get("policies")
        if raw_policies is None and isinstance(data.get("policy"), str):
            raw_policies = [data["policy"]]
        if raw_policies is None:
            policies = []
        elif isinstance(raw_policies, list) and all(
            isinstance(policy, str) for policy in raw_policies
        ):
            policies = raw_policies
        else:
            raise RampartServerError(200, "invalid decision policies")

        raw_duration = data.get(
            "eval_duration_us" if "eval_duration_us" in data else "eval_duration_ms",
            0.0,
        )
        if not isinstance(raw_duration, (int, float)):
            raise RampartServerError(200, "invalid decision duration")
        if "eval_duration_us" in data:
            raw_duration /= 1000.0

        return Decision(
            allowed=data["allowed"],
            action=action,
            message=message,
            policies=policies,
            eval_duration_ms=float(raw_duration),
        )
