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
import os
from typing import Any, Dict, Optional, Union

import httpx

from .types import Decision, RampartConnectionError, RampartDeniedError, RampartServerError


class RampartClient:
    """HTTP client for communicating with a Rampart server.
    
    Provides methods to check tool calls against policies and query server health.
    Supports both synchronous and asynchronous operation via the async client.
    
    The client fails open by default - if the server is unreachable, tool calls
    are allowed to proceed. This ensures agent operation continues even if the
    policy server is down.
    
    Args:
        url: Base URL of the Rampart server (default: http://localhost:19090)
        token: Bearer token for authentication (default: reads from RAMPART_TOKEN env var)
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
        self.url = url or os.environ.get("RAMPART_URL", "http://localhost:19090")
        self.token = token or os.environ.get("RAMPART_TOKEN")
        self.fail_open = fail_open
        
        # Remove trailing slash for consistent URL construction
        self.url = self.url.rstrip("/")
        
        # Build headers
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        
        self._client = httpx.Client(
            headers=headers,
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
        )
        
        self._async_client = httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
        )
    
    def __enter__(self) -> RampartClient:
        return self
    
    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
    
    def close(self) -> None:
        """Close the underlying HTTP clients."""
        self._client.close()
        
    async def aclose(self) -> None:
        """Close the underlying async HTTP client."""
        await self._async_client.aclose()
    
    def health(self) -> bool:
        """Check if the Rampart server is healthy.
        
        Returns:
            True if the server responds to the health check, False otherwise.
        """
        try:
            response = self._client.get(f"{self.url}/healthz")
            return response.status_code == 200
        except Exception:
            return False
    
    async def ahealth(self) -> bool:
        """Async version of health()."""
        try:
            response = await self._async_client.get(f"{self.url}/healthz")
            return response.status_code == 200
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
    ) -> Decision:
        """Make a synchronous request to the Rampart API."""
        request_data = {
            "agent": agent or "unknown-agent",
            "session": session or "unknown-session", 
            "params": params,
        }
        
        try:
            response = self._client.post(
                f"{self.url}/v1/{endpoint}/{tool}",
                json=request_data,
            )
            
            if response.status_code == 200:
                data = response.json()
                return Decision(
                    allowed=data.get("allowed", False),
                    action=data.get("action", "deny"),
                    message=data.get("message", ""),
                    policies=data.get("policies", []),
                    eval_duration_ms=data.get("eval_duration_ms", 0.0),
                )
            else:
                # Server returned an error
                if not self.fail_open:
                    raise RampartServerError(response.status_code, response.text)
                # Fail open: allow the call
                return Decision(
                    allowed=True,
                    action="allow",
                    message="fail-open: server error",
                    policies=[],
                    eval_duration_ms=0.0,
                )
        
        except httpx.RequestError as e:
            # Network/connection error
            if not self.fail_open:
                raise RampartConnectionError(f"Failed to connect to Rampart server: {e}")
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
    ) -> Decision:
        """Make an asynchronous request to the Rampart API."""
        request_data = {
            "agent": agent or "unknown-agent",
            "session": session or "unknown-session",
            "params": params,
        }
        
        try:
            response = await self._async_client.post(
                f"{self.url}/v1/{endpoint}/{tool}",
                json=request_data,
            )
            
            if response.status_code == 200:
                data = response.json()
                return Decision(
                    allowed=data.get("allowed", False),
                    action=data.get("action", "deny"),
                    message=data.get("message", ""),
                    policies=data.get("policies", []),
                    eval_duration_ms=data.get("eval_duration_ms", 0.0),
                )
            else:
                # Server returned an error
                if not self.fail_open:
                    raise RampartServerError(response.status_code, response.text)
                # Fail open: allow the call
                return Decision(
                    allowed=True,
                    action="allow",
                    message="fail-open: server error",
                    policies=[],
                    eval_duration_ms=0.0,
                )
        
        except httpx.RequestError as e:
            # Network/connection error
            if not self.fail_open:
                raise RampartConnectionError(f"Failed to connect to Rampart server: {e}")
            # Fail open: allow the call
            return Decision(
                allowed=True,
                action="allow", 
                message="fail-open: connection error",
                policies=[],
                eval_duration_ms=0.0,
            )