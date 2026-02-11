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

"""Unit tests for the Rampart client."""

import base64
import json
import os
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import urljoin

import httpx
import pytest

from rampart import (
    Decision,
    RampartClient,
    RampartConnectionError,
    RampartDeniedError,
    RampartServerError,
)
from rampart.decorators import exec_guard, fetch_guard, guard, read_guard, write_guard


class TestRampartClient:
    """Test the RampartClient class."""
    
    def test_init_defaults(self):
        """Test client initialization with defaults."""
        client = RampartClient()
        assert client.url == "http://localhost:19090"
        assert client.token is None
        assert client.fail_open is True
    
    def test_init_with_params(self):
        """Test client initialization with custom parameters."""
        client = RampartClient(
            url="http://example.com:8080",
            token="test-token",
            fail_open=False,
            timeout=60.0,
        )
        assert client.url == "http://example.com:8080"
        assert client.token == "test-token"
        assert client.fail_open is False
    
    def test_init_with_env_vars(self):
        """Test client initialization with environment variables."""
        with patch.dict(os.environ, {
            "RAMPART_URL": "http://env.example.com",
            "RAMPART_TOKEN": "env-token",
        }):
            client = RampartClient()
            assert client.url == "http://env.example.com"
            assert client.token == "env-token"
    
    def test_url_trailing_slash_removed(self):
        """Test that trailing slashes are removed from URLs."""
        client = RampartClient(url="http://example.com:8080/")
        assert client.url == "http://example.com:8080"
    
    @patch("rampart.client.httpx.Client")
    def test_health_success(self, mock_httpx_client):
        """Test successful health check."""
        mock_response = Mock()
        mock_response.status_code = 200
        
        mock_client_instance = Mock()
        mock_client_instance.get.return_value = mock_response
        mock_httpx_client.return_value = mock_client_instance
        
        client = RampartClient()
        client._client = mock_client_instance
        
        result = client.health()
        assert result is True
        mock_client_instance.get.assert_called_once_with(
            "http://localhost:19090/healthz"
        )
    
    @patch("rampart.client.httpx.Client")
    def test_health_failure(self, mock_httpx_client):
        """Test health check failure."""
        mock_client_instance = Mock()
        mock_client_instance.get.side_effect = httpx.RequestError("Connection failed")
        mock_httpx_client.return_value = mock_client_instance
        
        client = RampartClient()
        client._client = mock_client_instance
        
        result = client.health()
        assert result is False
    
    @patch("rampart.client.httpx.Client")
    def test_preflight_success(self, mock_httpx_client):
        """Test successful preflight check."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "allowed": True,
            "action": "allow",
            "message": "Command allowed",
            "policies": ["exec-safety"],
            "eval_duration_ms": 1.5,
        }
        
        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_httpx_client.return_value = mock_client_instance
        
        client = RampartClient()
        client._client = mock_client_instance
        
        decision = client.preflight(
            "exec",
            {"command": "git status"},
            agent="test-agent",
            session="test-session"
        )
        
        assert isinstance(decision, Decision)
        assert decision.allowed is True
        assert decision.action == "allow"
        assert decision.message == "Command allowed"
        assert decision.policies == ["exec-safety"]
        assert decision.eval_duration_ms == 1.5
        
        mock_client_instance.post.assert_called_once_with(
            "http://localhost:19090/v1/preflight/exec",
            json={
                "agent": "test-agent",
                "session": "test-session",
                "params": {"command": "git status"}
            }
        )
    
    @patch("rampart.client.httpx.Client")
    def test_preflight_denied(self, mock_httpx_client):
        """Test preflight check that's denied."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "allowed": False,
            "action": "deny",
            "message": "Dangerous command blocked",
            "policies": ["exec-safety"],
            "eval_duration_ms": 0.8,
        }
        
        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_httpx_client.return_value = mock_client_instance
        
        client = RampartClient()
        client._client = mock_client_instance
        
        decision = client.preflight("exec", {"command": "rm -rf /"})
        
        assert decision.allowed is False
        assert decision.action == "deny"
        assert decision.message == "Dangerous command blocked"
    
    @patch("rampart.client.httpx.Client")
    def test_preflight_default_agent_session(self, mock_httpx_client):
        """Test preflight with default agent and session."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "allowed": True,
            "action": "allow",
            "message": "OK",
            "policies": [],
            "eval_duration_ms": 0.1,
        }
        
        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_httpx_client.return_value = mock_client_instance
        
        client = RampartClient()
        client._client = mock_client_instance
        
        client.preflight("read", {"path": "/tmp/file"})
        
        mock_client_instance.post.assert_called_once_with(
            "http://localhost:19090/v1/preflight/read",
            json={
                "agent": "unknown-agent",
                "session": "unknown-session",
                "params": {"path": "/tmp/file"}
            }
        )
    
    @patch("rampart.client.httpx.Client")
    def test_preflight_connection_error_fail_open(self, mock_httpx_client):
        """Test preflight with connection error and fail_open=True."""
        mock_client_instance = Mock()
        mock_client_instance.post.side_effect = httpx.RequestError("Connection failed")
        mock_httpx_client.return_value = mock_client_instance
        
        client = RampartClient(fail_open=True)
        client._client = mock_client_instance
        
        decision = client.preflight("exec", {"command": "ls"})
        
        assert decision.allowed is True
        assert decision.action == "allow"
        assert decision.message == "fail-open: connection error"
    
    @patch("rampart.client.httpx.Client")
    def test_preflight_connection_error_fail_closed(self, mock_httpx_client):
        """Test preflight with connection error and fail_open=False."""
        mock_client_instance = Mock()
        mock_client_instance.post.side_effect = httpx.RequestError("Connection failed")
        mock_httpx_client.return_value = mock_client_instance
        
        client = RampartClient(fail_open=False)
        client._client = mock_client_instance
        
        with pytest.raises(RampartConnectionError):
            client.preflight("exec", {"command": "ls"})
    
    @patch("rampart.client.httpx.Client")
    def test_preflight_server_error_fail_open(self, mock_httpx_client):
        """Test preflight with server error and fail_open=True."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal server error"
        
        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_httpx_client.return_value = mock_client_instance
        
        client = RampartClient(fail_open=True)
        client._client = mock_client_instance
        
        decision = client.preflight("exec", {"command": "ls"})
        
        assert decision.allowed is True
        assert decision.action == "allow"
        assert decision.message == "fail-open: server error"
    
    @patch("rampart.client.httpx.Client") 
    def test_preflight_server_error_fail_closed(self, mock_httpx_client):
        """Test preflight with server error and fail_open=False."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal server error"
        
        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_httpx_client.return_value = mock_client_instance
        
        client = RampartClient(fail_open=False)
        client._client = mock_client_instance
        
        with pytest.raises(RampartServerError) as exc_info:
            client.preflight("exec", {"command": "ls"})
        
        assert exc_info.value.status_code == 500
        assert "Internal server error" in str(exc_info.value)
    
    @patch("rampart.client.httpx.Client")
    def test_check_exec_string_command(self, mock_httpx_client):
        """Test check_exec with string command."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "allowed": True,
            "action": "allow", 
            "message": "OK",
            "policies": [],
            "eval_duration_ms": 0.1,
        }
        
        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_httpx_client.return_value = mock_client_instance
        
        client = RampartClient()
        client._client = mock_client_instance
        
        decision = client.check_exec("git status")
        
        assert decision.allowed is True
        mock_client_instance.post.assert_called_once_with(
            "http://localhost:19090/v1/preflight/exec",
            json={
                "agent": "unknown-agent",
                "session": "unknown-session",
                "params": {"command": "git status"}
            }
        )
    
    @patch("rampart.client.httpx.Client")
    def test_check_exec_bytes_command(self, mock_httpx_client):
        """Test check_exec with bytes command."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "allowed": True,
            "action": "allow",
            "message": "OK", 
            "policies": [],
            "eval_duration_ms": 0.1,
        }
        
        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_httpx_client.return_value = mock_client_instance
        
        client = RampartClient()
        client._client = mock_client_instance
        
        decision = client.check_exec(b"git status")
        
        assert decision.allowed is True
        mock_client_instance.post.assert_called_once_with(
            "http://localhost:19090/v1/preflight/exec",
            json={
                "agent": "unknown-agent",
                "session": "unknown-session",
                "params": {"command": "git status"}
            }
        )
    
    @patch("rampart.client.httpx.Client")
    def test_check_exec_base64_encoding(self, mock_httpx_client):
        """Test check_exec with base64 encoding."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "allowed": True,
            "action": "allow",
            "message": "OK",
            "policies": [],
            "eval_duration_ms": 0.1,
        }
        
        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_httpx_client.return_value = mock_client_instance
        
        client = RampartClient()
        client._client = mock_client_instance
        
        command = "git status"
        expected_b64 = base64.b64encode(command.encode("utf-8")).decode("ascii")
        
        decision = client.check_exec(command, use_b64=True)
        
        assert decision.allowed is True
        mock_client_instance.post.assert_called_once_with(
            "http://localhost:19090/v1/preflight/exec",
            json={
                "agent": "unknown-agent",
                "session": "unknown-session",
                "params": {"command_b64": expected_b64}
            }
        )
    
    @patch("rampart.client.httpx.Client")
    def test_check_read(self, mock_httpx_client):
        """Test check_read method."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "allowed": True,
            "action": "allow",
            "message": "File read allowed",
            "policies": ["read-policy"],
            "eval_duration_ms": 0.2,
        }
        
        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_httpx_client.return_value = mock_client_instance
        
        client = RampartClient()
        client._client = mock_client_instance
        
        decision = client.check_read("/tmp/test.txt")
        
        assert decision.allowed is True
        assert decision.message == "File read allowed"
        mock_client_instance.post.assert_called_once_with(
            "http://localhost:19090/v1/preflight/read",
            json={
                "agent": "unknown-agent",
                "session": "unknown-session",
                "params": {"path": "/tmp/test.txt"}
            }
        )
    
    @patch("rampart.client.httpx.Client")
    def test_check_write(self, mock_httpx_client):
        """Test check_write method."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "allowed": False,
            "action": "deny",
            "message": "Write to system directory forbidden",
            "policies": ["write-policy"],
            "eval_duration_ms": 0.3,
        }
        
        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_httpx_client.return_value = mock_client_instance
        
        client = RampartClient()
        client._client = mock_client_instance
        
        decision = client.check_write("/etc/passwd", content="malicious content")
        
        assert decision.allowed is False
        assert decision.action == "deny"
        mock_client_instance.post.assert_called_once_with(
            "http://localhost:19090/v1/preflight/write",
            json={
                "agent": "unknown-agent",
                "session": "unknown-session",
                "params": {
                    "path": "/etc/passwd",
                    "content": "malicious content"
                }
            }
        )
    
    @patch("rampart.client.httpx.Client")
    def test_check_write_no_content(self, mock_httpx_client):
        """Test check_write without content."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "allowed": True,
            "action": "allow",
            "message": "OK",
            "policies": [],
            "eval_duration_ms": 0.1,
        }
        
        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_httpx_client.return_value = mock_client_instance
        
        client = RampartClient()
        client._client = mock_client_instance
        
        decision = client.check_write("/tmp/output.txt")
        
        mock_client_instance.post.assert_called_once_with(
            "http://localhost:19090/v1/preflight/write",
            json={
                "agent": "unknown-agent",
                "session": "unknown-session",
                "params": {"path": "/tmp/output.txt"}
            }
        )
    
    @patch("rampart.client.httpx.Client")
    def test_check_fetch(self, mock_httpx_client):
        """Test check_fetch method."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "allowed": True,
            "action": "log",
            "message": "URL fetch logged",
            "policies": ["fetch-policy"],
            "eval_duration_ms": 0.4,
        }
        
        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_httpx_client.return_value = mock_client_instance
        
        client = RampartClient()
        client._client = mock_client_instance
        
        decision = client.check_fetch("https://api.example.com/data")
        
        assert decision.allowed is True
        assert decision.action == "log"
        mock_client_instance.post.assert_called_once_with(
            "http://localhost:19090/v1/preflight/fetch",
            json={
                "agent": "unknown-agent",
                "session": "unknown-session",
                "params": {"url": "https://api.example.com/data"}
            }
        )


@pytest.mark.asyncio
class TestAsyncRampartClient:
    """Test async methods of RampartClient."""
    
    @patch("rampart.client.httpx.AsyncClient")
    async def test_ahealth_success(self, mock_httpx_async_client):
        """Test async health check success."""
        mock_response = Mock()
        mock_response.status_code = 200
        
        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = mock_response
        mock_httpx_async_client.return_value = mock_client_instance
        
        client = RampartClient()
        client._async_client = mock_client_instance
        
        result = await client.ahealth()
        assert result is True
    
    @patch("rampart.client.httpx.AsyncClient")
    async def test_apreflight_success(self, mock_httpx_async_client):
        """Test async preflight success."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "allowed": True,
            "action": "allow",
            "message": "OK",
            "policies": [],
            "eval_duration_ms": 0.1,
        }
        
        mock_client_instance = AsyncMock()
        mock_client_instance.post.return_value = mock_response
        mock_httpx_async_client.return_value = mock_client_instance
        
        client = RampartClient()
        client._async_client = mock_client_instance
        
        decision = await client.apreflight("exec", {"command": "ls"})
        assert decision.allowed is True


class TestDecorators:
    """Test decorator functionality."""
    
    def test_exec_guard_success(self):
        """Test exec_guard decorator with allowed command."""
        with patch("rampart.decorators.get_default_client") as mock_get_client:
            mock_client = Mock()
            mock_client.preflight.return_value = Decision(
                allowed=True,
                action="allow",
                message="OK",
                policies=[],
                eval_duration_ms=0.1,
            )
            mock_get_client.return_value = mock_client
            
            @exec_guard()
            def run_command(command: str) -> str:
                return f"executed: {command}"
            
            result = run_command("git status")
            assert result == "executed: git status"
            
            mock_client.preflight.assert_called_once_with(
                "exec",
                {"command": "git status"},
                None,
                None
            )
    
    def test_exec_guard_denied(self):
        """Test exec_guard decorator with denied command."""
        with patch("rampart.decorators.get_default_client") as mock_get_client:
            mock_client = Mock()
            mock_client.preflight.return_value = Decision(
                allowed=False,
                action="deny",
                message="Dangerous command",
                policies=["exec-safety"],
                eval_duration_ms=0.5,
            )
            mock_get_client.return_value = mock_client
            
            @exec_guard()
            def run_command(command: str) -> str:
                return f"executed: {command}"
            
            with pytest.raises(RampartDeniedError) as exc_info:
                run_command("rm -rf /")
            
            assert exc_info.value.tool == "exec"
            assert exc_info.value.policy == "exec-safety"
            assert "Dangerous command" in str(exc_info.value)
    
    def test_read_guard_with_param_mapping(self):
        """Test read_guard with custom parameter mapping."""
        with patch("rampart.decorators.get_default_client") as mock_get_client:
            mock_client = Mock()
            mock_client.preflight.return_value = Decision(
                allowed=True,
                action="allow",
                message="OK",
                policies=[],
                eval_duration_ms=0.1,
            )
            mock_get_client.return_value = mock_client
            
            @read_guard(path_param="filename")
            def read_file(filename: str) -> str:
                return f"content of {filename}"
            
            result = read_file("/tmp/test.txt")
            assert result == "content of /tmp/test.txt"
            
            mock_client.preflight.assert_called_once_with(
                "read",
                {"path": "/tmp/test.txt"},
                None,
                None
            )
    
    def test_custom_guard_decorator(self):
        """Test custom guard decorator with param mapping."""
        with patch("rampart.decorators.get_default_client") as mock_get_client:
            mock_client = Mock()
            mock_client.preflight.return_value = Decision(
                allowed=True,
                action="allow",
                message="OK",
                policies=[],
                eval_duration_ms=0.1,
            )
            mock_get_client.return_value = mock_client
            
            @guard("custom_tool", param_map={"input_data": "data"})
            def process_data(input_data: dict, timeout: int = 30) -> dict:
                return {"processed": input_data, "timeout": timeout}
            
            test_data = {"key": "value"}
            result = process_data(test_data, timeout=60)
            
            assert result["processed"] == test_data
            assert result["timeout"] == 60
            
            mock_client.preflight.assert_called_once_with(
                "custom_tool",
                {"data": test_data},
                None,
                None
            )
    
    @pytest.mark.asyncio
    async def test_async_exec_guard(self):
        """Test exec_guard with async function."""
        with patch("rampart.decorators.get_default_client") as mock_get_client:
            mock_client = Mock()
            mock_client.apreflight = AsyncMock()
            mock_client.apreflight.return_value = Decision(
                allowed=True,
                action="allow",
                message="OK",
                policies=[],
                eval_duration_ms=0.1,
            )
            mock_get_client.return_value = mock_client
            
            @exec_guard()
            async def async_run_command(command: str) -> str:
                return f"async executed: {command}"
            
            result = await async_run_command("git status")
            assert result == "async executed: git status"
            
            mock_client.apreflight.assert_called_once_with(
                "exec",
                {"command": "git status"},
                None,
                None
            )
    
    def test_guard_no_raise_on_deny(self):
        """Test guard decorator with raise_on_deny=False."""
        with patch("rampart.decorators.get_default_client") as mock_get_client:
            mock_client = Mock()
            mock_client.preflight.return_value = Decision(
                allowed=False,
                action="deny",
                message="Blocked",
                policies=["safety"],
                eval_duration_ms=0.1,
            )
            mock_get_client.return_value = mock_client
            
            @exec_guard(raise_on_deny=False)
            def run_command(command: str) -> str:
                return f"executed: {command}"
            
            result = run_command("dangerous command")
            assert result is None  # Function not called, returns None