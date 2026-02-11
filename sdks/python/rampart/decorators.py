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

"""Decorators for wrapping functions with Rampart policy checks."""

from __future__ import annotations

import asyncio
import functools
import inspect
from typing import Any, Callable, Dict, Optional, TypeVar, Union, cast

from .client import RampartClient
from .types import RampartDeniedError

# Type variable for decorated functions
F = TypeVar("F", bound=Callable[..., Any])

# Global client instance for decorators
_default_client: Optional[RampartClient] = None


def set_default_client(client: RampartClient) -> None:
    """Set the default client instance for decorators.
    
    Args:
        client: The RampartClient instance to use for policy checks
    """
    global _default_client
    _default_client = client


def get_default_client() -> RampartClient:
    """Get the default client instance, creating one if needed."""
    global _default_client
    if _default_client is None:
        _default_client = RampartClient()
    return _default_client


def guard(
    tool_name: str,
    *,
    client: Optional[RampartClient] = None,
    param_map: Optional[Dict[str, str]] = None,
    agent: Optional[str] = None,
    session: Optional[str] = None,
    raise_on_deny: bool = True,
) -> Callable[[F], F]:
    """Decorator to wrap a function with Rampart policy checks.
    
    The decorator performs a preflight check before calling the wrapped function.
    By default, it raises RampartDeniedError if the call is denied by policy.
    
    Args:
        tool_name: Name of the tool for policy evaluation
        client: RampartClient instance (uses default if None)
        param_map: Mapping from function parameter names to Rampart parameter names
        agent: Agent identifier for policy context
        session: Session identifier for policy context
        raise_on_deny: Whether to raise an exception when denied (default: True)
    
    Returns:
        Decorated function that performs policy checks
    
    Example:
        >>> @guard("exec")
        ... def run_command(command: str) -> str:
        ...     return subprocess.check_output(command, shell=True).decode()
        
        >>> @guard("read", param_map={"file_path": "path"})
        ... def read_file(file_path: str) -> str:
        ...     with open(file_path) as f:
        ...         return f.read()
    """
    
    def decorator(func: F) -> F:
        # Get function signature for parameter mapping
        sig = inspect.signature(func)
        
        if asyncio.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                # Extract parameters for policy check
                bound_args = sig.bind(*args, **kwargs)
                bound_args.apply_defaults()
                params = _extract_params(bound_args.arguments, param_map)
                
                # Get client instance
                policy_client = client or get_default_client()
                
                # Perform preflight check
                decision = await policy_client.apreflight(
                    tool_name, params, agent, session
                )
                
                if not decision.allowed and raise_on_deny:
                    policy_name = decision.policies[0] if decision.policies else None
                    raise RampartDeniedError(tool_name, policy_name, decision.message)
                
                # If allowed or not raising on deny, call the original function
                if decision.allowed:
                    return await func(*args, **kwargs)
                else:
                    # Policy denied but not raising - return None or empty result
                    return None
            
            return cast(F, async_wrapper)
        
        else:
            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                # Extract parameters for policy check
                bound_args = sig.bind(*args, **kwargs)
                bound_args.apply_defaults()
                params = _extract_params(bound_args.arguments, param_map)
                
                # Get client instance
                policy_client = client or get_default_client()
                
                # Perform preflight check
                decision = policy_client.preflight(
                    tool_name, params, agent, session
                )
                
                if not decision.allowed and raise_on_deny:
                    policy_name = decision.policies[0] if decision.policies else None
                    raise RampartDeniedError(tool_name, policy_name, decision.message)
                
                # If allowed or not raising on deny, call the original function
                if decision.allowed:
                    return func(*args, **kwargs)
                else:
                    # Policy denied but not raising - return None or empty result
                    return None
            
            return cast(F, sync_wrapper)
    
    return decorator


def exec_guard(
    *,
    client: Optional[RampartClient] = None,
    command_param: str = "command",
    agent: Optional[str] = None,
    session: Optional[str] = None,
    raise_on_deny: bool = True,
) -> Callable[[F], F]:
    """Convenience decorator for exec tool policy checks.
    
    Args:
        client: RampartClient instance (uses default if None)
        command_param: Name of the parameter containing the command
        agent: Agent identifier for policy context
        session: Session identifier for policy context
        raise_on_deny: Whether to raise an exception when denied
    
    Example:
        >>> @exec_guard()
        ... def run_command(command: str) -> str:
        ...     return subprocess.check_output(command, shell=True).decode()
        
        >>> @exec_guard(command_param="cmd")
        ... def execute(cmd: str, timeout: int = 30) -> str:
        ...     return subprocess.check_output(cmd, shell=True, timeout=timeout).decode()
    """
    param_map = {command_param: "command"}
    return guard(
        "exec",
        client=client,
        param_map=param_map,
        agent=agent,
        session=session,
        raise_on_deny=raise_on_deny,
    )


def read_guard(
    *,
    client: Optional[RampartClient] = None,
    path_param: str = "path",
    agent: Optional[str] = None,
    session: Optional[str] = None,
    raise_on_deny: bool = True,
) -> Callable[[F], F]:
    """Convenience decorator for read tool policy checks.
    
    Args:
        client: RampartClient instance (uses default if None)
        path_param: Name of the parameter containing the file path
        agent: Agent identifier for policy context
        session: Session identifier for policy context
        raise_on_deny: Whether to raise an exception when denied
    
    Example:
        >>> @read_guard()
        ... def read_file(path: str) -> str:
        ...     with open(path) as f:
        ...         return f.read()
        
        >>> @read_guard(path_param="filename")
        ... def load_config(filename: str) -> dict:
        ...     with open(filename) as f:
        ...         return json.load(f)
    """
    param_map = {path_param: "path"}
    return guard(
        "read",
        client=client,
        param_map=param_map,
        agent=agent,
        session=session,
        raise_on_deny=raise_on_deny,
    )


def write_guard(
    *,
    client: Optional[RampartClient] = None,
    path_param: str = "path",
    content_param: Optional[str] = None,
    agent: Optional[str] = None,
    session: Optional[str] = None,
    raise_on_deny: bool = True,
) -> Callable[[F], F]:
    """Convenience decorator for write tool policy checks.
    
    Args:
        client: RampartClient instance (uses default if None)
        path_param: Name of the parameter containing the file path
        content_param: Name of the parameter containing the content (optional)
        agent: Agent identifier for policy context
        session: Session identifier for policy context
        raise_on_deny: Whether to raise an exception when denied
    
    Example:
        >>> @write_guard()
        ... def write_file(path: str, content: str) -> None:
        ...     with open(path, 'w') as f:
        ...         f.write(content)
        
        >>> @write_guard(path_param="filename", content_param="data")
        ... def save_data(filename: str, data: str) -> None:
        ...     with open(filename, 'w') as f:
        ...         f.write(data)
    """
    param_map = {path_param: "path"}
    if content_param:
        param_map[content_param] = "content"
    
    return guard(
        "write",
        client=client,
        param_map=param_map,
        agent=agent,
        session=session,
        raise_on_deny=raise_on_deny,
    )


def fetch_guard(
    *,
    client: Optional[RampartClient] = None,
    url_param: str = "url",
    agent: Optional[str] = None,
    session: Optional[str] = None,
    raise_on_deny: bool = True,
) -> Callable[[F], F]:
    """Convenience decorator for fetch tool policy checks.
    
    Args:
        client: RampartClient instance (uses default if None)
        url_param: Name of the parameter containing the URL
        agent: Agent identifier for policy context
        session: Session identifier for policy context
        raise_on_deny: Whether to raise an exception when denied
    
    Example:
        >>> @fetch_guard()
        ... def fetch_url(url: str) -> str:
        ...     return httpx.get(url).text
        
        >>> @fetch_guard(url_param="endpoint")
        ... def api_call(endpoint: str, headers: dict) -> dict:
        ...     return httpx.get(endpoint, headers=headers).json()
    """
    param_map = {url_param: "url"}
    return guard(
        "fetch",
        client=client,
        param_map=param_map,
        agent=agent,
        session=session,
        raise_on_deny=raise_on_deny,
    )


def _extract_params(
    args: Dict[str, Any], param_map: Optional[Dict[str, str]]
) -> Dict[str, Any]:
    """Extract and map function parameters for policy evaluation.
    
    Args:
        args: Function arguments from inspect.BoundArguments
        param_map: Mapping from function parameter names to policy parameter names
    
    Returns:
        Dictionary of parameters for the policy check
    """
    if param_map is None:
        return args
    
    params = {}
    for func_param, policy_param in param_map.items():
        if func_param in args:
            params[policy_param] = args[func_param]
    
    return params