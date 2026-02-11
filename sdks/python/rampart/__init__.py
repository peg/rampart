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

"""Rampart SDK for Python.

This package provides a client library for integrating with Rampart,
an open-source policy engine for AI agent tool calls.

Basic usage:

    >>> import rampart
    >>> client = rampart.RampartClient()
    >>> decision = client.check_exec("rm -rf /")
    >>> if not decision.allowed:
    ...     print(f"Command blocked: {decision.message}")

Decorator usage:

    >>> @rampart.guard("exec")
    ... def run_command(command: str) -> str:
    ...     return subprocess.check_output(command, shell=True).decode()

For async support:

    >>> async def check_command():
    ...     async with rampart.RampartClient() as client:
    ...         decision = await client.acheck_exec("git push")
    ...         return decision.allowed
"""

from .client import RampartClient
from .decorators import (
    exec_guard,
    fetch_guard,
    guard,
    read_guard,
    set_default_client,
    write_guard,
)
from .types import (
    Decision,
    RampartConnectionError,
    RampartDeniedError,
    RampartError,
    RampartServerError,
)

__version__ = "0.1.0"

__all__ = [
    # Client
    "RampartClient",
    
    # Types
    "Decision",
    
    # Exceptions
    "RampartError", 
    "RampartConnectionError",
    "RampartDeniedError",
    "RampartServerError",
    
    # Decorators
    "guard",
    "exec_guard",
    "read_guard", 
    "write_guard",
    "fetch_guard",
    "set_default_client",
]