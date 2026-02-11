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

"""Types and exceptions for the Rampart SDK."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Decision:
    """The result of a policy evaluation.
    
    Contains the policy decision and metadata about the evaluation.
    """
    
    allowed: bool
    """True if the tool call would be allowed to proceed."""
    
    action: str
    """The policy action: allow, deny, log, or require_approval."""
    
    message: str
    """Human-readable reason for the decision."""
    
    policies: List[str]
    """Names of policies that matched during evaluation."""
    
    eval_duration_ms: float
    """Time taken to evaluate the policy in milliseconds."""


class RampartError(Exception):
    """Base exception for Rampart SDK errors."""
    pass


class RampartConnectionError(RampartError):
    """Raised when unable to connect to the Rampart server."""
    pass


class RampartDeniedError(RampartError):
    """Raised when a tool call is denied by policy.
    
    This exception contains details about which policy blocked the call
    and why it was blocked.
    """
    
    def __init__(self, tool: str, policy: Optional[str] = None, message: str = ""):
        self.tool = tool
        self.policy = policy
        self.message = message
        
        if policy:
            error_msg = f"Tool '{tool}' denied by policy '{policy}': {message}"
        else:
            error_msg = f"Tool '{tool}' denied: {message}"
        
        super().__init__(error_msg)


class RampartServerError(RampartError):
    """Raised when the Rampart server returns an error response."""
    
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"Server error {status_code}: {message}")