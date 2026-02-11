# Rampart Python SDK

[![PyPI version](https://badge.fury.io/py/rampart-sdk.svg)](https://badge.fury.io/py/rampart-sdk)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-yellow.svg)](https://opensource.org/licenses/Apache-2.0)

Python SDK for [Rampart](https://rampart.sh), an open-source policy engine for AI agent tool calls.

## Installation

```bash
pip install rampart-sdk
```

## Quick Start

### Basic Client Usage

```python
import rampart

# Create a client (reads RAMPART_URL and RAMPART_TOKEN from environment)
client = rampart.RampartClient()

# Check if an exec command would be allowed
decision = client.check_exec("rm -rf /")
if not decision.allowed:
    print(f"Command blocked: {decision.message}")
else:
    print("Command is allowed")

# Check other tool types
decision = client.check_read("/etc/passwd")
decision = client.check_write("/tmp/output.txt", content="Hello world")
decision = client.check_fetch("https://api.example.com/data")

# Check server health
if client.health():
    print("Rampart server is healthy")
```

### Decorator Usage

```python
import subprocess
import rampart

# Wrap functions with policy checks
@rampart.exec_guard()
def run_command(command: str) -> str:
    """Execute a shell command with policy enforcement."""
    return subprocess.check_output(command, shell=True, text=True)

@rampart.read_guard()
def read_file(path: str) -> str:
    """Read a file with policy enforcement."""
    with open(path) as f:
        return f.read()

@rampart.write_guard()
def write_file(path: str, content: str) -> None:
    """Write to a file with policy enforcement."""
    with open(path, 'w') as f:
        f.write(content)

# Functions will automatically check policies before executing
try:
    result = run_command("git status")
    print(result)
except rampart.RampartDeniedError as e:
    print(f"Command denied: {e}")
```

### Custom Decorators

```python
@rampart.guard("exec", param_map={"cmd": "command"})
def execute(cmd: str, timeout: int = 30) -> str:
    """Custom parameter mapping for policy checks."""
    return subprocess.check_output(
        cmd, shell=True, text=True, timeout=timeout
    )

@rampart.guard("custom_tool", agent="my-agent", session="session-123")
def custom_function(data: dict) -> dict:
    """Custom tool with explicit agent/session context."""
    # Your custom logic here
    return {"status": "processed", "data": data}
```

### Async Support

```python
import asyncio
import httpx
import rampart

async def main():
    # Async client usage
    async with rampart.RampartClient() as client:
        # Check policies asynchronously
        decision = await client.acheck_exec("git push")
        if decision.allowed:
            print("Git push is allowed")
        
        # Check server health
        healthy = await client.ahealth()
        print(f"Server healthy: {healthy}")

# Async decorators
@rampart.fetch_guard()
async def fetch_data(url: str) -> dict:
    """Fetch data with policy enforcement."""
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
        return response.json()

# Run async code
asyncio.run(main())
```

## Configuration

### Environment Variables

- `RAMPART_URL`: Rampart server URL (default: `http://localhost:19090`)
- `RAMPART_TOKEN`: Bearer token for authentication (optional)

### Client Configuration

```python
# Custom configuration
client = rampart.RampartClient(
    url="http://rampart.example.com:8080",
    token="your-auth-token",
    fail_open=True,  # Allow calls if server is unreachable (default)
    timeout=30.0,    # Request timeout in seconds
)

# Fail-closed mode (deny calls if server is unreachable)
strict_client = rampart.RampartClient(fail_open=False)
```

## API Reference

### RampartClient

#### Methods

- `health() -> bool`: Check server health
- `preflight(tool, params, agent=None, session=None) -> Decision`: Generic policy check
- `check_exec(command, agent=None, session=None, use_b64=False) -> Decision`: Check exec command
- `check_read(path, agent=None, session=None) -> Decision`: Check file read
- `check_write(path, content=None, agent=None, session=None) -> Decision`: Check file write  
- `check_fetch(url, agent=None, session=None) -> Decision`: Check URL fetch

All methods have async equivalents prefixed with `a` (e.g., `ahealth()`, `apreflight()`).

### Decision Object

```python
@dataclass
class Decision:
    allowed: bool              # Whether the call is allowed
    action: str               # Policy action: allow, deny, log, require_approval
    message: str              # Human-readable reason
    policies: List[str]       # Names of matched policies
    eval_duration_ms: float   # Evaluation time in milliseconds
```

### Exceptions

- `RampartError`: Base exception
- `RampartConnectionError`: Server connection failed
- `RampartDeniedError`: Tool call denied by policy
- `RampartServerError`: Server returned an error

### Decorators

- `@guard(tool_name, ...)`: Generic policy decorator
- `@exec_guard(...)`: Exec tool decorator
- `@read_guard(...)`: Read tool decorator  
- `@write_guard(...)`: Write tool decorator
- `@fetch_guard(...)`: Fetch tool decorator

#### Decorator Parameters

- `client`: Custom RampartClient instance
- `param_map`: Map function parameters to policy parameters
- `agent`: Agent identifier for policy context
- `session`: Session identifier for policy context
- `raise_on_deny`: Whether to raise exception on denial (default: True)

## Examples

### Basic Error Handling

```python
import rampart

client = rampart.RampartClient()

try:
    decision = client.check_exec("rm -rf /")
    if decision.allowed:
        print("Dangerous command is somehow allowed!")
    else:
        print(f"Command blocked by policy: {decision.policies}")
        
except rampart.RampartConnectionError:
    print("Cannot reach Rampart server")
    
except rampart.RampartServerError as e:
    print(f"Server error: {e.status_code} - {e.message}")
```

### Advanced Decorator Usage

```python
# Custom client for specific functions
secure_client = rampart.RampartClient(fail_open=False)
rampart.set_default_client(secure_client)

@rampart.exec_guard(
    command_param="script_path",
    agent="deployment-bot", 
    session="deploy-prod-v1.2.3"
)
def run_deployment_script(script_path: str, env: str) -> str:
    """Run deployment with strict policy enforcement."""
    return subprocess.check_output([script_path, env], text=True)

# Parameter mapping for complex functions
@rampart.guard(
    "database",
    param_map={
        "query": "sql",
        "database": "db_name"
    }
)
def execute_query(query: str, database: str, timeout: int = 30) -> list:
    """Execute SQL with policy checks on query and database."""
    # Your database logic here
    pass
```

### Integration with Existing Code

```python
# Gradually add policy checks to existing functions
def unsafe_file_operation(path: str) -> str:
    with open(path) as f:
        return f.read()

# Add policy check without changing function signature
safe_file_operation = rampart.read_guard()(unsafe_file_operation)

# Or check policies manually
def manual_policy_check(path: str) -> str:
    client = rampart.RampartClient()
    decision = client.check_read(path)
    
    if not decision.allowed:
        raise ValueError(f"File access denied: {decision.message}")
    
    return unsafe_file_operation(path)
```

## Development

### Running Tests

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=rampart --cov-report=html
```

### Code Formatting

```bash
# Format code
black rampart/ tests/
isort rampart/ tests/

# Type checking
mypy rampart/
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please see the [Contributing Guide](https://github.com/peg/rampart/blob/main/CONTRIBUTING.md) for details.

## Support

- 📖 [Documentation](https://rampart.sh/docs)
- 🐛 [Issue Tracker](https://github.com/peg/rampart/issues)
- 💬 [Discussions](https://github.com/peg/rampart/discussions)