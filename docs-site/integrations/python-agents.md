---
title: Securing Python Agents
description: "Integrate Python AI agents with Rampart's HTTP preflight API. Check and audit the actions your code explicitly submits before execution."
---

# Python Agents

Integrate Rampart with any Python agent framework — LangChain, CrewAI, AutoGen, or custom code.

## Python SDK (source-distributed alpha)

Start the Rampart proxy:

```bash
rampart serve
```

The SDK is not currently published on PyPI. From a Rampart source checkout,
install it and put its fail-closed enforcement call directly at the execution
boundary:

```bash
python -m pip install ./sdks/python
```

```python
import subprocess
import rampart

@rampart.exec_guard()
def safe_exec(command: str) -> str:
    return subprocess.check_output(command, shell=True, text=True)
```

The decorator sends an `enforce: true` preflight at the actual call boundary,
consumes one-shot grants and call-count state exactly once, and does not execute
the function unless Rampart returns a consistent allow decision. Its default
client fails closed when the policy service is unavailable or malformed.

## Preflight API

Check if a command would be allowed without executing it:

```python
import rampart

def preflight(command: str) -> bool:
    """Check if a command is allowed without executing."""
    with rampart.RampartClient(fail_open=False) as client:
        return client.check_exec(command, agent="my-agent", session="s1").allowed
```

Preflight is a preview only. Never separate a preflight from later execution;
use `enforce`, `aenforce`, or a guard decorator at the execution boundary.

## LD_PRELOAD Alternative

For simpler integration, wrap your entire Python process:

This optional path requires a source-built native library; current release and
Homebrew packages contain only the Rampart CLI. Run `make -C preload install`
from a matching Rampart source checkout first.

```bash
rampart preload -- python my_agent.py
```

This can intercept supported exec-family calls that reach the dynamic loader,
including common `os.system()` and `subprocess` paths. It does not cover static
binaries, direct syscalls, in-process Python file or network I/O, or every
possible subprocess implementation.

## LangChain Example

```python
import subprocess
import rampart
from langchain.tools import tool

@tool
@rampart.exec_guard()
def run_command(command: str) -> str:
    """Execute a shell command only after Rampart authorizes this invocation."""
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout
```

## API Reference

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `POST` | `/v1/tool/{toolName}` | Evaluate a host-owned tool call |
| `POST` | `/v1/preflight/{toolName}` | Dry-run check |
| `GET` | `/v1/approvals` | Pending approvals |
| `POST` | `/v1/approvals/{id}/resolve` | Approve/deny |
| `GET` | `/healthz` | Health check |
