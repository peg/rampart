---
title: Securing Python Agents
description: "Protect Python AI agents with Rampart's HTTP preflight API. Check commands before execution, enforce policy decisions, and log every tool action."
---

# Python Agents

Integrate Rampart with any Python agent framework — LangChain, CrewAI, AutoGen, or custom code.

## HTTP API

Start the Rampart proxy:

```bash
rampart serve
```

Then check commands before executing them:

```python
import requests
import time

RAMPART_URL = "http://localhost:9090"
RAMPART_TOKEN = "your-token"

def safe_exec(command: str) -> dict:
    """Check a command with Rampart before executing."""
    response = requests.post(
        f"{RAMPART_URL}/v1/tool/exec",
        headers={"Authorization": f"Bearer {RAMPART_TOKEN}"},
        json={
            "agent": "my-python-agent",
            "session": "session-1",
            "params": {"command": command}
        }
    )
    result = response.json()

    if result["decision"] == "deny":
        return {"blocked": True, "reason": result["message"]}
    elif result["decision"] == "require_approval":
        # Poll for approval resolution
        approval_id = result["approval_id"]
        while True:
            status_response = requests.get(f"{RAMPART_URL}/v1/approvals/{approval_id}")
            status = status_response.json()
            if status["status"] == "approved":
                break
            elif status["status"] in ["denied", "expired"]:
                return {"blocked": True, "reason": status.get("message", "Approval denied")}
            time.sleep(1)  # Poll every second

    # Command was allowed — execute it
    import subprocess
    output = subprocess.run(command, shell=True, capture_output=True, text=True)
    return {"blocked": False, "output": output.stdout}
```

## Preflight API

Check if a command would be allowed without executing it:

```python
def preflight(command: str) -> bool:
    """Check if a command is allowed without executing."""
    response = requests.post(
        f"{RAMPART_URL}/v1/preflight/exec",
        headers={"Authorization": f"Bearer {RAMPART_TOKEN}"},
        json={
            "agent": "my-agent",
            "session": "s1",
            "params": {"command": command}
        }
    )
    return response.json()["allowed"]
```

## LD_PRELOAD Alternative

For simpler integration, wrap your entire Python process:

```bash
rampart preload -- python my_agent.py
```

This intercepts all `os.system()`, `subprocess.run()`, and `os.exec*()` calls automatically — no code changes needed.

## LangChain Example

```python
from langchain.tools import tool

@tool
def run_command(command: str) -> str:
    """Execute a shell command (Rampart-protected)."""
    resp = requests.post(
        f"{RAMPART_URL}/v1/tool/exec",
        headers={"Authorization": f"Bearer {RAMPART_TOKEN}"},
        json={"agent": "langchain", "session": "s1", "params": {"command": command}}
    )
    data = resp.json()
    if data["decision"] == "deny":
        return f"Command blocked by policy: {data['message']}"
    # Rampart only evaluates policy — execute the command yourself
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout
```

## API Reference

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `POST` | `/v1/tool/{toolName}` | Evaluate and execute |
| `POST` | `/v1/preflight/{toolName}` | Dry-run check |
| `GET` | `/v1/approvals` | Pending approvals |
| `POST` | `/v1/approvals/{id}/resolve` | Approve/deny |
| `GET` | `/healthz` | Health check |
