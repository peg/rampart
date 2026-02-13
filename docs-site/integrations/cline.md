# Cline

Cline supports native hooks, similar to Claude Code. Rampart integrates directly with Cline's hook system.

## Setup

```bash
rampart setup cline
```

This installs native hooks that intercept exec and file operations before they execute.

## How It Works

Same as [Claude Code](claude-code.md) — Cline's hook system sends tool calls to `rampart hook` for evaluation. Denied calls return an error to Cline, which never executes them.

## Usage

Launch Cline normally from VS Code. Rampart evaluates every tool call transparently.

## Monitor

```bash
rampart watch
```

## Uninstall

```bash
## Uninstall

To remove Rampart hooks, edit your Cline MCP settings in VS Code and delete the Rampart hook entries, then restart Cline.
```
