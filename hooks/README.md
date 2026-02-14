# Rampart Node.js FS Hook

Intercepts Node.js file system operations (`fs.readFile`, `fs.writeFile`, sync and async variants) and checks them against Rampart policy before allowing execution.

## Why?

Claude Code's native Read/Write/Edit tools operate at the Node.js level, bypassing Rampart's shell-level `PreToolUse` hooks. This `--require` hook catches those operations at the `fs` module level.

## Install

```bash
export NODE_OPTIONS="--require $HOME/clawd/rampart/hooks/node-fs-hook.js"
```

Add to your shell profile (`.bashrc`, `.zshrc`) to make it persistent. Future Rampart releases will automate this via `rampart setup claude-code`.

## Configuration

| Env Var | Default | Description |
|---------|---------|-------------|
| `RAMPART_URL` | `http://127.0.0.1:19090` | Rampart serve endpoint |
| `RAMPART_TOKEN` | *(none)* | Optional bearer token |

## How It Works

1. Monkey-patches `fs.readFileSync`, `fs.writeFileSync`, `fs.readFile`, `fs.writeFile`, and their `fs.promises` equivalents
2. For each call, resolves the file path and checks if it's a "user file" worth policy-checking
3. Sends a sync HTTP request (via `curl`) to Rampart's `/v1/tool/{read,write}` endpoint
4. If Rampart returns 403, throws an error visible to Claude Code
5. If Rampart is unreachable, **fails open** (operation proceeds normally)

## Performance

- **Fast-path skipping**: Only checks paths under `$HOME` (plus sensitive system files like `/etc/shadow`). Skips `node_modules`, `.claude/`, `/tmp/claude-*`, `/proc/`, `/dev/`, `/sys/`.
- **1-second deny cache**: Avoids hammering Rampart on repeated reads of the same file.
- **500ms timeout**: Sync HTTP calls use a 500ms max timeout to avoid blocking Claude Code.

## Tradeoffs

- **Sync HTTP calls**: The biggest risk. `readFileSync`/`writeFileSync` require synchronous policy checks, implemented via `child_process.execFileSync` calling `curl`. This adds ~5-50ms latency per checked file operation.
- **Fail-open**: If Rampart isn't running, all operations are allowed. This prevents the hook from breaking Claude Code but means policy isn't enforced when Rampart is down.
- **No Edit endpoint**: `fs` doesn't have an "edit" primitive — edits are read+write, so they're caught as separate read and write checks.

## Testing

```bash
# Should work normally (reads a safe file)
NODE_OPTIONS="--require $HOME/clawd/rampart/hooks/node-fs-hook.js" \
  node -e "console.log(require('fs').readFileSync('/etc/hostname', 'utf-8'))"

# Should fail if Rampart denies /etc/shadow
NODE_OPTIONS="--require $HOME/clawd/rampart/hooks/node-fs-hook.js" \
  node -e "require('fs').readFileSync('/etc/shadow')"
```
