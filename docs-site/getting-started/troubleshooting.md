---
title: Troubleshooting
description: "Fix common Rampart setup issues for Claude Code, Cline, OpenClaw, and CLI environments. Diagnose PATH, hooks, services, and policy connection problems."
---

# Troubleshooting

Common issues and how to fix them.

## `rampart: command not found` {#rampart-command-not-found}

The `rampart` binary isn't in your `PATH`.

**If you installed with Homebrew:**

```bash
brew link rampart
```

**If you installed with `go install`:**

Add Go's bin directory to your PATH:

```bash
echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

Or symlink to a standard location:

```bash
sudo ln -sf $(go env GOPATH)/bin/rampart /usr/local/bin/rampart
```

## Commands aren't being blocked {#commands-not-blocked}

If your agent is running commands that should be denied:

### 1. Are hooks installed?

```bash
rampart doctor
```

If hooks aren't showing, reinstall:

```bash
rampart setup claude-code
```

### 2. Is your policy loading?

```bash
rampart status
```

Rampart looks for policies in this order:

1. Path specified via `--config` flag
2. `~/.rampart/policy.yaml`
3. Built-in `standard` profile (default)

### 3. Does your rule actually match?

Dry-run a specific command:

```bash
rampart test "rm -rf /"
```

Or pipe raw hook JSON:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | rampart hook
```

If the result is `allow` when you expect `deny`, your pattern doesn't match. Check:

- Glob patterns use `*` (matches anything) not regex
- `command_matches` patterns match the full command string
- Use `rampart policy lint` to catch typos and common mistakes

## Everything is blocked {#everything-blocked}

If every command gets denied, you probably have `default_action: deny` without enough `allow` rules.

**Quick fix** — switch to allow-by-default:

```yaml
version: "1"
default_action: allow  # Was: deny
```

**Better fix** — start from an example template:

```bash
cp policies/examples/web-developer.yaml ~/.rampart/policy.yaml
```

!!! warning "Don't use `deny` as default until you're ready"
    The `lockdown` template (`default_action: deny`) requires a complete allowlist. Start with `standard` or an example template and add deny rules for specific things.

## Hook error on Claude Code startup {#hook-error-startup}

If Claude Code shows an error about hooks failing, the most common cause is that `rampart` isn't in the PATH that Claude Code sees.

**Fix — symlink to a standard location:**

```bash
sudo ln -sf $(which rampart) /usr/local/bin/rampart
```

**Verify the hook config:**

```bash
cat ~/.claude/settings.json | python3 -m json.tool
```

You should see `rampart hook` in the PreToolUse hooks. If the path is wrong, re-run:

```bash
rampart setup claude-code
```

## How do I uninstall? {#uninstall}

Remove the hooks from your agent:

```bash
rampart setup claude-code --remove
```

This only removes the hooks — your policy and audit files stay in `~/.rampart/`.

To fully remove:

```bash
# Remove hooks
rampart setup claude-code --remove

# Remove the binary
brew uninstall rampart  # or: rm $(which rampart)

# Optionally remove config and audit data
rm -rf ~/.rampart
```

## How do I check if it's working? {#check-working}

```bash
# Health check
rampart doctor

# Quick status
rampart status

# Dry-run a command against your policy
rampart test "rm -rf /"
rampart test --tool read "/etc/shadow"
```

## Still stuck?

- Check [GitHub Issues](https://github.com/peg/rampart/issues)
- Run `rampart doctor` and include the output in your issue
- Email rampartsec@pm.me
