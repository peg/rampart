# Windows Setup Guide

Rampart fully supports Windows for protecting Claude Code and other AI agents.

## Quick Install

```powershell
irm https://rampart.sh/install.ps1 | iex
```

This downloads the latest release, installs to `~\.rampart\bin`, adds it to your PATH, and offers to set up Claude Code hooks automatically.

**Manual install:** Download the `.zip` from [GitHub Releases](https://github.com/peg/rampart/releases), extract `rampart.exe`, and add to your PATH.

## Setup Claude Code

```powershell
rampart setup claude-code
```

This adds hooks to `~\.claude\settings.json`. Claude Code will now route all Bash commands through Rampart.

## Running the Policy Server

```powershell
rampart serve
```

> **Note:** On Windows, `rampart serve` runs in the foreground. Keep the terminal window open while using Claude Code. Background service support (`--background`) is planned for a future release.

For a more permanent setup, you can:
1. Create a scheduled task to run `rampart serve` at login
2. Use [NSSM](https://nssm.cc/) to wrap it as a Windows service

## Verify Installation

```powershell
# Check version
rampart version

# Health check
rampart doctor

# Test a command against your policy
rampart test "rm -rf /"
```

## Windows-Specific Notes

### What Works

| Feature | Status |
|---------|--------|
| `rampart serve` | ✅ Works (foreground only) |
| `rampart setup claude-code` | ✅ Works |
| `rampart hook` | ✅ Works |
| `rampart test` | ✅ Works |
| `rampart watch` | ✅ Works |
| `rampart mcp` | ✅ Works |
| Path-based policies | ✅ Works (auto-converts `\` to `/`) |

### Limitations

| Feature | Status | Notes |
|---------|--------|-------|
| `rampart serve --background` | ❌ Unix only | Uses fork/exec |
| `rampart serve stop` | ❌ Unix only | Uses SIGTERM |
| `rampart upgrade` | ❌ Unix only | Re-run installer instead |
| `rampart wrap` | ❌ Unix only | Uses `$SHELL` |
| `rampart preload` | ❌ Linux only | Uses LD_PRELOAD |

### Path Matching

Rampart automatically normalizes Windows paths for policy matching:

```yaml
# This policy works on both Windows and Unix:
- name: block-ssh-keys
  match:
    tool: [read]
  rules:
    - action: deny
      when:
        path_matches:
          - "**/.ssh/id_*"
      message: "SSH key access blocked"
```

`C:\Users\Trevor\.ssh\id_rsa` will match `**/.ssh/id_*` correctly.

## Uninstall

```powershell
# Remove hooks from Claude Code
rampart setup claude-code --remove

# Delete Rampart files
Remove-Item -Recurse ~\.rampart
```

To also remove from PATH, go to **Settings → System → About → Advanced system settings → Environment Variables** and remove `%USERPROFILE%\.rampart\bin` from your user PATH.

## Troubleshooting

### "rampart is not recognized"

Restart your terminal after installation, or manually refresh PATH:
```powershell
$env:PATH = [Environment]::GetEnvironmentVariable("PATH", "User") + ";" + $env:PATH
```

### Claude Code not seeing hooks

1. Verify hooks are installed: `rampart doctor`
2. Check settings file exists: `Test-Path ~\.claude\settings.json`
3. Re-run setup: `rampart setup claude-code --force`

### Policy not blocking commands

1. Make sure `rampart serve` is running
2. Check the serve URL matches (default: `http://localhost:9090`)
3. Test directly: `rampart test "your-command"`

## Next Steps

- [Writing Policies](../README.md#writing-policies) — customize what's allowed
- [Live Dashboard](../README.md#live-dashboard) — monitor in real-time with `rampart watch`
