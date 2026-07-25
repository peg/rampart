# Windows Setup Guide

Rampart builds and tests its policy engine plus Claude Code and Codex hook setup
on Windows CI. A physical Windows host E2E is still pending, and Unix-specific
integration modes remain unavailable.

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

This adds lifecycle hooks to `~\.claude\settings.json`. Claude Code routes
hook-visible Bash and PowerShell calls through Rampart.

## Basic Hook Protection Is Configured

After setup, matched hook-visible calls can be denied locally without
`rampart serve`. This does not create an OS sandbox or cover host actions that
Claude does not emit to hooks.

## Optional: Policy Server

Run `rampart serve` if you want:
- **Live dashboard** — `rampart watch` shows real-time decisions
- **External/headless approval flow** — Claude's native `ask` prompt itself does not require serve
- **Centralized audit** — stream events to the dashboard

```powershell
rampart serve
```

> **Note:** On Windows, `rampart serve` runs in the foreground. Keep the terminal window open, or use Task Scheduler/NSSM to run it at startup.

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
| `rampart upgrade` | ⚠️ Re-run installer | Required when upgrading affected v1.2.x installations |
| `rampart wrap` | ❌ Unix only | Uses `$SHELL` |
| `rampart preload` | ❌ Linux only | Uses LD_PRELOAD |

For the v1.2.x to v1.3.0 upgrade, rerun `irm https://rampart.sh/install.ps1 | iex`. The installer repairs the affected legacy `~\.rampart` ACL before replacing the binary. If that directory is locked, the existing `rampart.exe` may not be able to start `rampart upgrade`.

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

`C:\Users\dev\.ssh\id_rsa` will match `**/.ssh/id_*` correctly.

## Uninstall

```powershell
rampart uninstall
```

Remove each configured integration with its `rampart setup <agent> --remove`
command before deleting the binary and data directory.

**Manual cleanup** (if rampart command isn't working):
```powershell
# Delete Rampart files
Remove-Item -Recurse -Force ~\.rampart
```

Then remove `%USERPROFILE%\.rampart\bin` from PATH: **Settings → System → About → Advanced system settings → Environment Variables**.

## Troubleshooting

### Windows Defender / Antivirus Warnings

Rampart is an unsigned binary that modifies other programs' configurations (Claude Code hooks). This may trigger security warnings:

**SmartScreen "Windows protected your PC":**
1. Click "More info"
2. Click "Run anyway"

**Windows Defender quarantine:**
1. Open Windows Security → Virus & threat protection
2. Click "Protection history"
3. Find Rampart, select "Restore" and "Allow on device"

**Corporate antivirus blocking:**
Contact your IT team to whitelist `rampart.exe`, or install to a location your AV trusts.

> **Why does this happen?** Rampart hooks into other programs and intercepts command execution — behaviors that look suspicious to antivirus heuristics. The binary is not code-signed (certificates cost ~$400/year). We're working on getting Rampart whitelisted with major AV vendors.

### "rampart is not recognized"

The installer refreshes PATH automatically, but if it doesn't work:
```powershell
$env:PATH = "$env:USERPROFILE\.rampart\bin;$env:PATH"
```

Or restart your terminal.

### Installation fails with "Access Denied"

If a previous install left files with broken permissions:

```powershell
# Run as Administrator
takeown /f "$env:USERPROFILE\.rampart" /r /d y
icacls "$env:USERPROFILE\.rampart" /grant "$($env:USERNAME):F" /t
Remove-Item -Recurse -Force "$env:USERPROFILE\.rampart"

# Then re-run installer
irm https://rampart.sh/install.ps1 | iex
```

### Claude Code not seeing hooks

1. Verify hooks are installed: `rampart doctor`
2. Check settings file exists: `Test-Path ~\.claude\settings.json`
3. Re-run setup: `rampart setup claude-code --force`

### Policy not blocking commands

1. Make sure `rampart serve` is running
2. Check the serve URL matches (default: `http://localhost:9090`)
3. Test directly: `rampart test "your-command"`

## Known Behavior

### `action: ask` in `--dangerously-skip-permissions` mode

`action: ask` shows the native approval prompt even when Claude Code is launched with `--dangerously-skip-permissions`. Claude Code honors hook-returned permission decisions regardless of the bypass flag.

## Next Steps

- [Writing Policies](../README.md#writing-policies) — customize what's allowed
- [Native Ask Prompt](./native-ask.md) — inline approval dialogs for sensitive commands
- [Live Dashboard](../README.md#live-dashboard) — monitor in real-time with `rampart watch`
