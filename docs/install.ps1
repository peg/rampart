#!/usr/bin/env pwsh
# Rampart Windows Installer
# Usage: irm https://rampart.sh/install.ps1 | iex
#
# This script downloads the latest Rampart release, installs it to ~/.rampart/bin,
# and adds it to your PATH. No admin rights required.

$ErrorActionPreference = "Stop"

$RepoOwner = "peg"
$RepoName = "rampart"
$InstallDir = "$env:USERPROFILE\.rampart\bin"

function Write-Status($msg) { Write-Host "  $msg" -ForegroundColor Cyan }
function Write-Success($msg) { Write-Host "✓ $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "⚠ $msg" -ForegroundColor Yellow }
function Write-Err($msg) { Write-Host "✗ $msg" -ForegroundColor Red }

Write-Host ""
Write-Host "🛡️  Rampart Installer" -ForegroundColor White
Write-Host ""

# Detect architecture
$arch = if ([Environment]::Is64BitOperatingSystem) {
    if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
} else {
    Write-Err "32-bit Windows is not supported"
    exit 1
}

Write-Status "Detected: Windows $arch"

# Get latest release
Write-Status "Fetching latest release..."
try {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$RepoOwner/$RepoName/releases/latest"
    $version = $release.tag_name
} catch {
    Write-Err "Failed to fetch latest release: $_"
    exit 1
}

Write-Status "Latest version: $version"

# Find the right asset
$assetName = "rampart_$($version -replace '^v','')_windows_$arch.zip"
$asset = $release.assets | Where-Object { $_.name -eq $assetName }

if (-not $asset) {
    Write-Err "Could not find asset: $assetName"
    Write-Err "Available assets:"
    $release.assets | ForEach-Object { Write-Host "  - $($_.name)" }
    exit 1
}

# Download
$downloadUrl = $asset.browser_download_url
$tempZip = "$env:TEMP\rampart-$version.zip"

Write-Status "Downloading $assetName..."
try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $tempZip -UseBasicParsing
} catch {
    Write-Err "Download failed: $_"
    exit 1
}

# Create install directory (clear existing to avoid conflicts)
if (Test-Path $InstallDir) {
    Write-Status "Removing previous installation..."
    try {
        Remove-Item -Recurse -Force $InstallDir -ErrorAction Stop
    } catch {
        Write-Err "Cannot remove existing installation at $InstallDir"
        Write-Err "This usually means files are locked or have permission issues."
        Write-Host ""
        Write-Host "  Try these steps:" -ForegroundColor Yellow
        Write-Host "    1. Close all terminals and Claude Code"
        Write-Host "    2. Run PowerShell as Administrator and execute:"
        Write-Host "       takeown /f `"$InstallDir`" /r /d y" -ForegroundColor Cyan
        Write-Host "       icacls `"$InstallDir`" /grant `"$env:USERNAME`:F`" /t" -ForegroundColor Cyan
        Write-Host "       Remove-Item -Recurse -Force `"$InstallDir`"" -ForegroundColor Cyan
        Write-Host "    3. Re-run this installer"
        Write-Host ""
        Remove-Item $tempZip -Force -ErrorAction SilentlyContinue
        exit 1
    }
}
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

# Extract
Write-Status "Installing to $InstallDir..."
try {
    Expand-Archive -Path $tempZip -DestinationPath $InstallDir -Force
} catch {
    Write-Err "Extraction failed: $_"
    # Clean up partial install to avoid permission issues on retry
    Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
    Remove-Item $tempZip -Force -ErrorAction SilentlyContinue
    exit 1
}

# Clean up
Remove-Item $tempZip -Force -ErrorAction SilentlyContinue

# Verify binary exists
$rampartExe = "$InstallDir\rampart.exe"
if (-not (Test-Path $rampartExe)) {
    Write-Err "Installation failed: rampart.exe not found"
    exit 1
}

# Add to PATH if not already there
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($userPath -notlike "*$InstallDir*") {
    Write-Status "Adding to PATH..."
    [Environment]::SetEnvironmentVariable("PATH", "$InstallDir;$userPath", "User")
    $env:PATH = "$InstallDir;$env:PATH"
    Write-Success "Added $InstallDir to PATH"
} else {
    Write-Status "Already in PATH"
}

# Verify installation
Write-Host ""
try {
    $versionOutput = & $rampartExe version 2>&1
    Write-Success "Installed: $($versionOutput | Select-Object -First 1)"
} catch {
    Write-Warn "Installed but could not verify version"
}

# Offer to set up Claude Code
Write-Host ""
$claudeSettings = "$env:USERPROFILE\.claude\settings.json"
if (Test-Path $claudeSettings) {
    Write-Host "Claude Code detected!" -ForegroundColor White
    $setup = Read-Host "  Set up Rampart hooks for Claude Code? [Y/n]"
    if ($setup -eq "" -or $setup -match "^[Yy]") {
        & $rampartExe setup claude-code
    }
} else {
    Write-Status "Claude Code not detected. Run 'rampart setup claude-code' after installing Claude."
}

# Done
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
Write-Success "Rampart installed successfully!"
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor White
Write-Host "    1. Restart your terminal (or run: `$env:PATH = [Environment]::GetEnvironmentVariable('PATH', 'User'))"
Write-Host "    2. Run: rampart setup claude-code"
Write-Host "    3. Use Claude Code — dangerous commands are now blocked!"
Write-Host ""
Write-Host "  Optional: Run 'rampart serve' for the live dashboard and approval flow."
Write-Host ""
Write-Host "  Docs: https://docs.rampart.sh"
Write-Host "  Uninstall: Remove-Item -Recurse ~\.rampart"
Write-Host ""
