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

# Create install directory
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# Extract
Write-Status "Installing to $InstallDir..."
try {
    Expand-Archive -Path $tempZip -DestinationPath $InstallDir -Force
} catch {
    Write-Err "Extraction failed: $_"
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

# Add to PATH if not already there (both persistent and current session)
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($userPath -notlike "*$InstallDir*") {
    Write-Status "Adding to PATH..."
    [Environment]::SetEnvironmentVariable("PATH", "$InstallDir;$userPath", "User")
    Write-Success "Added $InstallDir to PATH"
} else {
    Write-Status "Already in PATH"
}

# IMPORTANT: Update current session PATH to include both User and Machine paths
# This ensures rampart works immediately without restarting the terminal
$machinePath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
$newUserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
$env:PATH = "$newUserPath;$machinePath"

# Verify installation
Write-Host ""
try {
    $versionOutput = & $rampartExe version 2>&1
    Write-Success "Installed: $($versionOutput | Select-Object -First 1)"
} catch {
    Write-Warn "Installed but could not verify version"
}

# Auto-create policy directory and install standard policy
Write-Status "Installing standard policy..."
$policyDir = "$env:USERPROFILE\.rampart\policies"
if (-not (Test-Path $policyDir)) {
    New-Item -ItemType Directory -Path $policyDir -Force | Out-Null
}
try {
    & $rampartExe init --profile standard --force 2>&1 | Out-Null
    Write-Success "Policy installed to $policyDir"
} catch {
    Write-Warn "Could not install policy. Run 'rampart init --profile standard' manually."
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
Write-Host "  You're protected! Dangerous commands are now blocked." -ForegroundColor Green
Write-Host ""
Write-Host "  Try it:" -ForegroundColor White
Write-Host "    rampart test `"rm -rf /`"    # Should show DENY"
Write-Host "    rampart doctor              # Check installation"
Write-Host "    rampart watch               # Live dashboard"
Write-Host ""
Write-Host "  Docs: https://docs.rampart.sh"
Write-Host "  Uninstall: rampart uninstall"
Write-Host ""
