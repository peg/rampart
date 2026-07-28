#!/usr/bin/env pwsh
# Rampart Windows Installer
# Usage: irm https://rampart.sh/install.ps1 | iex
#
# This script downloads the latest Rampart release, installs it to ~/.rampart/bin,
# and adds it to your PATH. No admin rights required.

$ErrorActionPreference = "Stop"

$RepoOwner = "peg"
$RepoName = "rampart"
$RampartDir = "$env:USERPROFILE\.rampart"
$InstallDir = "$env:USERPROFILE\.rampart\bin"

function Write-Status($msg) { Write-Host "  $msg" -ForegroundColor Cyan }
function Write-Success($msg) { Write-Host "✓ $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "⚠ $msg" -ForegroundColor Yellow }
function Write-Err($msg) { Write-Host "✗ $msg" -ForegroundColor Red }

function Test-IsUnauthorizedAccess($errorRecord) {
    $exception = $errorRecord.Exception
    while ($null -ne $exception) {
        if ($exception -is [System.UnauthorizedAccessException]) { return $true }
        $exception = $exception.InnerException
    }
    return $false
}

function Test-DirectoryExistsFromParent($path) {
    $parent = Split-Path -Parent $path
    $leaf = Split-Path -Leaf $path
    foreach ($candidate in [System.IO.Directory]::EnumerateDirectories(
        $parent,
        $leaf,
        [System.IO.SearchOption]::TopDirectoryOnly
    )) {
        if ([System.StringComparer]::OrdinalIgnoreCase.Equals($candidate, $path)) {
            return $true
        }
    }
    return $false
}

function Test-DirectoryWritable($path) {
    $probe = Join-Path $path ".rampart-installer-$([Guid]::NewGuid().ToString('N')).tmp"
    try {
        [System.IO.File]::WriteAllText($probe, "")
        [System.IO.File]::Delete($probe)
        return $true
    } catch {
        try { [System.IO.File]::Delete($probe) } catch { }
        if (Test-IsUnauthorizedAccess $_) { return $false }
        throw
    }
}

function Repair-LegacyRampartDirectoryAcl {
    if (-not (Test-DirectoryExistsFromParent $RampartDir)) { return }
    if (Test-DirectoryWritable $RampartDir) { return }

    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = Get-Acl -LiteralPath $RampartDir
    $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
    if ($ownerSid.Value -ne $currentSid.Value) {
        throw "Refusing to repair $RampartDir because it is not owned by the current user."
    }
    if (-not $acl.AreAccessRulesProtected) {
        throw "Refusing to repair $RampartDir because it does not have the legacy protected ACL."
    }

    $explicitRules = $acl.GetAccessRules(
        $true,
        $false,
        [System.Security.Principal.SecurityIdentifier]
    )
    foreach ($rule in $explicitRules) {
        if ($rule.IdentityReference.Value -eq $currentSid.Value) {
            throw "Refusing to replace an existing explicit ACL for the current user on $RampartDir."
        }
    }

    $accessRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $currentSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.InheritanceFlags]::None,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    [void]$acl.AddAccessRule($accessRule)
    $acl.SetAccessRuleProtection($false, $true)
    Set-Acl -LiteralPath $RampartDir -AclObject $acl

    if (-not (Test-DirectoryWritable $RampartDir)) {
        throw "The ACL repair completed but $RampartDir is still inaccessible."
    }
    Write-Success "Repaired permissions from an affected Rampart 1.2.x installation"
}

Write-Host ""
Write-Host "🛡️  Rampart Installer" -ForegroundColor White
Write-Host ""

try {
    Repair-LegacyRampartDirectoryAcl
} catch {
    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    Write-Err "Cannot safely access $RampartDir`: $_"
    Write-Host ""
    Write-Host "  To repair it manually, run PowerShell as Administrator:" -ForegroundColor Yellow
    Write-Host "    icacls `"$RampartDir`" /grant `"*$($currentSid):F`"" -ForegroundColor Cyan
    Write-Host "    icacls `"$RampartDir`" /inheritance:e" -ForegroundColor Cyan
    exit 1
}

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

# Verify checksum (goreleaser produces checksums.txt with each release)
Write-Status "Verifying checksum..."
$checksumAsset = $release.assets | Where-Object { $_.name -eq "checksums.txt" }
if ($checksumAsset) {
    try {
        $checksums = Invoke-RestMethod -Uri $checksumAsset.browser_download_url
        $expectedLine = $checksums -split "`n" | Where-Object { $_ -match [regex]::Escape($assetName) }
        if ($expectedLine) {
            $expected = ($expectedLine -split "\s+")[0].Trim().ToLower()
            $actual = (Get-FileHash $tempZip -Algorithm SHA256).Hash.ToLower()
            if ($actual -ne $expected) {
                Write-Err "Checksum mismatch!"
                Write-Err "  Expected: $expected"
                Write-Err "  Got:      $actual"
                Remove-Item $tempZip -Force -ErrorAction SilentlyContinue
                exit 1
            }
            Write-Success "Checksum verified"
        } else {
            Write-Warn "Checksum for $assetName not found in checksums.txt (skipping verification)"
        }
    } catch {
        Write-Warn "Could not verify checksum: $_"
    }
} else {
    Write-Warn "No checksums.txt in release (skipping verification)"
}

# Create install directory (clear existing to avoid conflicts)
if (Test-Path $InstallDir) {
    # Stop any running rampart processes first
    $rampartExe = "$InstallDir\rampart.exe"
    if (Test-Path $rampartExe) {
        Write-Status "Stopping any running Rampart processes..."
        # Try graceful shutdown first
        try {
            & $rampartExe serve stop 2>$null
        } catch { }
        # Kill any remaining processes
        Get-Process -Name "rampart" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500  # Give Windows time to release file handles
    }
    
    Write-Status "Removing previous installation..."
    $removed = $false
    
    # Try PowerShell first
    try {
        Remove-Item -Recurse -Force $InstallDir -ErrorAction Stop
        $removed = $true
    } catch {
        # Try cmd.exe rd as fallback (sometimes works when PS doesn't)
        Write-Status "Retrying with cmd.exe..."
        cmd /c "rd /s /q `"$InstallDir`"" 2>$null
        if (-not (Test-Path $InstallDir)) {
            $removed = $true
        }
    }
    
    if (-not $removed) {
        Write-Err "Cannot remove existing installation at $InstallDir"
        Write-Err "This usually means files are locked or have permission issues."
        Write-Host ""
        Write-Host "  Try these steps:" -ForegroundColor Yellow
        Write-Host "    1. Close all terminals and Claude Code"
        Write-Host "    2. Run PowerShell as Administrator and execute:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "       takeown /f `"$InstallDir`" /r /d y" -ForegroundColor Cyan
        $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        Write-Host "       icacls `"$InstallDir`" /grant `"*$($currentSid):F`" /t" -ForegroundColor Cyan
        Write-Host "       Remove-Item -Recurse -Force `"$InstallDir`"" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "    3. Re-run this installer" -ForegroundColor Yellow
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
    Write-Success "Added $InstallDir to PATH"
}

# Always refresh current session PATH so rampart works immediately
if ($env:PATH -notlike "*$InstallDir*") {
    $env:PATH = "$InstallDir;$env:PATH"
}

# Verify installation
Write-Host ""
try {
    $versionOutput = & $rampartExe version 2>&1
    Write-Success "Installed: $($versionOutput | Select-Object -First 1)"
} catch {
    Write-Warn "Installed but could not verify version"
}

# Offer one zero-configuration setup path for fresh installs and upgrades.
Write-Host ""
$setup = Read-Host "  Detect, protect, and verify supported AI agents now? [Y/n]"
if ($setup -eq "" -or $setup -match "^[Yy]") {
    & $rampartExe protect
}

# Done
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
Write-Success "Rampart installed successfully!"
Write-Host ""
Write-Host "  Get started:" -ForegroundColor White
Write-Host "    rampart protect" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Or try it now:" -ForegroundColor White
Write-Host "    rampart version" -ForegroundColor Cyan
Write-Host "    rampart test `"rm -rf /`"" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Docs: https://docs.rampart.sh" -ForegroundColor DarkGray
Write-Host "  Uninstall: rampart uninstall" -ForegroundColor DarkGray
Write-Host ""
