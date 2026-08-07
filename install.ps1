#!/usr/bin/env pwsh
# Rampart Windows Installer
# Usage: irm https://rampart.sh/install.ps1 | iex
#
# This script downloads the latest Rampart release, installs it to ~/.rampart/bin,
# and adds it to your PATH. No admin rights required.

#requires -Version 5.1

[CmdletBinding()]
param(
    # Compatibility no-op retained for existing automation. The installer no
    # longer prompts to modify agent configuration; run `rampart protect`
    # explicitly after installation.
    [switch]$NonInteractive,
    [switch]$TestMode,
    [string]$TestArchivePath,
    [string]$TestInstallDir,
    [string]$TestExpectedSha256,
    [string]$TestExpectedVersion,
    [switch]$TestFailAfterBackup,
    [switch]$TestRestartBackgroundServe,
    [switch]$TestFailBackgroundRestart
)

$ErrorActionPreference = "Stop"

# Ensure UTF-8 output for Unicode characters
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()

$RepoOwner = "peg"
$RepoName = "rampart"
$RampartDir = "$env:USERPROFILE\.rampart"
$InstallDir = "$env:USERPROFILE\.rampart\bin"
$RestartBackgroundServe = $false
$RemoveArchiveWhenDone = $false

if ($TestFailAfterBackup -and -not $TestMode) {
    throw "-TestFailAfterBackup is available only with -TestMode."
}
if (($TestRestartBackgroundServe -or $TestFailBackgroundRestart) -and -not $TestMode) {
    throw "Installer restart fault injection is available only with -TestMode."
}
if ($TestFailBackgroundRestart -and -not $TestRestartBackgroundServe) {
    throw "-TestFailBackgroundRestart requires -TestRestartBackgroundServe."
}
if ($TestMode) {
    if ([string]::IsNullOrWhiteSpace($TestArchivePath) -or
        [string]::IsNullOrWhiteSpace($TestInstallDir) -or
        [string]::IsNullOrWhiteSpace($TestExpectedSha256) -or
        [string]::IsNullOrWhiteSpace($TestExpectedVersion)) {
        throw "-TestMode requires archive, install directory, SHA-256, and version inputs."
    }

    $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd([char[]]"\/")
    $tempPrefix = $tempRoot + [System.IO.Path]::DirectorySeparatorChar
    $resolvedTestInstallDir = [System.IO.Path]::GetFullPath($TestInstallDir).TrimEnd([char[]]"\/")
    if ([System.StringComparer]::OrdinalIgnoreCase.Equals($resolvedTestInstallDir, $tempRoot) -or
        -not $resolvedTestInstallDir.StartsWith(
        $tempPrefix,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "-TestInstallDir must be a child of the system temporary directory."
    }

    $InstallDir = $resolvedTestInstallDir
    $RampartDir = Split-Path -Parent $InstallDir
}

function Write-Status($msg) { Write-Host "  $msg" -ForegroundColor Cyan }
function Write-Success($msg) { Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err($msg) { Write-Host "[X] $msg" -ForegroundColor Red }

function Test-StrictReleaseVersion($value) {
    if ([string]::IsNullOrWhiteSpace($value)) { return $false }
    $pattern = '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$'
    return [System.Text.RegularExpressions.Regex]::IsMatch(
        "$value",
        $pattern,
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
}

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
    if (-not [System.IO.Directory]::Exists($parent)) { return $false }
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

function Test-SamePath($left, $right) {
    try {
        $leftFull = [System.IO.Path]::GetFullPath($left).TrimEnd([char[]]"\/")
        $rightFull = [System.IO.Path]::GetFullPath($right).TrimEnd([char[]]"\/")
        return [System.StringComparer]::OrdinalIgnoreCase.Equals($leftFull, $rightFull)
    } catch {
        return $false
    }
}

function Split-WindowsCommandLineArguments($commandLine) {
    $arguments = [System.Collections.Generic.List[string]]::new()
    $length = $commandLine.Length
    $index = 0

    while ($index -lt $length) {
        while ($index -lt $length -and [char]::IsWhiteSpace($commandLine[$index])) {
            $index++
        }
        if ($index -ge $length) { break }

        $value = [System.Text.StringBuilder]::new()
        $inQuotes = $false
        while ($index -lt $length) {
            $character = $commandLine[$index]
            if ($character -eq [char]'\') {
                $slashStart = $index
                while ($index -lt $length -and $commandLine[$index] -eq [char]'\') {
                    $index++
                }
                $slashCount = $index - $slashStart
                if ($index -lt $length -and $commandLine[$index] -eq [char]'"') {
                    [void]$value.Append(('\' * [Math]::Floor($slashCount / 2)))
                    if (($slashCount % 2) -eq 0) {
                        $inQuotes = -not $inQuotes
                    } else {
                        [void]$value.Append('"')
                    }
                    $index++
                    continue
                }
                [void]$value.Append(('\' * $slashCount))
                continue
            }
            if ($character -eq [char]'"') {
                $inQuotes = -not $inQuotes
                $index++
                continue
            }
            if (-not $inQuotes -and [char]::IsWhiteSpace($character)) {
                break
            }
            [void]$value.Append($character)
            $index++
        }
        [void]$arguments.Add($value.ToString())
    }

    return $arguments.ToArray()
}

function Test-ManagedServeArguments($commandLine) {
    $parsedArguments = @(Split-WindowsCommandLineArguments $commandLine)
    for ($index = 0; $index -lt $parsedArguments.Count; $index++) {
        $argument = "$($parsedArguments[$index])"
        if ($argument -eq "--config") {
            # --config is the only supported root flag with a separate value.
            if ($index + 1 -ge $parsedArguments.Count) { return $false }
            $index++
            continue
        }
        if ($argument -eq "--version") {
            # Cobra exits for the root version flag before a later subcommand.
            return $false
        }
        if ($argument.StartsWith("--config=", [System.StringComparison]::Ordinal) -or
            $argument -eq "--verbose" -or
            $argument.StartsWith("--verbose=", [System.StringComparison]::Ordinal)) {
            continue
        }
        if ($argument.StartsWith("-", [System.StringComparison]::Ordinal)) {
            # Unknown root flags are ambiguous and may consume another value.
            return $false
        }
        return $argument -eq "serve"
    }
    return $false
}

function Test-ManagedServeProcess($process, $managedExe) {
    try {
        if ($null -eq $process -or -not (Test-SamePath $process.Path $managedExe)) {
            return $false
        }
        $record = Get-CimInstance Win32_Process -Filter "ProcessId = $($process.Id)" -ErrorAction Stop
        if ($null -eq $record -or -not (Test-SamePath $record.ExecutablePath $managedExe)) {
            return $false
        }
        $commandLine = "$($record.CommandLine)".Trim()
        $remainder = $null
        if ($commandLine.StartsWith('"')) {
            $closingQuote = $commandLine.IndexOf('"', 1)
            if ($closingQuote -gt 0) {
                $commandPath = $commandLine.Substring(1, $closingQuote - 1)
                if (Test-SamePath $commandPath $managedExe) {
                    $remainder = $commandLine.Substring($closingQuote + 1)
                }
            }
        } elseif ($commandLine.StartsWith($managedExe, [System.StringComparison]::OrdinalIgnoreCase)) {
            $remainder = $commandLine.Substring($managedExe.Length)
        }
        if ($null -eq $remainder) { return $false }
        # Authenticate the same supported root-flag forms as Rampart itself.
        # This recognizes e.g. `rampart --config policy.yaml serve
        # --background` without accepting `serve` as an unrelated flag value.
        return (Test-ManagedServeArguments $remainder)
    } catch {
        return $false
    }
}

function Get-ManagedServeProcess($managedExe) {
    $pidPath = Join-Path $RampartDir "serve.pid"
    if (-not [System.IO.File]::Exists($pidPath)) { return }
    $servePid = 0
    $rawPid = [System.IO.File]::ReadAllText($pidPath).Trim()
    if (-not [int]::TryParse($rawPid, [ref]$servePid)) { return }
    $serveProcess = Get-Process -Id $servePid -ErrorAction SilentlyContinue
    if (Test-ManagedServeProcess $serveProcess $managedExe) {
        Write-Output $serveProcess
    }
}

function Stop-ManagedRampartServe($managedExe, [ref]$restartServe) {
    $restartServe.Value = $false
    $serveProcess = Get-ManagedServeProcess $managedExe
    if ($null -ne $serveProcess) {
        # Update the caller before any operation that can fail so it can recover
        # a server stopped during a partially successful shutdown sequence.
        $restartServe.Value = $true
        try { & $managedExe serve stop 2>$null | Out-Null } catch { }
    }

    if ($null -eq $serveProcess) { return }

    for ($attempt = 0; $attempt -lt 10; $attempt++) {
        $current = Get-Process -Id $serveProcess.Id -ErrorAction SilentlyContinue
        if ($null -eq $current -or -not (Test-ManagedServeProcess $current $managedExe)) {
            return
        }
        Start-Sleep -Milliseconds 200
    }

    # The graceful stop did not complete. Force only the exact PID whose
    # executable and first subcommand were re-authenticated above. Unrelated
    # Rampart CLI/wrapper processes are never terminated by an upgrade.
    $current = Get-Process -Id $serveProcess.Id -ErrorAction SilentlyContinue
    if ($null -ne $current -and (Test-ManagedServeProcess $current $managedExe)) {
        Stop-Process -Id $current.Id -Force -ErrorAction Stop
    }
    $current = Get-Process -Id $serveProcess.Id -ErrorAction SilentlyContinue
    if ($null -ne $current -and (Test-ManagedServeProcess $current $managedExe)) {
        throw "The managed Rampart serve process is still running from $managedExe."
    }
}

function Test-RampartCandidate($candidateDir, $expectedVersion) {
    $candidateExe = Join-Path $candidateDir "rampart.exe"
    if (-not [System.IO.File]::Exists($candidateExe)) {
        throw "Candidate archive does not contain rampart.exe at its root."
    }
    $candidate = Get-Item -LiteralPath $candidateExe -Force
    if ($candidate.PSIsContainer -or
        (($candidate.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Candidate rampart.exe is not a regular file."
    }

    try {
        $versionOutput = @(& $candidateExe version 2>&1)
        $versionExitCode = $LASTEXITCODE
    } catch {
        throw "Candidate rampart.exe could not run: $_"
    }
    $firstLine = $versionOutput |
        ForEach-Object { "$($_)".Trim() } |
        Where-Object { $_ -ne "" } |
        Select-Object -First 1
    $versionMatch = [System.Text.RegularExpressions.Regex]::Match(
        "$firstLine",
        '^rampart\s+(\S+)'
    )
    if ($versionExitCode -ne 0 -or -not $versionMatch.Success) {
        throw "Candidate rampart.exe failed version validation (exit $versionExitCode)."
    }
    if (-not [string]::IsNullOrWhiteSpace($expectedVersion)) {
        $actualVersion = $versionMatch.Groups[1].Value.TrimStart([char]'v')
        $normalizedExpectedVersion = $expectedVersion.TrimStart([char]'v')
        if (-not [System.StringComparer]::Ordinal.Equals($actualVersion, $normalizedExpectedVersion)) {
            throw "Candidate version $actualVersion does not match release $expectedVersion."
        }
    }
    return "$firstLine"
}

function Get-InstallTransactionArtifacts {
    if (-not [System.IO.Directory]::Exists($RampartDir)) { return }
    Get-ChildItem -LiteralPath $RampartDir -Directory -Force -ErrorAction Stop |
        Where-Object {
            $_.Name -like ".install-backup-*" -or
            $_.Name -like ".install-stage-*"
        }
}

function Remove-InstallerArchive {
    if ($RemoveArchiveWhenDone -and -not [string]::IsNullOrWhiteSpace($tempZip)) {
        Remove-Item -LiteralPath $tempZip -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ""
Write-Host "Rampart Installer" -ForegroundColor White
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

# A hard shutdown can interrupt the two directory moves below. Never guess that
# an old backup is disposable: preserve it and tell the user where it is. A
# later successful transaction removes only the backup it created itself.
if (-not $TestMode) {
    try {
        $orphanedTransactionPaths = @(Get-InstallTransactionArtifacts)
        if ($orphanedTransactionPaths.Count -gt 0) {
            Write-Warn "Found preserved files from an earlier interrupted upgrade; they will not be deleted automatically:"
            foreach ($orphanedPath in $orphanedTransactionPaths) {
                Write-Host "    $($orphanedPath.FullName)" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Warn "Could not inspect prior installer transaction files: $_"
    }
}

# Resolve a verified archive. Test mode is intentionally restricted to a child
# of the system temporary directory and never changes PATH or live processes.
if ($TestMode) {
    $version = "installer-test"
    $expectedCandidateVersion = $TestExpectedVersion
    if (-not (Test-StrictReleaseVersion $expectedCandidateVersion)) {
        Write-Err "Invalid release version: $expectedCandidateVersion. Expected a tag such as v1.6.0 or v1.6.0-rc.1."
        exit 1
    }
    $tempZip = [System.IO.Path]::GetFullPath($TestArchivePath)
    $assetName = Split-Path -Leaf $tempZip
    $expected = $TestExpectedSha256.ToLowerInvariant()
    if (-not [System.IO.File]::Exists($tempZip)) {
        Write-Err "Test archive not found: $tempZip"
        exit 1
    }
    Write-Status "Using local installer transaction fixture"
} else {
    $arch = if ([Environment]::Is64BitOperatingSystem) {
        if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
    } else {
        Write-Err "32-bit Windows is not supported"
        exit 1
    }
    Write-Status "Detected: Windows $arch"

    Write-Status "Fetching latest release..."
    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$RepoOwner/$RepoName/releases/latest"
        $version = $release.tag_name
    } catch {
        Write-Err "Failed to fetch latest release: $_"
        exit 1
    }
    if (-not (Test-StrictReleaseVersion $version)) {
        Write-Err "Invalid release version: $version. Expected a tag such as v1.6.0 or v1.6.0-rc.1."
        exit 1
    }
    Write-Status "Latest version: $version"
    $expectedCandidateVersion = $version

    $assetName = "rampart_$($version -replace '^v','')_windows_$arch.zip"
    $asset = $release.assets | Where-Object { $_.name -eq $assetName }
    if (-not $asset) {
        Write-Err "Could not find asset: $assetName"
        Write-Err "Available assets:"
        $release.assets | ForEach-Object { Write-Host "  - $($_.name)" }
        exit 1
    }

    $downloadUrl = $asset.browser_download_url
    $tempZip = Join-Path $env:TEMP "rampart-$version-$([Guid]::NewGuid().ToString('N')).zip"
    $RemoveArchiveWhenDone = $true
    Write-Status "Downloading $assetName..."
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tempZip -UseBasicParsing
    } catch {
        Write-Err "Download failed: $_"
        Remove-InstallerArchive
        exit 1
    }

    # GoReleaser produces checksums.txt with each release. Fail closed if
    # integrity cannot be established; never install an unverified binary.
    $checksumAsset = $release.assets | Where-Object { $_.name -eq "checksums.txt" }
    if (-not $checksumAsset) {
        Write-Err "No checksums.txt asset in release; refusing to install an unverified binary."
        Remove-InstallerArchive
        exit 1
    }
    try {
        $checksums = Invoke-RestMethod -Uri $checksumAsset.browser_download_url
    } catch {
        Write-Err "Could not download checksums.txt; refusing to install an unverified binary: $_"
        Remove-InstallerArchive
        exit 1
    }
    $expectedLines = @($checksums -split "`r?`n" | Where-Object {
        $fields = $_.Trim() -split "\s+"
        $fields.Count -ge 2 -and $fields[$fields.Count - 1].TrimStart([char]'*') -ceq $assetName
    })
    if ($expectedLines.Count -ne 1) {
        Write-Err "Expected exactly one checksum entry for $assetName; refusing unverified install."
        Remove-InstallerArchive
        exit 1
    }
    $expected = (($expectedLines[0].Trim() -split "\s+")[0]).ToLowerInvariant()
}

Write-Status "Verifying checksum..."
if ($expected -notmatch '^[0-9a-f]{64}$') {
    Write-Err "Invalid SHA-256 checksum for $assetName; refusing unverified install."
    Remove-InstallerArchive
    exit 1
}
try {
    $actual = (Get-FileHash -LiteralPath $tempZip -Algorithm SHA256).Hash.ToLowerInvariant()
} catch {
    Write-Err "Could not calculate SHA-256; refusing unverified install: $_"
    Remove-InstallerArchive
    exit 1
}
if ($actual -ne $expected) {
    Write-Err "Checksum mismatch!"
    Write-Err "  Expected: $expected"
    Write-Err "  Got:      $actual"
    Remove-InstallerArchive
    exit 1
}
Write-Success "Checksum verified"

# Extract and execute the candidate from a unique staging directory before
# stopping the existing service or moving any installed files.
$transactionId = [Guid]::NewGuid().ToString('N')
$stageDir = Join-Path $RampartDir ".install-stage-$transactionId"
$backupDir = Join-Path $RampartDir ".install-backup-$transactionId"
Write-Status "Staging and validating the candidate..."
try {
    New-Item -ItemType Directory -Path $RampartDir -Force | Out-Null
    New-Item -ItemType Directory -Path $stageDir -ErrorAction Stop | Out-Null
    Expand-Archive -LiteralPath $tempZip -DestinationPath $stageDir -Force
    $candidateVersion = Test-RampartCandidate $stageDir $expectedCandidateVersion
} catch {
    Write-Err "Candidate validation failed; the existing installation was not changed: $_"
    Remove-Item -LiteralPath $stageDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-InstallerArchive
    exit 1
}
Remove-InstallerArchive
Write-Success "Validated candidate: $candidateVersion"

$hadPriorInstall = Test-Path -LiteralPath $InstallDir
if ($hadPriorInstall -and -not (Test-Path -LiteralPath $InstallDir -PathType Container)) {
    Write-Err "Refusing to replace non-directory install path: $InstallDir"
    Remove-Item -LiteralPath $stageDir -Recurse -Force -ErrorAction SilentlyContinue
    exit 1
}
if ($hadPriorInstall) {
    $priorInstallItem = Get-Item -LiteralPath $InstallDir -Force
    if (($priorInstallItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Write-Err "Refusing to replace a linked install directory: $InstallDir"
        Remove-Item -LiteralPath $stageDir -Recurse -Force -ErrorAction SilentlyContinue
        exit 1
    }
}

$priorExe = Join-Path $InstallDir "rampart.exe"
if ($hadPriorInstall -and ([System.IO.File]::Exists($priorExe)) -and -not $TestMode) {
    try {
        Stop-ManagedRampartServe $priorExe ([ref]$RestartBackgroundServe)
    } catch {
        Write-Err "Could not stop the managed Rampart installation safely: $_"
        if ($RestartBackgroundServe) {
            try {
                if ($null -eq (Get-ManagedServeProcess $priorExe)) {
                    & $priorExe serve --background | Out-Null
                    if ($LASTEXITCODE -ne 0) {
                        Write-Warn "The existing installation was preserved, but its background server did not restart."
                    }
                }
            } catch {
                Write-Warn "The existing installation was preserved, but its background server could not be confirmed running: $_"
            }
        }
        Remove-Item -LiteralPath $stageDir -Recurse -Force -ErrorAction SilentlyContinue
        exit 1
    }
}
if ($TestRestartBackgroundServe) {
    $RestartBackgroundServe = $true
}

# Directory moves occur on the same volume. Keep the old tree under a unique
# backup name until the candidate has also passed validation at its final path.
$priorMoved = $false
$candidateActivated = $false
$installedVersion = $null
try {
    if ($hadPriorInstall) {
        [System.IO.Directory]::Move($InstallDir, $backupDir)
        $priorMoved = $true
    }
    if ($TestFailAfterBackup) {
        throw "Injected replacement failure after backup"
    }
    [System.IO.Directory]::Move($stageDir, $InstallDir)
    $candidateActivated = $true
    $installedVersion = Test-RampartCandidate $InstallDir $expectedCandidateVersion
} catch {
    $replacementError = $_
    $rollbackError = $null

    if ($priorMoved) {
        try {
            if (Test-Path -LiteralPath $InstallDir) {
                if (-not $candidateActivated) {
                    throw "Install path reappeared before rollback; refusing to remove an unknown directory."
                }
                Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction Stop
            }
            [System.IO.Directory]::Move($backupDir, $InstallDir)
        } catch {
            $rollbackError = $_
        }
    } elseif ($candidateActivated) {
        Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    Remove-Item -LiteralPath $stageDir -Recurse -Force -ErrorAction SilentlyContinue
    if ($null -eq $rollbackError) {
        if ($priorMoved) {
            Write-Warn "Candidate replacement failed; restored the previous installation."
        } elseif ($hadPriorInstall) {
            Write-Warn "Candidate replacement failed; the existing installation remains in place."
        }
        # The old server may have been stopped even when moving the old tree was
        # the operation that failed. Restart whenever the old executable is back
        # at its managed path, not only after a completed rollback move.
        if ($RestartBackgroundServe -and [System.IO.File]::Exists($priorExe)) {
            try {
                & $priorExe serve --background | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    Write-Warn "The previous installation was preserved, but its background server did not restart."
                }
            } catch {
                Write-Warn "The previous installation was preserved, but its background server did not restart: $_"
            }
        }
    } else {
        Write-Err "Automatic rollback also failed: $rollbackError"
        Write-Err "The prior installation remains preserved at $backupDir"
    }
    Write-Err "Installation failed during replacement: $replacementError"
    exit 1
}

$rampartExe = Join-Path $InstallDir "rampart.exe"

if ($RestartBackgroundServe) {
    Write-Status "Restarting the Rampart background server..."
    $restartError = $null
    if ($TestMode) {
        if ($TestFailBackgroundRestart) {
            $restartError = "injected background restart failure"
        }
    } else {
        try {
            & $rampartExe serve --background
            if ($LASTEXITCODE -ne 0) {
                $restartError = "serve --background exited with code $LASTEXITCODE"
            }
        } catch {
            $restartError = "$_"
        }
    }
    if ($null -eq $restartError) {
        Write-Success "Restarted Rampart background server"
    } else {
        $runtimeRollbackError = $null
        $candidateAside = $false
        try {
            if (-not $TestMode) {
                $candidateProcess = Get-ManagedServeProcess $rampartExe
                if ($null -ne $candidateProcess) {
                    $ignoredRestart = $false
                    Stop-ManagedRampartServe $rampartExe ([ref]$ignoredRestart)
                }
            }
            if (-not $priorMoved -or -not (Test-Path -LiteralPath $backupDir -PathType Container)) {
                throw "the prior installation backup is unavailable"
            }
            if (Test-Path -LiteralPath $stageDir) {
                throw "the candidate staging path unexpectedly reappeared"
            }
            [System.IO.Directory]::Move($InstallDir, $stageDir)
            $candidateAside = $true
            [System.IO.Directory]::Move($backupDir, $InstallDir)
            $priorMoved = $false
            $candidateActivated = $false
            Remove-Item -LiteralPath $stageDir -Recurse -Force -ErrorAction Stop
            $candidateAside = $false

            if (-not $TestMode) {
                & $priorExe serve --background | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    throw "the restored background server exited with code $LASTEXITCODE"
                }
            }
        } catch {
            $runtimeRollbackError = $_
            if ($candidateAside -and -not (Test-Path -LiteralPath $InstallDir)) {
                try {
                    [System.IO.Directory]::Move($stageDir, $InstallDir)
                    $candidateAside = $false
                } catch { }
            }
        }

        if ($null -eq $runtimeRollbackError) {
            Write-Warn "The candidate runtime did not restart; restored the previous Rampart installation and background server."
        } else {
            Write-Err "The candidate runtime did not restart and automatic rollback was incomplete: $runtimeRollbackError"
            if (Test-Path -LiteralPath $backupDir) {
                Write-Err "The prior installation remains preserved at $backupDir"
            }
        }
        Write-Err "Rampart upgrade failed because its previously running background server did not restart: $restartError"
        exit 1
    }
}

# Runtime recovery is part of the transaction. Delete the prior installation
# only after the candidate has passed final-path validation and any required
# background-server readiness proof.
if ($priorMoved -and (Test-Path -LiteralPath $backupDir)) {
    try {
        Remove-Item -LiteralPath $backupDir -Recurse -Force -ErrorAction Stop
        $priorMoved = $false
    } catch {
        Write-Warn "Upgrade succeeded, but the prior installation could not be removed: $backupDir"
    }
}

Write-Host ""
Write-Success "Installed: $installedVersion"

# PATH is a convenience mutation and must never strand a server that the
# installer stopped for replacement. Restart the authenticated managed runtime
# first, then make PATH updates best-effort and non-fatal.
if (-not $TestMode) {
    try {
        $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
        $pathEntries = @($userPath -split ';' | Where-Object { $_ -ne "" })
        if (-not ($pathEntries | Where-Object { Test-SamePath $_ $InstallDir })) {
            Write-Status "Adding to PATH..."
            $updatedUserPath = if ([string]::IsNullOrWhiteSpace($userPath)) {
                $InstallDir
            } else {
                "$InstallDir;$userPath"
            }
            [Environment]::SetEnvironmentVariable("PATH", $updatedUserPath, "User")
            Write-Success "Added $InstallDir to PATH"
        }

        $sessionPathEntries = @($env:PATH -split ';' | Where-Object { $_ -ne "" })
        if (-not ($sessionPathEntries | Where-Object { Test-SamePath $_ $InstallDir })) {
            $env:PATH = "$InstallDir;$env:PATH"
        }
    } catch {
        Write-Warn "Rampart was installed and its managed background server was recovered, but PATH could not be updated: $_"
        Write-Host "  Add $InstallDir to your user PATH manually." -ForegroundColor Yellow
    }

    if ($hadPriorInstall) {
        Write-Warn "Task Scheduler and NSSM jobs are not modified by this installer. If either launches Rampart, restart that task or service now so it loads the new binary."
    }
}

# Done
Write-Host ""
Write-Host "----------------------------------------------------" -ForegroundColor DarkGray
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
