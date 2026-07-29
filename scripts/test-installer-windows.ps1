# Copyright 2026 The Rampart Authors
# Licensed under the Apache License, Version 2.0

#requires -Version 5.1

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw "This functional test requires Windows."
}
$RepoRoot = Split-Path -Parent $PSScriptRoot
$Installer = Join-Path $RepoRoot "install.ps1"
$PublishedInstaller = Join-Path $RepoRoot "docs\install.ps1"
$TestRoot = Join-Path ([System.IO.Path]::GetTempPath()) "rampart-installer-$([Guid]::NewGuid().ToString('N'))"
$OriginalUserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
$PowerShellExe = if ($PSVersionTable.PSEdition -eq "Core") {
    Join-Path $PSHOME "pwsh.exe"
} else {
    Join-Path $PSHOME "powershell.exe"
}

function Assert-True($condition, $message) {
    if (-not $condition) { throw $message }
}

function Build-RampartFixture($path, $version) {
    & go build -ldflags "-X github.com/peg/rampart/internal/build.versionFromLDFlags=$version" -o $path ./cmd/rampart
    if ($LASTEXITCODE -ne 0) {
        throw "could not build Rampart fixture $version"
    }
}

function Initialize-PriorInstall($installDir, $oldBinary) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    Copy-Item -LiteralPath $oldBinary -Destination (Join-Path $installDir "rampart.exe") -Force
    [System.IO.File]::WriteAllText((Join-Path $installDir "prior-state.txt"), "preserve-me")
}

function Invoke-InstallerFixture(
    $archive,
    $installDir,
    $expectedVersion = "v9.9.9-installer-test",
    [switch]$FailAfterBackup,
    [switch]$RestartBackgroundServe,
    [switch]$FailBackgroundRestart
) {
    $checksum = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    $arguments = @(
        "-NoLogo",
        "-NoProfile",
        # The host-level flag makes any future Read-Host regression fail
        # immediately instead of hanging CI or silently configuring agents.
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-File", $Installer,
        "-TestMode",
        "-TestArchivePath", $archive,
        "-TestInstallDir", $installDir,
        "-TestExpectedSha256", $checksum,
        "-TestExpectedVersion", $expectedVersion
    )
    if ($FailAfterBackup) { $arguments += "-TestFailAfterBackup" }
    if ($RestartBackgroundServe) { $arguments += "-TestRestartBackgroundServe" }
    if ($FailBackgroundRestart) { $arguments += "-TestFailBackgroundRestart" }

    $nativePreferenceExists = Test-Path Variable:PSNativeCommandUseErrorActionPreference
    if ($nativePreferenceExists) {
        $oldNativePreference = $PSNativeCommandUseErrorActionPreference
        $PSNativeCommandUseErrorActionPreference = $false
    }
    try {
        $output = @(& $PowerShellExe @arguments 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        if ($nativePreferenceExists) {
            $PSNativeCommandUseErrorActionPreference = $oldNativePreference
        }
    }
    return [pscustomobject]@{
        ExitCode = $exitCode
        Output = ($output -join [Environment]::NewLine)
    }
}

function Get-RampartVersion($installDir) {
    $output = @(& (Join-Path $installDir "rampart.exe") version 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "installed Rampart fixture did not run" }
    return $output -join [Environment]::NewLine
}

function Assert-NoTransactionArtifacts($installDir) {
    $parent = Split-Path -Parent $installDir
    $artifacts = @(Get-ChildItem -LiteralPath $parent -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like ".install-stage-*" -or $_.Name -like ".install-backup-*" })
    Assert-True ($artifacts.Count -eq 0) "installer left transaction artifacts: $($artifacts.FullName -join ', ')"
}

function Import-InstallerFunction($name) {
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $Installer,
        [ref]$tokens,
        [ref]$errors
    )
    Assert-True ($errors.Count -eq 0) "installer parse failed: $($errors -join ', ')"
    $definitions = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $name
    }, $true))
    Assert-True ($definitions.Count -eq 1) "expected one installer function named $name"
    # Define it in script scope so it remains available after this helper
    # returns, while still avoiding execution of the installer's main body.
    Invoke-Expression ("function script:$name $($definitions[0].Body.Extent.Text)")
}

try {
    New-Item -ItemType Directory -Path $TestRoot -Force | Out-Null
    Push-Location $RepoRoot
    try {
        $oldBinary = Join-Path $TestRoot "rampart-old.exe"
        $candidatePayload = Join-Path $TestRoot "candidate"
        $candidateBinary = Join-Path $candidatePayload "rampart.exe"
        New-Item -ItemType Directory -Path $candidatePayload | Out-Null
        Build-RampartFixture $oldBinary "v9.9.8-installer-test"
        Build-RampartFixture $candidateBinary "v9.9.9-installer-test"

        $candidateArchive = Join-Path $TestRoot "candidate.zip"
        Compress-Archive -LiteralPath $candidateBinary -DestinationPath $candidateArchive
        $invalidPayload = Join-Path $TestRoot "invalid"
        New-Item -ItemType Directory -Path $invalidPayload | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $invalidPayload "not-rampart.txt"), "invalid")
        $invalidArchive = Join-Path $TestRoot "invalid.zip"
        Compress-Archive -LiteralPath (Join-Path $invalidPayload "not-rampart.txt") -DestinationPath $invalidArchive
    } finally {
        Pop-Location
    }

    Assert-True (
        (Get-FileHash -LiteralPath $Installer -Algorithm SHA256).Hash -eq
        (Get-FileHash -LiteralPath $PublishedInstaller -Algorithm SHA256).Hash
    ) "install.ps1 and docs/install.ps1 differ"

    # Exercise command-line authentication without executing the installer
    # main body. Managed `serve --background` processes may have supported root
    # flags before the subcommand, including quoted config paths.
    Import-InstallerFunction "Split-WindowsCommandLineArguments"
    Import-InstallerFunction "Test-ManagedServeArguments"
    $managedCases = @(
        @{ Input = 'serve --background'; Want = $true },
        @{ Input = '--verbose serve --background'; Want = $true },
        @{ Input = '--verbose=false --config="C:\Policy Files\rampart.yaml" serve --background'; Want = $true },
        @{ Input = '--config "C:\Policy Files\rampart.yaml" serve --background'; Want = $true },
        @{ Input = '--config=C:\policy.yaml serve --background'; Want = $true },
        @{ Input = '--config'; Want = $false },
        @{ Input = '--version serve'; Want = $false },
        @{ Input = '--output serve'; Want = $false },
        @{ Input = 'doctor --output serve'; Want = $false }
    )
    foreach ($case in $managedCases) {
        $actual = Test-ManagedServeArguments $case.Input
        Assert-True ($actual -eq $case.Want) "managed serve parser returned $actual for '$($case.Input)'"
    }

    $installerText = [System.IO.File]::ReadAllText($Installer)
    $restartOffset = $installerText.IndexOf('Write-Status "Restarting the Rampart background server..."')
    $backupCommitOffset = $installerText.IndexOf('Remove-Item -LiteralPath $backupDir -Recurse -Force -ErrorAction Stop')
    $installedOffset = $installerText.IndexOf('Write-Success "Installed: $installedVersion"')
    $pathOffset = $installerText.IndexOf('# PATH is a convenience mutation')
    Assert-True (
        $restartOffset -ge 0 -and
        $backupCommitOffset -gt $restartOffset -and
        $installedOffset -gt $backupCommitOffset -and
        $pathOffset -gt $installedOffset
    ) "restart proof, backup commit, success reporting, and PATH mutation are out of transaction order"
    Assert-True ($installerText.Contains('Task Scheduler and NSSM jobs are not modified')) "external Windows manager upgrade guidance is missing"

    # Successful last-install -> candidate replacement.
    $successInstall = Join-Path $TestRoot "success\bin"
    Initialize-PriorInstall $successInstall $oldBinary
    $success = Invoke-InstallerFixture $candidateArchive $successInstall
    Assert-True ($success.ExitCode -eq 0) "successful replacement failed:`n$($success.Output)"
    Assert-True ($success.Output -notmatch 'Detect, protect, and verify') "installer unexpectedly prompted to modify agent configuration"
    Assert-True ((Get-RampartVersion $successInstall) -match 'v9\.9\.9-installer-test') "candidate was not activated"
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $successInstall "prior-state.txt"))) "old install content leaked into candidate"
    Assert-NoTransactionArtifacts $successInstall

    # Failure after the prior tree was moved must restore it exactly.
    $rollbackInstall = Join-Path $TestRoot "rollback\bin"
    Initialize-PriorInstall $rollbackInstall $oldBinary
    $rollback = Invoke-InstallerFixture $candidateArchive $rollbackInstall -FailAfterBackup
    Assert-True ($rollback.ExitCode -ne 0) "injected replacement failure unexpectedly succeeded"
    Assert-True ($rollback.Output -match 'restored the previous installation') "rollback was not reported:`n$($rollback.Output)"
    Assert-True ((Get-RampartVersion $rollbackInstall) -match 'v9\.9\.8-installer-test') "rollback did not restore the prior binary"
    Assert-True ((Get-Content -LiteralPath (Join-Path $rollbackInstall "prior-state.txt") -Raw) -eq "preserve-me") "rollback did not preserve prior state"
    Assert-NoTransactionArtifacts $rollbackInstall

    # A runtime restart is part of the transaction, not a post-commit warning.
    # The prior tree must still exist until the candidate proves readiness.
    $restartRollbackInstall = Join-Path $TestRoot "restart-rollback\bin"
    Initialize-PriorInstall $restartRollbackInstall $oldBinary
    $restartRollback = Invoke-InstallerFixture $candidateArchive $restartRollbackInstall `
        -RestartBackgroundServe -FailBackgroundRestart
    Assert-True ($restartRollback.ExitCode -ne 0) "injected restart failure unexpectedly succeeded"
    Assert-True ($restartRollback.Output -match 'restored the previous Rampart installation') "runtime rollback was not reported:`n$($restartRollback.Output)"
    Assert-True ((Get-RampartVersion $restartRollbackInstall) -match 'v9\.9\.8-installer-test') "runtime rollback did not restore the prior binary"
    Assert-True ((Get-Content -LiteralPath (Join-Path $restartRollbackInstall "prior-state.txt") -Raw) -eq "preserve-me") "runtime rollback did not restore prior state"
    Assert-NoTransactionArtifacts $restartRollbackInstall

    # An invalid candidate must fail before the prior installation is moved.
    $invalidInstall = Join-Path $TestRoot "invalid-candidate\bin"
    Initialize-PriorInstall $invalidInstall $oldBinary
    $invalid = Invoke-InstallerFixture $invalidArchive $invalidInstall
    Assert-True ($invalid.ExitCode -ne 0) "invalid candidate unexpectedly succeeded"
    Assert-True ($invalid.Output -match 'existing installation was not changed') "pre-replacement validation failure was not reported:`n$($invalid.Output)"
    Assert-True ((Get-RampartVersion $invalidInstall) -match 'v9\.9\.8-installer-test') "invalid candidate changed the prior binary"
    Assert-True ((Get-Content -LiteralPath (Join-Path $invalidInstall "prior-state.txt") -Raw) -eq "preserve-me") "invalid candidate changed prior state"
    Assert-NoTransactionArtifacts $invalidInstall

    # A correctly checksummed archive for the wrong release must also fail
    # before replacement; checksums prove bytes, while this proves identity.
    $wrongVersionInstall = Join-Path $TestRoot "wrong-version\bin"
    Initialize-PriorInstall $wrongVersionInstall $oldBinary
    $wrongVersion = Invoke-InstallerFixture $candidateArchive $wrongVersionInstall "v9.9.10-installer-test"
    Assert-True ($wrongVersion.ExitCode -ne 0) "wrong-version candidate unexpectedly succeeded"
    Assert-True ($wrongVersion.Output -match 'does not match release') "version mismatch was not reported:`n$($wrongVersion.Output)"
    Assert-True ((Get-RampartVersion $wrongVersionInstall) -match 'v9\.9\.8-installer-test') "wrong-version candidate changed the prior binary"
    Assert-NoTransactionArtifacts $wrongVersionInstall

    # Release identifiers are used in asset and temporary paths. Reject the
    # same malformed/tag-traversal forms as the Unix installer before staging.
    $invalidVersionInstall = Join-Path $TestRoot "invalid-version\bin"
    Initialize-PriorInstall $invalidVersionInstall $oldBinary
    $invalidVersion = Invoke-InstallerFixture $candidateArchive $invalidVersionInstall "v../../tmp/rampart"
    Assert-True ($invalidVersion.ExitCode -ne 0) "invalid release version unexpectedly succeeded"
    Assert-True ($invalidVersion.Output -match 'Invalid release version') "invalid release version was not reported:`n$($invalidVersion.Output)"
    Assert-True ((Get-RampartVersion $invalidVersionInstall) -match 'v9\.9\.8-installer-test') "invalid release version changed the prior binary"
    Assert-NoTransactionArtifacts $invalidVersionInstall

    Assert-True (
        [System.StringComparer]::Ordinal.Equals(
            $OriginalUserPath,
            [Environment]::GetEnvironmentVariable("PATH", "User")
        )
    ) "installer test mode changed the persistent user PATH"

    Write-Host "Windows installer transaction tests passed."
} finally {
    Remove-Item -LiteralPath $TestRoot -Recurse -Force -ErrorAction SilentlyContinue
}
