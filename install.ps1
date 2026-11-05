#requires -Version 5.1
<#
.SYNOPSIS
    Prebuilt release installer for Arc CLI and Arc Decision UI sidecar on Windows.

.DESCRIPTION
    Downloads (or reads from local paths) a prebuilt Arc release archive (.zip)
    and its SHA256SUMS manifest, verifies the archive SHA-256 digest before
    extraction, installs arc.exe and arc-decision-ui-host.exe side-by-side into
    the target installation directory alongside LICENSE-MIT and LICENSE-APACHE,
    verifies executable execution and sibling sidecar resolution, and inspects
    or updates the user PATH.

.PARAMETER Version
    Release version to install (default: $env:ARC_VERSION or "1.0.0"). Leading 'v' is normalized.

.PARAMETER InstallDir
    Destination directory for binaries (default: $env:ARC_INSTALL_DIR or "$HOME\.arc\bin").

.PARAMETER BaseUrl
    Base URL for downloading release artifacts (default: $env:ARC_RELEASE_BASE_URL or GitHub Releases URL).

.PARAMETER ArchivePath
    Local filesystem path to a pre-downloaded release .zip archive (offline/test mode).

.PARAMETER ChecksumPath
    Local filesystem path to a SHA256SUMS file (offline/test mode).

.PARAMETER NoModifyPath
    Do not modify the persistent user PATH environment variable.

.PARAMETER Help
    Display usage information and exit 0.
#>

[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$Version = '',
    [string]$InstallDir = '',
    [string]$BaseUrl = '',
    [string]$ArchivePath = '',
    [string]$ChecksumPath = '',
    [switch]$NoModifyPath,
    [switch]$Help,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RemainingArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($null -ne $RemainingArgs) {
    for ($i = 0; $i -lt $RemainingArgs.Count; $i++) {
        $arg = $RemainingArgs[$i]
        switch -Regex ($arg) {
            '^(--help|-h|/\?)$' {
                $Help = $true
            }
            '^(--no-modify-path|-no-modify-path)$' {
                $NoModifyPath = $true
            }
            '^(--version|-version)$' {
                if (($i + 1) -lt $RemainingArgs.Count) {
                    $Version = $RemainingArgs[++$i]
                }
            }
            '^(--install-dir|-install-dir)$' {
                if (($i + 1) -lt $RemainingArgs.Count) {
                    $InstallDir = $RemainingArgs[++$i]
                }
            }
            '^(--base-url|-base-url)$' {
                if (($i + 1) -lt $RemainingArgs.Count) {
                    $BaseUrl = $RemainingArgs[++$i]
                }
            }
            '^(--archive|--archive-path|-archive-path)$' {
                if (($i + 1) -lt $RemainingArgs.Count) {
                    $ArchivePath = $RemainingArgs[++$i]
                }
            }
            '^(--checksums|--checksum-path|-checksum-path)$' {
                if (($i + 1) -lt $RemainingArgs.Count) {
                    $ChecksumPath = $RemainingArgs[++$i]
                }
            }
        }
    }
}

function Show-Usage {
    Write-Output @"
Arc Prebuilt Release Installer for Windows (install.ps1)
License: MIT OR Apache-2.0

Usage:
  .\install.ps1 [options]

Parameters:
  -Version <version>       Version of Arc to install (env: ARC_VERSION, default: 1.0.0)
  -InstallDir <path>       Target directory for binaries (env: ARC_INSTALL_DIR, default: `$HOME\.arc\bin)
  -BaseUrl <url>           Base URL for release assets (env: ARC_RELEASE_BASE_URL)
  -ArchivePath <path>      Local path to release .zip archive (skips archive download)
  -ChecksumPath <path>     Local path to SHA256SUMS file (skips checksum download)
  -NoModifyPath            Skip updating persistent User PATH environment variable
  -Help                    Print this help message and exit

Examples:
  .\install.ps1
  .\install.ps1 -Version 1.0.0 -InstallDir "`$HOME\.arc\bin" -NoModifyPath
  .\install.ps1 -ArchivePath .\arc-v1.0.0-x86_64-pc-windows-msvc.zip -ChecksumPath .\SHA256SUMS -NoModifyPath
"@
}

if ($Help) {
    Show-Usage
    exit 0
}

function Resolve-ExpectedSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SumsFilePath,
        [Parameter(Mandatory = $true)]
        [string[]]$CandidateNames
    )

    if (-not (Test-Path -LiteralPath $SumsFilePath -PathType Leaf)) {
        throw "Checksum file not found at: $SumsFilePath"
    }

    $lines = Get-Content -LiteralPath $SumsFilePath -Encoding UTF8
    foreach ($candidate in $CandidateNames) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }
        foreach ($rawLine in $lines) {
            $line = $rawLine.Trim()
            if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) {
                continue
            }
            if ($line -match '^([0-9a-fA-F]{64})\s+\*?(.+)$') {
                $digest = $Matches[1].ToLowerInvariant()
                $entryFile = [System.IO.Path]::GetFileName($Matches[2].Trim())
                if ([string]::Equals($entryFile, $candidate, [System.StringComparison]::OrdinalIgnoreCase)) {
                    return $digest
                }
            }
        }
    }

    return $null
}

function Get-FileSha256Hex {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    if (Get-Command -Name 'Get-FileHash' -ErrorAction SilentlyContinue) {
        return (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [System.IO.File]::OpenRead($FilePath)
        try {
            $hashBytes = $sha256.ComputeHash($stream)
            return ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()
        }
        finally {
            $stream.Dispose()
        }
    }
    finally {
        $sha256.Dispose()
    }
}

function Extract-ZipArchive {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ZipPath,
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath
    )

    if (Get-Command -Name 'Expand-Archive' -ErrorAction SilentlyContinue) {
        Expand-Archive -LiteralPath $ZipPath -DestinationPath $DestinationPath -Force
        return
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $DestinationPath)
}

function Find-ExtractedFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RootDir,
        [Parameter(Mandatory = $true)]
        [string]$FileName
    )

    $directPath = Join-Path $RootDir $FileName
    if (Test-Path -LiteralPath $directPath -PathType Leaf) {
        return $directPath
    }

    $found = Get-ChildItem -LiteralPath $RootDir -Filter $FileName -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $found) {
        return $found.FullName
    }

    return $null
}

function Test-DirectoryInPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DirectoryPath,
        [AllowEmptyString()]
        [string]$PathString
    )

    if ([string]::IsNullOrWhiteSpace($PathString)) {
        return $false
    }

    $normalizedTarget = [System.IO.Path]::GetFullPath($DirectoryPath).TrimEnd('\', '/')
    foreach ($entry in ($PathString -split ';')) {
        $trimmed = $entry.Trim().Trim('"')
        if ([string]::IsNullOrWhiteSpace($trimmed)) {
            continue
        }
        try {
            $normalizedEntry = [System.IO.Path]::GetFullPath($trimmed).TrimEnd('\', '/')
        }
        catch {
            $normalizedEntry = $trimmed.TrimEnd('\', '/')
        }
        if ([string]::Equals($normalizedEntry, $normalizedTarget, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

$stagingDir = $null
try {
    # 1. Resolve Version
    if ([string]::IsNullOrWhiteSpace($Version)) {
        if (-not [string]::IsNullOrWhiteSpace($env:ARC_VERSION)) {
            $Version = $env:ARC_VERSION
        }
        else {
            $Version = '1.0.0'
        }
    }
    $normalizedVersion = $Version.Trim()
    if ($normalizedVersion.StartsWith('v', [System.StringComparison]::OrdinalIgnoreCase)) {
        $normalizedVersion = $normalizedVersion.Substring(1)
    }
    if ([string]::IsNullOrWhiteSpace($normalizedVersion)) {
        throw "Invalid empty version specified."
    }

    # 2. Resolve InstallDir
    if ([string]::IsNullOrWhiteSpace($InstallDir)) {
        if (-not [string]::IsNullOrWhiteSpace($env:ARC_INSTALL_DIR)) {
            $InstallDir = $env:ARC_INSTALL_DIR
        }
        else {
            $homeRoot = if (-not [string]::IsNullOrWhiteSpace($env:HOME)) {
                $env:HOME
            }
            elseif (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
                $env:USERPROFILE
            }
            else {
                $HOME
            }
            $InstallDir = Join-Path (Join-Path $homeRoot '.arc') 'bin'
        }
    }
    $resolvedInstallDir = [System.IO.Path]::GetFullPath($InstallDir)

    # 3. Resolve Target & Archive Name
    $targetTriple = 'x86_64-pc-windows-msvc'
    $canonicalArchiveName = "arc-v$normalizedVersion-$targetTriple.zip"

    # 4. Resolve BaseUrl
    if ([string]::IsNullOrWhiteSpace($BaseUrl)) {
        if (-not [string]::IsNullOrWhiteSpace($env:ARC_RELEASE_BASE_URL)) {
            $BaseUrl = $env:ARC_RELEASE_BASE_URL
        }
        else {
            $repoSlug = if (-not [string]::IsNullOrWhiteSpace($env:ARC_GITHUB_REPO)) {
                $env:ARC_GITHUB_REPO
            }
            else {
                'Tonybs03/Agent-Runtime-Customization'
            }
            $BaseUrl = "https://github.com/$repoSlug/releases/download/v$normalizedVersion"
        }
    }
    $normalizedBaseUrl = $BaseUrl.TrimEnd('/')

    # 5. Create temporary staging directory
    $stagingDir = Join-Path ([System.IO.Path]::GetTempPath()) ("arc-install-" + [System.Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

    # 6. Acquire archive and SHA256SUMS
    if (-not [string]::IsNullOrWhiteSpace($ArchivePath)) {
        if (-not (Test-Path -LiteralPath $ArchivePath -PathType Leaf)) {
            throw "Specified archive does not exist: $ArchivePath"
        }
        $localArchiveFile = [System.IO.Path]::GetFullPath($ArchivePath)
        $archiveFileName = [System.IO.Path]::GetFileName($localArchiveFile)
    }
    else {
        $localArchiveFile = Join-Path $stagingDir $canonicalArchiveName
        $archiveFileName = $canonicalArchiveName
        $archiveUrl = "$normalizedBaseUrl/$canonicalArchiveName"
        Write-Output "Downloading $archiveUrl ..."
        Invoke-WebRequest -Uri $archiveUrl -OutFile $localArchiveFile -UseBasicParsing
    }

    if (-not [string]::IsNullOrWhiteSpace($ChecksumPath)) {
        if (-not (Test-Path -LiteralPath $ChecksumPath -PathType Leaf)) {
            throw "Specified checksum file does not exist: $ChecksumPath"
        }
        $localChecksumFile = [System.IO.Path]::GetFullPath($ChecksumPath)
    }
    else {
        $localChecksumFile = Join-Path $stagingDir 'SHA256SUMS'
        $checksumUrl = "$normalizedBaseUrl/SHA256SUMS"
        Write-Output "Downloading $checksumUrl ..."
        Invoke-WebRequest -Uri $checksumUrl -OutFile $localChecksumFile -UseBasicParsing
    }

    # 7. Verify SHA-256 BEFORE extracting archive
    $expectedHash = Resolve-ExpectedSha256 -SumsFilePath $localChecksumFile -CandidateNames @($archiveFileName, $canonicalArchiveName)
    if ([string]::IsNullOrWhiteSpace($expectedHash)) {
        throw "No matching SHA-256 entry found in '$localChecksumFile' for archive '$archiveFileName' (or '$canonicalArchiveName')."
    }

    $actualHash = Get-FileSha256Hex -FilePath $localArchiveFile
    if ($actualHash -ne $expectedHash) {
        throw "SHA-256 checksum mismatch for '$archiveFileName': expected $expectedHash, got $actualHash. Aborting before extraction."
    }
    Write-Output "Verified SHA-256 checksum for $archiveFileName ($actualHash)"

    # 8. Extract archive into temporary directory
    $extractDir = Join-Path $stagingDir 'extracted'
    New-Item -ItemType Directory -Path $extractDir -Force | Out-Null
    Extract-ZipArchive -ZipPath $localArchiveFile -DestinationPath $extractDir

    $extractedArc = Find-ExtractedFile -RootDir $extractDir -FileName 'arc.exe'
    $extractedSidecar = Find-ExtractedFile -RootDir $extractDir -FileName 'arc-decision-ui-host.exe'

    if ([string]::IsNullOrWhiteSpace($extractedArc)) {
        throw "Required binary 'arc.exe' is missing from the release archive."
    }
    if ([string]::IsNullOrWhiteSpace($extractedSidecar)) {
        throw "Required sibling binary 'arc-decision-ui-host.exe' is missing from the release archive."
    }

    # 9. Install sibling binaries and license files into InstallDir
    if (-not (Test-Path -LiteralPath $resolvedInstallDir -PathType Container)) {
        New-Item -ItemType Directory -Path $resolvedInstallDir -Force | Out-Null
    }

    $installedArc = Join-Path $resolvedInstallDir 'arc.exe'
    $installedSidecar = Join-Path $resolvedInstallDir 'arc-decision-ui-host.exe'

    Copy-Item -LiteralPath $extractedArc -Destination $installedArc -Force
    Copy-Item -LiteralPath $extractedSidecar -Destination $installedSidecar -Force

    foreach ($licenseFile in @('LICENSE-MIT', 'LICENSE-APACHE')) {
        $extractedLicense = Find-ExtractedFile -RootDir $extractDir -FileName $licenseFile
        if (-not [string]::IsNullOrWhiteSpace($extractedLicense)) {
            Copy-Item -LiteralPath $extractedLicense -Destination (Join-Path $resolvedInstallDir $licenseFile) -Force
        }
    }

    Write-Output "Arc v$normalizedVersion is dual-licensed under MIT OR Apache-2.0 (see LICENSE-MIT and LICENSE-APACHE)."

    # 10. Post-install verification (sibling existence and arc.exe --version)
    if (-not (Test-Path -LiteralPath $installedArc -PathType Leaf)) {
        throw "Post-install verification failed: 'arc.exe' was not found at '$installedArc'."
    }
    if (-not (Test-Path -LiteralPath $installedSidecar -PathType Leaf)) {
        throw "Post-install verification failed: sibling 'arc-decision-ui-host.exe' was not found at '$installedSidecar'."
    }

    $arcParent = (Get-Item -LiteralPath $installedArc).Directory.FullName
    $sidecarParent = (Get-Item -LiteralPath $installedSidecar).Directory.FullName
    if (-not [string]::Equals($arcParent, $sidecarParent, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Post-install verification failed: 'arc.exe' and 'arc-decision-ui-host.exe' must be in the same directory."
    }

    $versionOutput = & $installedArc --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Post-install verification failed: '$installedArc --version' exited with code $LASTEXITCODE."
    }
    Write-Output "Verified binary execution: $($versionOutput | Out-String | ForEach-Object { $_.Trim() })"
    Write-Output "Installed arc.exe and arc-decision-ui-host.exe side-by-side in: $resolvedInstallDir"

    # 11. Inspect / update PATH
    $inProcessPath = Test-DirectoryInPath -DirectoryPath $resolvedInstallDir -PathString $env:PATH
    if ($inProcessPath) {
        Write-Output "Install directory '$resolvedInstallDir' is already on PATH."
    }
    elseif ($NoModifyPath) {
        Write-Output "Note: '$resolvedInstallDir' is not on your PATH (-NoModifyPath was specified)."
        Write-Output "To add it to your current PowerShell session PATH, run:"
        Write-Output "  `$env:PATH = `"$resolvedInstallDir;`$env:PATH`""
    }
    else {
        $userPath = [System.Environment]::GetEnvironmentVariable('Path', 'User')
        if (-not (Test-DirectoryInPath -DirectoryPath $resolvedInstallDir -PathString $userPath)) {
            $newUserPath = if ([string]::IsNullOrWhiteSpace($userPath)) {
                $resolvedInstallDir
            }
            else {
                "$userPath;$resolvedInstallDir"
            }
            [System.Environment]::SetEnvironmentVariable('Path', $newUserPath, 'User')
            Write-Output "Added '$resolvedInstallDir' to your persistent User PATH."
        }
        $env:PATH = "$resolvedInstallDir;$env:PATH"
        Write-Output "Updated PATH with '$resolvedInstallDir'."
    }

    exit 0
}
catch {
    [Console]::Error.WriteLine("Error: $($_.Exception.Message)")
    exit 1
}
finally {
    if ($null -ne $stagingDir -and (Test-Path -LiteralPath $stagingDir)) {
        Remove-Item -LiteralPath $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
