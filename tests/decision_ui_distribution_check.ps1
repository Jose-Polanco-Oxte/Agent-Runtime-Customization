[CmdletBinding()]
param(
    [string]$Manifest = "docs/internal/evidence/decision-ui/distribution-20260829.json",
    [string]$OutputRoot = "docs/internal/evidence/decision-ui/distribution-runs"
)

$ErrorActionPreference = "Stop"

function Resolve-RepositoryPath {
    param([string]$Path)
    $candidate = Join-Path (Get-Location) $Path
    return (Resolve-Path -LiteralPath $candidate).Path
}

function Add-Check {
    param(
        [System.Collections.Generic.List[object]]$Checks,
        [string]$Name,
        [bool]$Passed,
        [string]$Details
    )
    $Checks.Add([ordered]@{
        name = $Name
        result = if ($Passed) { "PASS" } else { "FAIL" }
        details = $Details
    })
}

$runId = "distribution-$(Get-Date -Format 'yyyyMMddTHHmmssfff')"
$runDirectory = Join-Path $OutputRoot $runId
New-Item -ItemType Directory -Force -Path $runDirectory | Out-Null
$checks = [System.Collections.Generic.List[object]]::new()
$errors = [System.Collections.Generic.List[string]]::new()

try {
    $manifestPath = Resolve-RepositoryPath $Manifest
    $manifestObject = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    Add-Check $checks "manifest_parse" $true "Manifest parsed as JSON."
}
catch {
    Add-Check $checks "manifest_parse" $false "Manifest could not be parsed."
    $errors.Add("manifest_parse")
    $manifestObject = $null
}

if ($null -ne $manifestObject) {
    $rootVersion = (Select-String -LiteralPath "Cargo.toml" -Pattern '^version = ' | Select-Object -First 1).Line.Trim().Split('"')[1]
    $sidecarVersion = (Select-String -LiteralPath "ui/decision/src-tauri/Cargo.toml" -Pattern '^version = ' | Select-Object -First 1).Line.Trim().Split('"')[1]
    $frontendVersion = (Get-Content -LiteralPath "ui/decision/package.json" -Raw | ConvertFrom-Json).version
    $versionsMatch = $rootVersion -eq $sidecarVersion -and $sidecarVersion -eq $frontendVersion -and $manifestObject.product_version -eq $rootVersion
    Add-Check $checks "version_pair" $versionsMatch "root=$rootVersion; sidecar=$sidecarVersion; frontend=$frontendVersion; manifest=$($manifestObject.product_version)"
    if (-not $versionsMatch) { $errors.Add("version_pair") }

    $artifactPaths = @{}
    foreach ($artifact in @($manifestObject.artifacts)) {
        try {
            $artifactPath = Resolve-RepositoryPath $artifact.relative_path
            $artifactPaths[$artifact.role] = $artifactPath
            $item = Get-Item -LiteralPath $artifactPath
            $actualHash = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
            $sizeMatch = [int64]$item.Length -eq [int64]$artifact.size_bytes
            $hashMatch = $actualHash -eq $artifact.sha256.ToLowerInvariant()
            $passed = $sizeMatch -and $hashMatch
            Add-Check $checks "artifact_$($artifact.role)" $passed "path=$($artifact.relative_path); size=$($item.Length)/$($artifact.size_bytes); sha256=$actualHash"
            if (-not $passed) { $errors.Add("artifact_$($artifact.role)") }
        }
        catch {
            Add-Check $checks "artifact_$($artifact.role)" $false "Artifact is missing or unreadable."
            $errors.Add("artifact_$($artifact.role)")
        }
    }

    $primary = $artifactPaths["primary"]
    $sidecar = $artifactPaths["decision_sidecar"]
    $siblingMatch = $null -ne $primary -and $null -ne $sidecar -and (Split-Path -Parent $primary) -eq (Split-Path -Parent $sidecar) -and (Split-Path -Leaf $sidecar) -eq "arc-decision-ui-host.exe"
    Add-Check $checks "sibling_layout" $siblingMatch "primary_dir=$(Split-Path -Parent $primary); sidecar_dir=$(Split-Path -Parent $sidecar)"
    if (-not $siblingMatch) { $errors.Add("sibling_layout") }

    $packagingContract = $manifestObject.packaging.bundle_active -eq $false -and $manifestObject.packaging.sibling_required -eq $true -and $manifestObject.packaging.owner -eq "Arc portable distribution pipeline"
    Add-Check $checks "packaging_contract" $packagingContract "bundle_active=$($manifestObject.packaging.bundle_active); owner=$($manifestObject.packaging.owner)"
    if (-not $packagingContract) { $errors.Add("packaging_contract") }
}

$result = if ($errors.Count -eq 0) { "PASS" } else { "FAIL" }
$stdoutLines = @(
    "RUN_ID=$runId"
    "RESULT=$result"
    "CHECK_COUNT=$($checks.Count)"
    "FAILED_CHECKS=$($errors -join ',')"
)
$stderrLines = @($checks | ForEach-Object { "$($_.result) $($_.name): $($_.details)" })
[System.IO.File]::WriteAllText((Join-Path $runDirectory "stdout.log"), (($stdoutLines -join "`n") + "`n"))
[System.IO.File]::WriteAllText((Join-Path $runDirectory "stderr.log"), (($stderrLines -join "`n") + "`n"))

$repoRevision = (git rev-parse HEAD).Trim()
$run = [ordered]@{
    run_id = $runId
    plan = "PLAN-20260829-DECISION-UI-TAURI-SVELTE-REMEDIATION.md"
    revision = $repoRevision
    platform = [ordered]@{
        os = "Windows"
        shell = "PowerShell"
        interactive_desktop = $false
    }
    toolchains = [ordered]@{
        powershell = $PSVersionTable.PSVersion.ToString()
        rustc = (& rustc --version).Trim()
        cargo = (& cargo --version).Trim()
    }
    commands = @([ordered]@{
        command = "tests/decision_ui_distribution_check.ps1"
        working_directory = (Get-Location).Path
        exit_code = if ($result -eq "PASS") { 0 } else { 1 }
        result = $result
        stdout_log = "stdout.log"
        stderr_log = "stderr.log"
        notes = "Exact artifact size, SHA-256, version-pair, sibling-layout and packaging-contract checks."
    })
    cases = @([ordered]@{
        case_id = "DUI010-distribution-contract"
        finding_ids = @("DUI-010", "DUI-002", "DUI-009")
        layer = "distribution"
        platform = "Windows"
        result = $result
        artifact = "run.json"
    })
}
$run | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $runDirectory "run.json") -Encoding utf8

$stdoutLines
Write-Output "RUN_DIRECTORY=$runDirectory"
if ($result -ne "PASS") { exit 1 }
