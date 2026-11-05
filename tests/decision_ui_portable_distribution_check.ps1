#requires -Version 7.0
[CmdletBinding()]
param(
    [string]$Manifest = 'docs/internal/evidence/decision-ui/distribution-20260829.json',
    [string]$PrimaryBinary = '',
    [string]$SidecarBinary = '',
    [string]$OutputRoot = 'docs/internal/evidence/decision-ui/distribution-runs',
    [switch]$Build
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    throw 'La validación portable de esta implementación requiere Windows.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$manifestPath = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $Manifest))
$outputRootPath = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $OutputRoot))
$runId = "portable-distribution-$(Get-Date -Format 'yyyyMMddTHHmmssfff')"
$runDirectory = Join-Path $outputRootPath $runId
New-Item -ItemType Directory -Force -Path $runDirectory | Out-Null

$checks = [System.Collections.Generic.List[object]]::new()
$commands = [System.Collections.Generic.List[object]]::new()
$previousUdfRoot = [Environment]::GetEnvironmentVariable('ARC_DECISION_UI_UDF_ROOT', 'Process')
$previousTrace = [Environment]::GetEnvironmentVariable('ARC_DECISION_UI_TRACE', 'Process')
$protectedAclApplied = $false
$protectedIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

function Add-Check {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [Parameter(Mandatory = $true)][string]$Details
    )

    [void]$checks.Add([ordered]@{
        name = $Name
        result = if ($Passed) { 'PASS' } else { 'FAIL' }
        details = $Details
    })
}

function Add-Command {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][object]$Result,
        [Parameter(Mandatory = $true)][string]$StdoutLog,
        [Parameter(Mandatory = $true)][string]$StderrLog
    )

    [void]$commands.Add([ordered]@{
        name = $Name
        executable = $Executable
        arguments = @($Arguments)
        working_directory = $WorkingDirectory
        exit_code = $Result.exit_code
        timed_out = $Result.timed_out
        elapsed_ms = $Result.elapsed_ms
        result = if ($Result.exit_code -eq 0 -and -not $Result.timed_out) { 'PASS' } else { 'FAIL' }
        stdout_log = $StdoutLog
        stderr_log = $StderrLog
    })
}

function Test-Check {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )

    try {
        $detail = & $Action
        $detailText = if ($null -eq $detail) { 'completed' } else { [string]$detail }
        Add-Check -Name $Name -Passed $true -Details $detailText
    }
    catch {
        Add-Check -Name $Name -Passed $false -Details $_.Exception.Message
    }
}

function Resolve-RepoPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $candidate = if ([System.IO.Path]::IsPathRooted($Path)) { $Path } else { Join-Path $repoRoot $Path }
    return [System.IO.Path]::GetFullPath($candidate)
}

function Get-RunRelativePath {
    param([AllowNull()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return 'NOT-CREATED'
    }
    return [System.IO.Path]::GetRelativePath($runDirectory, $Path).Replace('\', '/')
}

function Read-TomlVersion {
    param([Parameter(Mandatory = $true)][string]$Path)

    $match = Select-String -LiteralPath $Path -Pattern '^\s*version\s*=\s*"([^"]+)"' | Select-Object -First 1
    if ($null -eq $match) {
        throw "No se encontró version en $Path"
    }
    return $match.Matches[0].Groups[1].Value
}

function Get-ArtifactRecord {
    param([Parameter(Mandatory = $true)][string]$Path)

    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if (-not $item.PSIsContainer -and $item.Length -ge 0) {
        return [ordered]@{
            path = $item.FullName
            file_name = $item.Name
            size_bytes = [int64]$item.Length
            sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    throw "El artefacto no es un archivo regular: $Path"
}

function Invoke-CapturedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][hashtable]$EnvironmentOverrides,
        [Parameter(Mandatory = $true)][string[]]$RemoveEnvironmentNames,
        [Parameter(Mandatory = $true)][int]$TimeoutMs
    )

    $start = [System.Diagnostics.Stopwatch]::StartNew()
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $FilePath
    $psi.WorkingDirectory = $WorkingDirectory
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        [void]$psi.ArgumentList.Add($argument)
    }
    foreach ($name in $RemoveEnvironmentNames) {
        [void]$psi.Environment.Remove($name)
    }
    foreach ($entry in $EnvironmentOverrides.GetEnumerator()) {
        $psi.Environment[$entry.Key] = [string]$entry.Value
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $psi
    try {
        if (-not $process.Start()) {
            throw "No se pudo iniciar el proceso: $FilePath"
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $timedOut = -not $process.WaitForExit($TimeoutMs)
        if ($timedOut) {
            try {
                $process.Kill($true)
            }
            catch [System.InvalidOperationException] {
            }
            $process.WaitForExit()
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        $exitCode = if ($timedOut) { -1 } else { $process.ExitCode }
        $start.Stop()
        return [pscustomobject]@{
            exit_code = [int]$exitCode
            timed_out = [bool]$timedOut
            elapsed_ms = [int64]$start.ElapsedMilliseconds
            stdout = [string]$stdout
            stderr = [string]$stderr
        }
    }
    finally {
        $process.Dispose()
    }
}

function Save-ProcessLogs {
    param(
        [Parameter(Mandatory = $true)][object]$Result,
        [Parameter(Mandatory = $true)][string]$Prefix
    )

    $stdoutRelative = "$Prefix-stdout.log"
    $stderrRelative = "$Prefix-stderr.log"
    [System.IO.File]::WriteAllText((Join-Path $runDirectory $stdoutRelative), $Result.stdout)
    [System.IO.File]::WriteAllText((Join-Path $runDirectory $stderrRelative), $Result.stderr)
    return [pscustomobject]@{ stdout = $stdoutRelative; stderr = $stderrRelative }
}

function Invoke-BuildCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory
    )

    $logPath = Join-Path $runDirectory "build-$Name.log"
    Push-Location $WorkingDirectory
    try {
        & $FilePath @Arguments *> $logPath
        $exitCode = [int]$LASTEXITCODE
    }
    finally {
        Pop-Location
    }
    [void]$commands.Add([ordered]@{
        name = "build-$Name"
        executable = $FilePath
        arguments = @($Arguments)
        working_directory = $WorkingDirectory
        exit_code = $exitCode
        timed_out = $false
        elapsed_ms = $null
        result = if ($exitCode -eq 0) { 'PASS' } else { 'FAIL' }
        stdout_log = "build-$Name.log"
        stderr_log = "build-$Name.log"
    })
    if ($exitCode -ne 0) {
        throw "El build $Name falló con exit code $exitCode"
    }
}

function Get-WebView2Runtime {
    $registryPaths = @(
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}',
        'HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
    )
    foreach ($registryPath in $registryPaths) {
        if (Test-Path -LiteralPath $registryPath) {
            $item = Get-ItemProperty -LiteralPath $registryPath
            return [ordered]@{
                registry_path = $registryPath
                name = [string]$item.name
                pv = [string]$item.pv
                version = if ($null -ne $item.PSObject.Properties['VERSION']) { [string]$item.VERSION } else { '' }
            }
        }
    }
    return $null
}

function Invoke-DecisionSmoke {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ArcPath,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$UdfPath
    )

    New-Item -ItemType Directory -Force -Path $UdfPath | Out-Null
    $result = Invoke-CapturedProcess `
        -FilePath $ArcPath `
        -Arguments @('decision', 'ask', '--title', 'Arc portable distribution smoke', '--message', 'Automatic timeout smoke; no selection is required.') `
        -WorkingDirectory $WorkingDirectory `
        -EnvironmentOverrides @{
            ARC_DECISION_UI_UDF_ROOT = $UdfPath
            ARC_DECISION_UI_TRACE = '1'
            ARC_DECISION_UI_TIMEOUT_MS = '5000'
        } `
        -RemoveEnvironmentNames @('ARC_DECISION_UI_HOST') `
        -TimeoutMs 20000
    $logs = Save-ProcessLogs -Result $result -Prefix $Name
    Add-Command -Name $Name -Executable $ArcPath -Arguments @('decision', 'ask', '--title', 'Arc portable distribution smoke', '--message', 'Automatic timeout smoke; no selection is required.') -WorkingDirectory $WorkingDirectory -Result $result -StdoutLog $logs.stdout -StderrLog $logs.stderr
    if ($result.timed_out -or $result.exit_code -ne 0) {
        throw "El smoke $Name no terminó correctamente: exit=$($result.exit_code), timed_out=$($result.timed_out)"
    }
    $lines = @($result.stdout -split '\r?\n' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($lines.Count -ne 1) {
        throw "El smoke $Name no produjo exactamente un frame JSON: líneas=$($lines.Count)"
    }
    $response = $lines[0] | ConvertFrom-Json
    if ($response.status -ne 'unresolved' -or $response.reason -ne 'timed_out') {
        throw "El smoke $Name no terminó como TimedOut: status=$($response.status), reason=$($response.reason)"
    }
    if ($result.stderr -notmatch 'frontend_ready' -or $result.stderr -notmatch 'response_emitted' -or $result.stderr -notmatch 'host_exit_requested') {
        throw "El smoke $Name no observó la secuencia WebView/readiness/exit esperada"
    }
    return [ordered]@{
        elapsed_ms = $result.elapsed_ms
        response_status = [string]$response.status
        response_reason = [string]$response.reason
        trace_ready = $true
        trace_response_emitted = $true
        trace_exit_requested = $true
    }
}

function Invoke-SidecarHarnessSmoke {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$SidecarPath,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][string]$UdfPath
    )

    $pwsh = (Get-Command pwsh.exe -ErrorAction Stop).Source
    $harnessPath = Resolve-RepoPath -Path 'tests/decision_ui_process_harness.ps1'
    $arguments = @(
        '-NoLogo',
        '-NoProfile',
        '-File',
        $harnessPath,
        '-Case',
        'timeout',
        '-Binary',
        $SidecarPath,
        '-OutputRoot',
        $OutputPath,
        '-DecisionTimeoutMs',
        '5000',
        '-SupervisorTimeoutMs',
        '10000'
    )
    $result = Invoke-CapturedProcess -FilePath $pwsh -Arguments $arguments -WorkingDirectory (Split-Path -Parent $SidecarPath) -EnvironmentOverrides @{
        ARC_DECISION_UI_TRACE = '1'
        ARC_DECISION_UI_UDF_ROOT = $UdfPath
    } -RemoveEnvironmentNames @('ARC_DECISION_UI_HOST') -TimeoutMs 30000
    $logs = Save-ProcessLogs -Result $result -Prefix $Name
    Add-Command -Name $Name -Executable $pwsh -Arguments $arguments -WorkingDirectory (Split-Path -Parent $SidecarPath) -Result $result -StdoutLog $logs.stdout -StderrLog $logs.stderr
    if ($result.timed_out -or $result.exit_code -ne 0) {
        throw "El harness $Name falló: exit=$($result.exit_code); timed_out=$($result.timed_out)"
    }
    if ($result.stdout -notmatch '(?m)^RESULT=PASS\s*$') {
        throw "El harness $Name no reportó RESULT=PASS"
    }
    return [ordered]@{
        elapsed_ms = $result.elapsed_ms
        harness_result = 'PASS'
        output_root = $OutputPath
    }
}

$runtimeInfo = $null
$manifestObject = $null
$primarySourcePath = $null
$sidecarSourcePath = $null
$packageRoot = $null
$protectedRoot = $null
$missingRoot = $null
$result = 'FAIL'
$fatalError = $null

try {
    try {
        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
            throw "No existe el manifest: $manifestPath"
        }
        $manifestObject = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
        Add-Check -Name 'manifest_parse' -Passed $true -Details "Manifest parseado: $Manifest"
    }
    catch {
        Add-Check -Name 'manifest_parse' -Passed $false -Details $_.Exception.Message
        throw
    }

    if ($Build) {
        try {
            $npm = (Get-Command npm.cmd -ErrorAction Stop).Source
            Invoke-BuildCommand -Name 'frontend-release' -FilePath $npm -Arguments @('run', 'build:workspace:release') -WorkingDirectory (Join-Path $repoRoot 'ui\decision')
            Add-Check -Name 'release_build' -Passed $true -Details 'Frontend y binarios release generados por build:workspace:release.'
        }
        catch {
            Add-Check -Name 'release_build' -Passed $false -Details $_.Exception.Message
        }
    }

    $manifestArtifacts = @{}
    foreach ($artifact in @($manifestObject.artifacts)) {
        $manifestArtifacts[[string]$artifact.role] = $artifact
    }
    foreach ($role in @('primary', 'decision_sidecar')) {
        if (-not $manifestArtifacts.ContainsKey($role)) {
            throw "El manifest no contiene el artefacto requerido: $role"
        }
    }
    $primarySourcePath = if ([string]::IsNullOrWhiteSpace($PrimaryBinary)) { Resolve-RepoPath -Path ([string]$manifestArtifacts['primary'].relative_path) } else { Resolve-RepoPath -Path $PrimaryBinary }
    $sidecarSourcePath = if ([string]::IsNullOrWhiteSpace($SidecarBinary)) { Resolve-RepoPath -Path ([string]$manifestArtifacts['decision_sidecar'].relative_path) } else { Resolve-RepoPath -Path $SidecarBinary }

    Test-Check -Name 'source_artifacts_exist' -Action {
        if (-not (Test-Path -LiteralPath $primarySourcePath -PathType Leaf)) { throw "No existe primary: $primarySourcePath" }
        if (-not (Test-Path -LiteralPath $sidecarSourcePath -PathType Leaf)) { throw "No existe sidecar: $sidecarSourcePath" }
        "primary=$primarySourcePath; sidecar=$sidecarSourcePath"
    }

    $rootVersion = Read-TomlVersion -Path (Join-Path $repoRoot 'Cargo.toml')
    $sidecarVersion = Read-TomlVersion -Path (Join-Path $repoRoot 'ui/decision/src-tauri/Cargo.toml')
    $frontendVersion = (Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'ui/decision/package.json') | ConvertFrom-Json).version
    Test-Check -Name 'version_pair' -Action {
        if ($rootVersion -ne $sidecarVersion -or $sidecarVersion -ne $frontendVersion -or $manifestObject.product_version -ne $rootVersion) {
            throw "Versiones incompatibles: root=$rootVersion; sidecar=$sidecarVersion; frontend=$frontendVersion; manifest=$($manifestObject.product_version)"
        }
        "product_version=$rootVersion"
    }

    $sourceRecords = @{}
    foreach ($role in @('primary', 'decision_sidecar')) {
        $path = if ($role -eq 'primary') { $primarySourcePath } else { $sidecarSourcePath }
        $actual = Get-ArtifactRecord -Path $path
        $expected = $manifestArtifacts[$role]
        $sourceRecords[$role] = $actual
        Test-Check -Name "source_hash_$role" -Action {
            if ([int64]$actual.size_bytes -ne [int64]$expected.size_bytes -or $actual.sha256 -ne ([string]$expected.sha256).ToLowerInvariant()) {
                throw "Mismatch $role`: size=$($actual.size_bytes)/$($expected.size_bytes); sha256=$($actual.sha256)/$($expected.sha256)"
            }
            "size=$($actual.size_bytes); sha256=$($actual.sha256)"
        }
    }

    $packageRoot = Join-Path $runDirectory "Arc-$($manifestObject.product_version)"
    New-Item -ItemType Directory -Force -Path $packageRoot | Out-Null
    Copy-Item -LiteralPath $primarySourcePath -Destination (Join-Path $packageRoot 'arc.exe')
    Copy-Item -LiteralPath $sidecarSourcePath -Destination (Join-Path $packageRoot 'arc-decision-ui-host.exe')
    Test-Check -Name 'portable_sibling_layout' -Action {
        $stagedPrimary = Join-Path $packageRoot 'arc.exe'
        $stagedSidecar = Join-Path $packageRoot 'arc-decision-ui-host.exe'
        if (-not (Test-Path -LiteralPath $stagedPrimary -PathType Leaf) -or -not (Test-Path -LiteralPath $stagedSidecar -PathType Leaf)) {
            throw 'El paquete portable no contiene el par de ejecutables.'
        }
        if ((Split-Path -Parent $stagedPrimary) -ne (Split-Path -Parent $stagedSidecar)) {
            throw 'El primary y el sidecar no son hermanos.'
        }
        "package=$packageRoot; primary=arc.exe; sidecar=arc-decision-ui-host.exe"
    }

    foreach ($role in @('primary', 'decision_sidecar')) {
        $path = if ($role -eq 'primary') { Join-Path $packageRoot 'arc.exe' } else { Join-Path $packageRoot 'arc-decision-ui-host.exe' }
        $expected = $manifestArtifacts[$role]
        $actual = Get-ArtifactRecord -Path $path
        Test-Check -Name "staged_hash_$role" -Action {
            if ([int64]$actual.size_bytes -ne [int64]$expected.size_bytes -or $actual.sha256 -ne ([string]$expected.sha256).ToLowerInvariant()) {
                throw "Mismatch staged $role`: size=$($actual.size_bytes)/$($expected.size_bytes); sha256=$($actual.sha256)/$($expected.sha256)"
            }
            "size=$($actual.size_bytes); sha256=$($actual.sha256)"
        }
    }

    $runtimeInfo = Get-WebView2Runtime
    $runtimePath = Join-Path $runDirectory 'webview2-runtime.json'
    $runtimeInfo | ConvertTo-Json -Depth 5 | Set-Content -Encoding utf8 -LiteralPath $runtimePath
    Test-Check -Name 'webview2_runtime_required' -Action {
        if ($null -eq $runtimeInfo -or [string]::IsNullOrWhiteSpace($runtimeInfo.pv)) {
            throw 'Microsoft Edge WebView2 Runtime no está registrado o no expone PV.'
        }
        "name=$($runtimeInfo.name); pv=$($runtimeInfo.pv); registry_path=$($runtimeInfo.registry_path)"
    }

    $env:ARC_DECISION_UI_UDF_ROOT = Join-Path $runDirectory 'udf-clean'
    $env:ARC_DECISION_UI_TRACE = '1'
    $cleanVersion = Invoke-CapturedProcess -FilePath (Join-Path $packageRoot 'arc.exe') -Arguments @('--version') -WorkingDirectory $packageRoot -EnvironmentOverrides @{} -RemoveEnvironmentNames @('ARC_DECISION_UI_HOST') -TimeoutMs 10000
    $cleanLogs = Save-ProcessLogs -Result $cleanVersion -Prefix 'clean-version'
    Add-Command -Name 'clean-version' -Executable (Join-Path $packageRoot 'arc.exe') -Arguments @('--version') -WorkingDirectory $packageRoot -Result $cleanVersion -StdoutLog $cleanLogs.stdout -StderrLog $cleanLogs.stderr
    Test-Check -Name 'clean_execution' -Action {
        if ($cleanVersion.timed_out -or $cleanVersion.exit_code -ne 0 -or $cleanVersion.stdout -notmatch [regex]::Escape($rootVersion)) {
            throw "arc --version falló: exit=$($cleanVersion.exit_code); timed_out=$($cleanVersion.timed_out); stdout=$($cleanVersion.stdout.Trim())"
        }
        "exit=$($cleanVersion.exit_code); version=$rootVersion; elapsed_ms=$($cleanVersion.elapsed_ms)"
    }

    Test-Check -Name 'portable_decision_smoke' -Action {
        Invoke-SidecarHarnessSmoke -Name 'portable-sidecar-smoke' -SidecarPath (Join-Path $packageRoot 'arc-decision-ui-host.exe') -OutputPath (Join-Path $runDirectory 'portable-harness') -UdfPath (Join-Path $runDirectory 'udf-clean') | ConvertTo-Json -Compress
    }

    $missingRoot = Join-Path $runDirectory 'missing-sidecar'
    New-Item -ItemType Directory -Force -Path $missingRoot | Out-Null
    Copy-Item -LiteralPath $primarySourcePath -Destination (Join-Path $missingRoot 'arc.exe')
    Test-Check -Name 'sidecar_missing_fails_closed' -Action {
        $missingResult = Invoke-CapturedProcess -FilePath (Join-Path $missingRoot 'arc.exe') -Arguments @('decision', 'ask', '--title', 'Arc missing sidecar', '--message', 'Expected transport failure.') -WorkingDirectory $missingRoot -EnvironmentOverrides @{ ARC_DECISION_UI_UDF_ROOT = (Join-Path $runDirectory 'udf-missing') } -RemoveEnvironmentNames @('ARC_DECISION_UI_HOST') -TimeoutMs 10000
        $missingLogs = Save-ProcessLogs -Result $missingResult -Prefix 'missing-sidecar'
        Add-Command -Name 'sidecar-missing' -Executable (Join-Path $missingRoot 'arc.exe') -Arguments @('decision', 'ask', '--title', 'Arc missing sidecar', '--message', 'Expected transport failure.') -WorkingDirectory $missingRoot -Result $missingResult -StdoutLog $missingLogs.stdout -StderrLog $missingLogs.stderr
        if ($missingResult.timed_out -or $missingResult.exit_code -ne 0) { throw "La ausencia del sidecar no terminó limpiamente: exit=$($missingResult.exit_code)" }
        $lines = @($missingResult.stdout -split '\r?\n' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($lines.Count -ne 1) { throw "La ausencia del sidecar produjo $($lines.Count) frames." }
        $response = $lines[0] | ConvertFrom-Json
        if ($response.decision.status -ne 'unresolved' -or $response.decision.reason -ne 'transport_failed') { throw "La ausencia del sidecar no fue TransportFailed: status=$($response.decision.status); reason=$($response.decision.reason)" }
        "exit=$($missingResult.exit_code); status=$($response.decision.status); reason=$($response.decision.reason); sibling_not_found=true"
    }

    $protectedRoot = Join-Path $runDirectory 'protected-install'
    New-Item -ItemType Directory -Force -Path $protectedRoot | Out-Null
    Copy-Item -LiteralPath (Join-Path $packageRoot 'arc.exe') -Destination (Join-Path $protectedRoot 'arc.exe')
    Copy-Item -LiteralPath (Join-Path $packageRoot 'arc-decision-ui-host.exe') -Destination (Join-Path $protectedRoot 'arc-decision-ui-host.exe')
    $aclInheritanceText = (& icacls.exe $protectedRoot /inheritance:r /C 2>&1 | Out-String)
    $aclInheritanceExit = [int]$LASTEXITCODE
    $aclGrantText = (& icacls.exe $protectedRoot /grant:r ("{0}:(OI)(CI)(RX)" -f $protectedIdentity) /T /C 2>&1 | Out-String)
    $aclGrantExit = [int]$LASTEXITCODE
    $aclDenyText = (& icacls.exe $protectedRoot /deny ("{0}:(OI)(CI)(WD,AD,DC,WA)" -f $protectedIdentity) /T /C 2>&1 | Out-String)
    $aclDenyExit = [int]$LASTEXITCODE
    ($aclInheritanceText + $aclGrantText + $aclDenyText) | Set-Content -Encoding utf8 -LiteralPath (Join-Path $runDirectory 'protected-acl-apply.log')
    $aclApplyExit = if ($aclInheritanceExit -eq 0 -and $aclGrantExit -eq 0 -and $aclDenyExit -eq 0) { 0 } else { 1 }
    $protectedAclApplied = $aclApplyExit -eq 0
    [ordered]@{
        identity = $protectedIdentity
        deny = 'Write'
        root = $protectedRoot
        inheritance_exit_code = $aclInheritanceExit
        grant_exit_code = $aclGrantExit
        deny_exit_code = $aclDenyExit
        apply_exit_code = $aclApplyExit
        applied = $protectedAclApplied
        sddl = (Get-Acl -LiteralPath $protectedRoot).Sddl
    } | ConvertTo-Json -Depth 5 | Set-Content -Encoding utf8 -LiteralPath (Join-Path $runDirectory 'protected-acl.json')
    Test-Check -Name 'protected_location_acl' -Action {
        if (-not $protectedAclApplied) { throw "icacls no pudo aplicar el deny de escritura: exit=$aclApplyExit" }
        "isolated_fixture=$protectedRoot; identity=$protectedIdentity; deny=Write"
    }
    Test-Check -Name 'protected_location_execution' -Action {
        if (-not $protectedAclApplied) { throw 'No se ejecuta el caso protegido porque la ACL no se pudo aplicar.' }
        $protectedVersion = Invoke-CapturedProcess -FilePath (Join-Path $protectedRoot 'arc.exe') -Arguments @('--version') -WorkingDirectory $protectedRoot -EnvironmentOverrides @{} -RemoveEnvironmentNames @('ARC_DECISION_UI_HOST') -TimeoutMs 10000
        $protectedLogs = Save-ProcessLogs -Result $protectedVersion -Prefix 'protected-version'
        Add-Command -Name 'protected-version' -Executable (Join-Path $protectedRoot 'arc.exe') -Arguments @('--version') -WorkingDirectory $protectedRoot -Result $protectedVersion -StdoutLog $protectedLogs.stdout -StderrLog $protectedLogs.stderr
        if ($protectedVersion.timed_out -or $protectedVersion.exit_code -ne 0 -or $protectedVersion.stdout -notmatch [regex]::Escape($rootVersion)) { throw "Ejecución desde ubicación protegida falló: exit=$($protectedVersion.exit_code)" }
        "exit=$($protectedVersion.exit_code); version=$rootVersion; install_directory_write_denied=true"
    }
    Test-Check -Name 'protected_decision_smoke' -Action {
        if (-not $protectedAclApplied) { throw 'No se ejecuta el smoke protegido porque la ACL no se pudo aplicar.' }
        Invoke-SidecarHarnessSmoke -Name 'protected-sidecar-smoke' -SidecarPath (Join-Path $protectedRoot 'arc-decision-ui-host.exe') -OutputPath (Join-Path $runDirectory 'protected-harness') -UdfPath (Join-Path $runDirectory 'udf-protected') | ConvertTo-Json -Compress
    }
}
catch {
    $fatalError = $_.Exception.Message
    if (@($checks | Where-Object { $_.result -eq 'FAIL' }).Count -eq 0) {
        Add-Check -Name 'runner_execution' -Passed $false -Details $fatalError
    }
}
finally {
    if ($protectedAclApplied -and $null -ne $protectedRoot -and (Test-Path -LiteralPath $protectedRoot)) {
        $aclRestoreText = (& icacls.exe $protectedRoot /remove:d $protectedIdentity /T /C 2>&1 | Out-String)
        $aclRestoreExit = [int]$LASTEXITCODE
        $aclRestoreText | Set-Content -Encoding utf8 -LiteralPath (Join-Path $runDirectory 'protected-acl-restore.log')
        Add-Check -Name 'protected_location_acl_restore' -Passed ($aclRestoreExit -eq 0) -Details "identity=$protectedIdentity; exit=$aclRestoreExit"
    }
    if ($null -eq $previousUdfRoot) { Remove-Item Env:ARC_DECISION_UI_UDF_ROOT -ErrorAction SilentlyContinue } else { $env:ARC_DECISION_UI_UDF_ROOT = $previousUdfRoot }
    if ($null -eq $previousTrace) { Remove-Item Env:ARC_DECISION_UI_TRACE -ErrorAction SilentlyContinue } else { $env:ARC_DECISION_UI_TRACE = $previousTrace }
}

$failedChecks = @($checks | Where-Object { $_.result -eq 'FAIL' })
$result = if ($failedChecks.Count -eq 0 -and $null -eq $fatalError) { 'PASS' } else { 'FAIL' }
$revision = (git -C $repoRoot rev-parse HEAD).Trim()
$run = [ordered]@{
    schema_version = 1
    run_id = $runId
    plan = 'PLAN-20260829-DECISION-UI-TAURI-SVELTE-REMEDIATION.md'
    scope = 'portable-distribution'
    revision = $revision
    manifest = [System.IO.Path]::GetRelativePath($repoRoot, $manifestPath).Replace('\', '/')
    product_version = [string]$manifestObject.product_version
    platform = [ordered]@{
        os = 'Windows'
        architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        shell = 'PowerShell'
        interactive_desktop = [Environment]::UserInteractive
        identity = $protectedIdentity
    }
    source_artifacts = $sourceRecords
    staged_package = Get-RunRelativePath -Path $packageRoot
    protected_fixture = Get-RunRelativePath -Path $protectedRoot
    runtime = $runtimeInfo
    checks = @($checks)
    commands = @($commands)
    result = $result
    failed_checks = @($failedChecks | ForEach-Object { $_.name })
    fatal_error = $fatalError
    limitations = @(
        'La ubicación protegida es un fixture aislado con deny de escritura; no existe instalador MSI/NSIS en el producto.',
        'La ausencia física de WebView2 no se simula desinstalando el runtime del equipo; se valida su presencia como prerrequisito y la política de sidecar ausente.',
        'Upgrade, rollback, offline runtime y janitor no forman parte de este alcance portable seleccionado.'
    )
}
$run | ConvertTo-Json -Depth 12 | Set-Content -Encoding utf8 -LiteralPath (Join-Path $runDirectory 'run.json')
@"
# Portable Distribution Run

- Run: $runId
- Scope: portable-distribution
- Revision: $revision
- Product version: $($manifestObject.product_version)
- Result: $result
- Package: $(Get-RunRelativePath -Path $packageRoot)
- Protected fixture: $(Get-RunRelativePath -Path $protectedRoot)

## Checks

$(@($checks | ForEach-Object { "- $($_.result): $($_.name) — $($_.details)" }) -join "`n")

## Limitations

- No existe instalador MSI/NSIS; la prueba valida distribución portable.
- WebView2 se comprueba como prerrequisito presente; no se desinstala del equipo para fabricar un caso ausente.
- Upgrade, rollback, offline runtime y janitor quedan fuera del alcance seleccionado.
"@ | Set-Content -Encoding utf8 -LiteralPath (Join-Path $runDirectory 'summary.md')

Write-Output "RUN_ID=$runId"
Write-Output "RUN_DIRECTORY=$runDirectory"
Write-Output "RESULT=$result"
Write-Output "CHECK_COUNT=$($checks.Count)"
Write-Output "FAILED_CHECKS=$(($failedChecks | ForEach-Object { $_.name }) -join ',')"
if ($result -ne 'PASS') { exit 1 }
