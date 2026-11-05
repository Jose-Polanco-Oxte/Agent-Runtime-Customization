[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Binary = (Join-Path $PSScriptRoot "..\target\release\arc-decision-ui-webdriver-fixture.exe"),

    [Parameter(Mandatory = $false)]
    [string]$OutputRoot = (Join-Path $PSScriptRoot "..\docs\internal\evidence\decision-ui\webdriver-runs"),

    [Parameter(Mandatory = $false)]
    [string]$Plan = "PLAN_ELIMINACION_RULE_EVALUATOR_Y_MIGRACION_CANONICA.md",

    [Parameter(Mandatory = $false)]
    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-CapturedCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList,
        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory,
        [Parameter(Mandatory = $true)]
        [string]$StdoutPath,
        [Parameter(Mandatory = $true)]
        [string]$StderrPath,
        [Parameter(Mandatory = $false)]
        [hashtable]$Environment = @{}
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $ArgumentList) {
        $startInfo.ArgumentList.Add($argument)
    }
    foreach ($entry in $Environment.GetEnumerator()) {
        $startInfo.Environment[$entry.Key] = [string]$entry.Value
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $startedAt = [System.Diagnostics.Stopwatch]::GetTimestamp()
    if (-not $process.Start()) {
        throw "Failed to start $FilePath"
    }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    [System.IO.File]::WriteAllText($StdoutPath, $stdout)
    [System.IO.File]::WriteAllText($StderrPath, $stderr)
    $elapsedMs = [math]::Round((([System.Diagnostics.Stopwatch]::GetTimestamp() - $startedAt) * 1000.0) / [System.Diagnostics.Stopwatch]::Frequency, 3)

    return [pscustomobject]@{
        ExitCode = [int]$process.ExitCode
        ElapsedMs = $elapsedMs
    }
}

function Get-WebDriverProcessIds {
    $ids = [System.Collections.Generic.List[int]]::new()
    foreach ($name in @("tauri-driver", "msedgedriver")) {
        foreach ($process in @(Get-Process -Name $name -ErrorAction SilentlyContinue)) {
            $ids.Add([int]$process.Id)
        }
    }
    return $ids.ToArray()
}

function Stop-NewWebDriverProcesses {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [int[]]$BaselineProcessIds
    )

    $newProcesses = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
    foreach ($name in @("tauri-driver", "msedgedriver")) {
        foreach ($process in @(Get-Process -Name $name -ErrorAction SilentlyContinue)) {
            if ($BaselineProcessIds -notcontains [int]$process.Id) {
                $newProcesses.Add($process)
            }
        }
    }

    $stoppedIds = [System.Collections.Generic.List[int]]::new()
    $failures = [System.Collections.Generic.List[string]]::new()
    foreach ($process in @($newProcesses | Sort-Object @{ Expression = { $_.ProcessName -ne "tauri-driver" } })) {
        try {
            $process.Refresh()
            if (-not $process.HasExited) {
                $process.Kill($true)
                if (-not $process.WaitForExit(5000)) {
                    $failures.Add("pid=$($process.Id):did_not_exit")
                    continue
                }
            }
            $stoppedIds.Add([int]$process.Id)
        }
        catch [System.InvalidOperationException] {
            $stoppedIds.Add([int]$process.Id)
        }
        catch {
            $failures.Add("pid=$($process.Id):$($_.Exception.GetType().Name)")
        }
    }

    $remainingIds = @(
        Get-WebDriverProcessIds | Where-Object { $BaselineProcessIds -notcontains [int]$_ }
    )
    return [pscustomobject]@{
        Passed = $failures.Count -eq 0 -and $remainingIds.Count -eq 0
        StoppedIds = @($stoppedIds)
        RemainingIds = $remainingIds
        Failures = @($failures)
    }
}

if (-not $IsWindows) {
    throw "This harness currently accredits the Windows tauri-driver path only"
}

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$uiRoot = Join-Path $repositoryRoot "ui\decision"
$runId = "webdriver-readiness-acl-$(Get-Date -Format 'yyyyMMddTHHmmssfff')"
$OutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
$runDirectory = Join-Path $OutputRoot $runId
New-Item -ItemType Directory -Force -Path $runDirectory | Out-Null

$npmCommand = (Get-Command npm.cmd -ErrorAction Stop).Source
$cargoCommand = (Get-Command cargo.exe -ErrorAction Stop).Source
$tauriDriverCommand = (Get-Command tauri-driver.exe -ErrorAction Stop).Source
$commands = [System.Collections.Generic.List[object]]::new()
$buildPassed = $true
$webdriverCleanupPassed = $true

if (-not $SkipBuild) {
    $frontend = Invoke-CapturedCommand `
        -FilePath $npmCommand `
        -ArgumentList @("run", "build") `
        -WorkingDirectory $uiRoot `
        -StdoutPath (Join-Path $runDirectory "npm-build.stdout.log") `
        -StderrPath (Join-Path $runDirectory "npm-build.stderr.log")
    $frontendResult = if ($frontend.ExitCode -eq 0) { "PASS" } else { "FAIL" }
    $commands.Add([ordered]@{
        command = "npm run build"
        working_directory = "ui/decision"
        exit_code = $frontend.ExitCode
        result = $frontendResult
        stdout_log = "npm-build.stdout.log"
        stderr_log = "npm-build.stderr.log"
        notes = "elapsed_ms=$($frontend.ElapsedMs)"
    })
    $buildPassed = $frontend.ExitCode -eq 0

    if ($buildPassed) {
        $cargo = Invoke-CapturedCommand `
            -FilePath $cargoCommand `
            -ArgumentList @(
                "build",
                "--locked",
                "--release",
                "--manifest-path", "ui/decision/src-tauri/Cargo.toml",
                "--features", "custom-protocol,webdriver-fixture",
                "--bin", "arc-decision-ui-webdriver-fixture"
            ) `
            -WorkingDirectory $repositoryRoot `
            -StdoutPath (Join-Path $runDirectory "cargo-build.stdout.log") `
            -StderrPath (Join-Path $runDirectory "cargo-build.stderr.log")
        $cargoResult = if ($cargo.ExitCode -eq 0) { "PASS" } else { "FAIL" }
        $commands.Add([ordered]@{
            command = "cargo build --locked --release --manifest-path ui/decision/src-tauri/Cargo.toml --features custom-protocol,webdriver-fixture --bin arc-decision-ui-webdriver-fixture"
            working_directory = "."
            exit_code = $cargo.ExitCode
            result = $cargoResult
            stdout_log = "cargo-build.stdout.log"
            stderr_log = "cargo-build.stderr.log"
            notes = "elapsed_ms=$($cargo.ElapsedMs)"
        })
        $buildPassed = $cargo.ExitCode -eq 0
    }
}

$webdriverExitCode = -1
if ($buildPassed -and (Test-Path -LiteralPath $Binary -PathType Leaf)) {
    $resolvedBinary = (Resolve-Path -LiteralPath $Binary).Path
    $webdriverProcessesBefore = @(Get-WebDriverProcessIds)
    $webdriver = $null
    $cleanup = $null
    $terminalEvidencePath = (Join-Path $runDirectory "terminal-attempts.log")
    $traceFilePath = (Join-Path $runDirectory "webdriver-trace.log")
    $udfPath = (Join-Path $runDirectory "udf")
    $tempEvidenceFile = Join-Path ([System.IO.Path]::GetTempPath()) "arc-webdriver-terminal-evidence-path.txt"
    try {
        [System.IO.File]::WriteAllText($tempEvidenceFile, $terminalEvidencePath)
        [Environment]::SetEnvironmentVariable("ARC_WEBDRIVER_TERMINAL_EVIDENCE", $terminalEvidencePath, "Process")
        [Environment]::SetEnvironmentVariable("ARC_WEBDRIVER_OUTPUT_DIR", $runDirectory, "Process")
        [Environment]::SetEnvironmentVariable("ARC_DECISION_UI_TRACE", "1", "Process")
        [Environment]::SetEnvironmentVariable("ARC_DECISION_UI_TRACE_FILE", $traceFilePath, "Process")
        [Environment]::SetEnvironmentVariable("ARC_DECISION_UI_UDF_ROOT", $udfPath, "Process")
    } catch {}
    try {
        $webdriver = Invoke-CapturedCommand `
            -FilePath $npmCommand `
            -ArgumentList @("run", "test:webdriver") `
            -WorkingDirectory $uiRoot `
            -StdoutPath (Join-Path $runDirectory "webdriver.stdout.log") `
            -StderrPath (Join-Path $runDirectory "webdriver.stderr.log") `
            -Environment @{
                ARC_WEBDRIVER_BINARY = $resolvedBinary
                ARC_WEBDRIVER_OUTPUT_DIR = $runDirectory
                ARC_WEBDRIVER_TAURI_DRIVER = $tauriDriverCommand
                ARC_WEBDRIVER_TERMINAL_EVIDENCE = $terminalEvidencePath
                ARC_DECISION_UI_UDF_ROOT = $udfPath
                ARC_DECISION_UI_TRACE = "1"
                ARC_DECISION_UI_TRACE_FILE = $traceFilePath
            }
    }
    finally {
        $cleanup = Stop-NewWebDriverProcesses -BaselineProcessIds $webdriverProcessesBefore
        try {
            [Environment]::SetEnvironmentVariable("ARC_DECISION_UI_UDF_ROOT", $null, "Process")
            [Environment]::SetEnvironmentVariable("ARC_DECISION_UI_TRACE_FILE", $null, "Process")
            if (Test-Path -LiteralPath $tempEvidenceFile) {
                Remove-Item -Force -LiteralPath $tempEvidenceFile -ErrorAction SilentlyContinue
            }
            $crashLog = Join-Path ([System.IO.Path]::GetTempPath()) "arc-webdriver-fixture-crash.log"
            if (Test-Path -LiteralPath $crashLog) {
                Copy-Item -LiteralPath $crashLog -Destination (Join-Path $runDirectory "arc-webdriver-fixture-crash.log") -Force -ErrorAction SilentlyContinue
            }
        } catch {}
    }
    if ($null -eq $webdriver) {
        throw "WebDriver command did not produce a process result"
    }
    if ($null -eq $cleanup) {
        throw "WebDriver process cleanup did not produce a result"
    }
    $webdriverExitCode = $webdriver.ExitCode
    $webdriverResult = if ($webdriver.ExitCode -eq 0) { "PASS" } else { "FAIL" }
    $commands.Add([ordered]@{
        command = "npm run test:webdriver"
        working_directory = "ui/decision"
        exit_code = $webdriver.ExitCode
        result = $webdriverResult
        stdout_log = "webdriver.stdout.log"
        stderr_log = "webdriver.stderr.log"
        notes = "elapsed_ms=$($webdriver.ElapsedMs); tauri-driver=2.0.6; provider_layer=NOT-APPLICABLE"
    })
    $webdriverCleanupPassed = [bool]$cleanup.Passed
    $cleanupResult = if ($webdriverCleanupPassed) { "PASS" } else { "FAIL" }
    $cleanupExitCode = if ($webdriverCleanupPassed) { 0 } else { 1 }
    $commands.Add([ordered]@{
        command = "cleanup WebDriver processes created by this harness"
        working_directory = "."
        exit_code = $cleanupExitCode
        result = $cleanupResult
        stdout_log = $null
        stderr_log = $null
        notes = "stopped_pids=$(@($cleanup.StoppedIds) -join ','); remaining_pids=$(@($cleanup.RemainingIds) -join ','); failures=$(@($cleanup.Failures) -join ',')"
    })
}
else {
    $commands.Add([ordered]@{
        command = "npm run test:webdriver"
        working_directory = "ui/decision"
        exit_code = -1
        result = "NOT-RUN"
        stdout_log = $null
        stderr_log = $null
        notes = "fixture build did not produce the requested binary"
    })
}

$assertionsPath = Join-Path $runDirectory "webdriver.json"
$assertions = if (Test-Path -LiteralPath $assertionsPath -PathType Leaf) {
    Get-Content -Raw -LiteralPath $assertionsPath | ConvertFrom-Json
}
else {
    $null
}
$readinessPassed = $null -ne $assertions -and $assertions.result -eq "PASS" -and $assertions.readiness.dom_rendered -and $assertions.readiness.backend_accepted
$aclPassed = $null -ne $assertions -and $assertions.result -eq "PASS" -and $assertions.acl.commands.Count -eq 5 -and $assertions.terminal.attempts_before_driver_cleanup -eq 0
$readinessResult = if ($readinessPassed) { "PASS" } elseif ($webdriverExitCode -eq -1) { "NOT-RUN" } else { "FAIL" }
$aclResult = if ($aclPassed) { "PASS" } elseif ($webdriverExitCode -eq -1) { "NOT-RUN" } else { "FAIL" }
$binaryHash = if (Test-Path -LiteralPath $Binary -PathType Leaf) {
    (Get-FileHash -LiteralPath $Binary -Algorithm SHA256).Hash.ToLowerInvariant()
}
else {
    "unavailable"
}

$run = [ordered]@{
    run_id = $runId
    plan = $Plan
    revision = (git rev-parse HEAD).Trim()
    platform = [ordered]@{
        os = "Windows"
        shell = "PowerShell"
        interactive_desktop = [Environment]::UserInteractive
    }
    toolchains = [ordered]@{
        rustc = (& rustc --version).Trim()
        cargo = (& cargo --version).Trim()
        node = (& node --version).Trim()
        npm = (& npm.cmd --version).Trim()
        tauri_driver = "tauri-driver 2.0.6 (pinned; executable resolved)"
        binary_sha256 = $binaryHash
    }
    commands = @($commands)
    cases = @(
        [ordered]@{
            case_id = "DUI003-webdriver-readiness"
            finding_ids = @("DUI-003")
            layer = "Tauri WebDriver"
            platform = "Windows"
            result = $readinessResult
            artifact = if ($null -ne $assertions) { "webdriver.json" } else { $null }
        },
        [ordered]@{
            case_id = "DUI007-unauthorized-window-webdriver"
            finding_ids = @("DUI-007")
            layer = "Tauri WebDriver"
            platform = "Windows"
            result = $aclResult
            artifact = if ($null -ne $assertions) { "webdriver.json" } else { $null }
        }
    )
}
$run | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $runDirectory "run.json") -Encoding utf8

$overallResult = if ($readinessPassed -and $aclPassed -and $webdriverExitCode -eq 0 -and $webdriverCleanupPassed) { "PASS" } else { "FAIL" }
Write-Output "RUN_ID=$runId"
Write-Output "RESULT=$overallResult"
Write-Output "READINESS_RESULT=$readinessResult"
Write-Output "ACL_RESULT=$aclResult"
Write-Output "RUN_DIRECTORY=$runDirectory"

if ($overallResult -ne "PASS") {
    exit 1
}
