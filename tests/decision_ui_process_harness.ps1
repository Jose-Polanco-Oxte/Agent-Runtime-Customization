[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("allow", "deny", "escape", "x", "timeout", "parent-death", "builder-failure", "frontend-failure", "udf-no-write", "invalid-request")]
    [string]$Case,

    [Parameter(Mandatory = $false)]
    [string]$Binary = (Join-Path $PSScriptRoot "..\target\release\arc-decision-ui-host.exe"),

    [Parameter(Mandatory = $false)]
    [string]$OutputRoot = (Join-Path $PSScriptRoot "..\docs\internal\evidence\decision-ui\process-runs"),

    [Parameter(Mandatory = $false)]
    [ValidateRange(100, 86400000)]
    [int]$DecisionTimeoutMs = 5000,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1000, 86405000)]
    [int]$SupervisorTimeoutMs = 10000,

    [Parameter(Mandatory = $false)]
    [string]$ReadinessSignalPath = '',

    [Parameter(Mandatory = $false)]
    [ValidateSet("load_request", "render_or_ready")]
    [string]$FrontendFailureStage = "load_request"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not ('ArcProcessHarnessErrorReader' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

public sealed class ArcProcessHarnessErrorReader
{
    private int completed;

    public ConcurrentQueue<string> Lines { get; } = new ConcurrentQueue<string>();
    public ConcurrentQueue<string> Errors { get; } = new ConcurrentQueue<string>();
    public bool Completed => Volatile.Read(ref completed) == 1;

    public Task Start(Process process, string readinessSignalPath)
    {
        return Task.Run(() =>
        {
            try
            {
                string line;
                while ((line = process.StandardError.ReadLine()) != null)
                {
                    Lines.Enqueue(line);
                    if (!string.IsNullOrWhiteSpace(readinessSignalPath) &&
                        line.IndexOf("arc embedded decision ui trace: frontend_ready", StringComparison.Ordinal) >= 0)
                    {
                        try
                        {
                            File.WriteAllText(readinessSignalPath, DateTime.UtcNow.ToString("O"));
                        }
                        catch (UnauthorizedAccessException)
                        {
                            Errors.Enqueue("readiness_signal_access_denied");
                        }
                        catch (IOException)
                        {
                            Errors.Enqueue("readiness_signal_io_error");
                        }
                    }
                }
                Interlocked.Exchange(ref completed, 1);
            }
            catch (IOException)
            {
                Errors.Enqueue("io_error");
            }
            catch (InvalidOperationException)
            {
                Errors.Enqueue("invalid_process_state");
            }
        });
    }
}
'@
}

function Get-CaseRequest {
    param([string]$SelectedCase)

    if ($SelectedCase -eq "invalid-request") {
        return "not-json"
    }

    $requestId = "harness-$SelectedCase"
    $request = [ordered]@{
        request_id = $requestId
        title = "Arc decision UI process harness"
        message = "Harness decision for the selected process case."
        guard_id = "harness-guard"
        operation = "harness_$($SelectedCase.Replace('-', '_'))"
        scope = "the selected harness case only"
    }
    return ($request | ConvertTo-Json -Compress)
}

function Get-ExpectedDecision {
    param([string]$SelectedCase)

    switch ($SelectedCase) {
        "allow" { return "allow" }
        "deny" { return "deny" }
        "escape" { return "closed" }
        "x" { return "closed" }
        "timeout" { return "timed_out" }
        "parent-death" { return "transport_failed" }
        "builder-failure" { return "transport_failed" }
        "frontend-failure" { return "transport_failed" }
        "udf-no-write" { return "transport_failed" }
        "invalid-request" { return $null }
        default { throw "Unsupported process case: $SelectedCase" }
    }
}

function Protect-LogText {
    param(
        [string]$Text,
        [string]$SidecarPath,
        [string]$RunPath
    )

    $sanitized = $Text.Replace($SidecarPath, "<sidecar>")
    $sanitized = $sanitized.Replace($RunPath, "<run-root>")
    $sanitized = [regex]::Replace(
        $sanitized,
        '(?i)"(request_id|title|message|operation|scope)"\s*:\s*"(?:[^"\\]|\\.)*"',
        '"$1":"<redacted>"'
    )
    return $sanitized
}

function Protect-ProtocolOutput {
    param([string]$Text)

    $lines = @($Text -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 })
    if ($lines.Count -eq 0) {
        return ""
    }

    $protected = foreach ($line in $lines) {
        try {
            $response = $line | ConvertFrom-Json
            if ($null -ne $response.request_id) {
                $response.request_id = "<redacted>"
            }
            $response | ConvertTo-Json -Compress
        }
        catch [System.Text.Json.JsonException] {
            "<invalid-or-partial-json>"
        }
    }
    return (($protected -join "`n") + "`n")
}

function Receive-TaskText {
    param(
        [Parameter(Mandatory = $true)][System.Threading.Tasks.Task]$Task,
        [Parameter(Mandatory = $true)][int]$TimeoutMs
    )

    try {
        if (-not $Task.Wait([TimeSpan]::FromMilliseconds($TimeoutMs))) {
            return [pscustomobject]@{
                completed = $false
                text = ''
                reason = 'timeout'
            }
        }
    }
    catch [System.AggregateException] {
        return [pscustomobject]@{
            completed = $false
            text = ''
            reason = 'task_faulted'
        }
    }
    catch [System.InvalidOperationException] {
        return [pscustomobject]@{
            completed = $false
            text = ''
            reason = 'task_invalid_state'
        }
    }

    try {
        return [pscustomobject]@{
            completed = $true
            text = [string]$Task.GetAwaiter().GetResult()
            reason = ''
        }
    }
    catch [System.AggregateException] {
        return [pscustomobject]@{
            completed = $false
            text = ''
            reason = 'task_faulted'
        }
    }
    catch [System.Threading.Tasks.TaskCanceledException] {
        return [pscustomobject]@{
            completed = $false
            text = ''
            reason = 'task_canceled'
        }
    }
    catch [System.IO.IOException] {
        return [pscustomobject]@{
            completed = $false
            text = ''
            reason = 'io_error'
        }
    }
    catch [System.InvalidOperationException] {
        return [pscustomobject]@{
            completed = $false
            text = ''
            reason = 'task_invalid_state'
        }
    }
}

if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
    throw "Release sidecar was not found: $Binary"
}

$expectedDecision = Get-ExpectedDecision $Case
$runId = "process-$Case-$(Get-Date -Format 'yyyyMMddTHHmmssfff')"
$runDirectory = Join-Path $OutputRoot $runId
New-Item -ItemType Directory -Force -Path $runDirectory | Out-Null

$requestJson = Get-CaseRequest $Case
$readinessSignalPathResolved = ''
if (-not [string]::IsNullOrWhiteSpace($ReadinessSignalPath)) {
    $readinessSignalPathResolved = [System.IO.Path]::GetFullPath($ReadinessSignalPath)
    $readinessSignalParent = Split-Path -Parent $readinessSignalPathResolved
    if (-not [string]::IsNullOrWhiteSpace($readinessSignalParent)) {
        New-Item -ItemType Directory -Force -Path $readinessSignalParent | Out-Null
    }
}
$psi = [System.Diagnostics.ProcessStartInfo]::new()
$psi.FileName = (Resolve-Path -LiteralPath $Binary).Path
$psi.WorkingDirectory = Split-Path -Parent $psi.FileName
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.Environment["ARC_DECISION_UI_TRACE"] = "1"
$psi.Environment["ARC_DECISION_UI_TIMEOUT_MS"] = [string]$DecisionTimeoutMs

if ($Case -eq "parent-death") {
    $psi.Environment["ARC_DECISION_UI_PARENT_PID"] = "4294967295"
}

if ($Case -eq "builder-failure") {
    $invalidUdfRoot = Join-Path $runDirectory "udf-root-file"
    [System.IO.File]::WriteAllText($invalidUdfRoot, "fixture")
    $psi.Environment["ARC_DECISION_UI_UDF_ROOT"] = $invalidUdfRoot
}

if ($Case -eq "frontend-failure") {
    $psi.Environment["ARC_DECISION_UI_TEST_FRONTEND_FAILURE"] = $FrontendFailureStage
}

if ($Case -eq "udf-no-write" -and [string]::IsNullOrWhiteSpace($env:ARC_DECISION_UI_UDF_ROOT)) {
    throw "udf-no-write requires ARC_DECISION_UI_UDF_ROOT to identify the ACL-controlled fixture directory"
}

$process = [System.Diagnostics.Process]::new()
$process.StartInfo = $psi
$startedAt = [System.Diagnostics.Stopwatch]::GetTimestamp()
if (-not $process.Start()) {
    throw "The release sidecar process could not be started"
}

$process.StandardInput.Write($requestJson)
$process.StandardInput.Close()
$stdoutTask = $process.StandardOutput.ReadToEndAsync()
$stderrReader = [ArcProcessHarnessErrorReader]::new()
$stderrTask = $stderrReader.Start($process, $readinessSignalPathResolved)
$supervisorDeadline = [DateTime]::UtcNow.AddMilliseconds($SupervisorTimeoutMs)
$forcedTermination = $false
$forcedTerminationError = ''
while (-not $process.WaitForExit(100)) {
    if ([DateTime]::UtcNow -ge $supervisorDeadline) {
        $forcedTermination = $true
        try {
            $process.Kill($true)
            [void]$process.WaitForExit(5000)
        }
        catch [System.InvalidOperationException] {
            $forcedTerminationError = 'invalid_process_state'
        }
        catch [System.ComponentModel.Win32Exception] {
            $forcedTerminationError = 'win32_error'
        }
        break
    }
}

$stdoutResult = Receive-TaskText -Task $stdoutTask -TimeoutMs 5000
$stderrResult = Receive-TaskText -Task $stderrTask -TimeoutMs 5000
$stdoutRaw = [string]$stdoutResult.text
$stderrRaw = ($stderrReader.Lines.ToArray() -join "`n")
$stderrReaderError = ($stderrReader.Errors.ToArray() -join ',')
$stderrReadComplete = [bool]$stderrReader.Completed -and [bool]$stderrResult.completed
if ($stderrRaw.Length -gt 0) {
    $stderrRaw += "`n"
}
$exitCode = if ($forcedTermination) { -1 } else { $process.ExitCode }
$elapsedMs = [math]::Round((([System.Diagnostics.Stopwatch]::GetTimestamp() - $startedAt) * 1000.0) / [System.Diagnostics.Stopwatch]::Frequency, 3)
$stdout = Protect-ProtocolOutput $stdoutRaw
$stderr = Protect-LogText $stderrRaw $psi.FileName $runDirectory
$stderrReadReason = if ($stderrReadComplete) { '' } elseif ($stderrReaderError) { $stderrReaderError } else { 'timeout' }

[System.IO.File]::WriteAllText((Join-Path $runDirectory "stdout.log"), $stdout)
[System.IO.File]::WriteAllText((Join-Path $runDirectory "stderr.log"), $stderr)

$response = $null
$responseStatus = $null
$stdoutLines = @($stdoutRaw -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 })
if ($stdoutLines.Count -eq 1) {
    try {
        $response = $stdoutLines[0] | ConvertFrom-Json
        if ($response.decision.status -eq "unresolved") {
            $responseStatus = $response.decision.reason
        }
        else {
            $responseStatus = $response.decision.status
        }
    }
    catch [System.Text.Json.JsonException] {
        $responseStatus = $null
    }
}

$events = @($stderrRaw -split "`r?`n" | Where-Object { $_ -match "arc embedded decision ui trace: ([a-z_]+|window_event:[^\r\n]+)" } | ForEach-Object {
    if ($_ -match "arc embedded decision ui trace: ([^\r\n]+)") { $Matches[1] }
})

$result = "FAIL"
if ($Case -eq "invalid-request") {
    if ($exitCode -ne 0 -and $stdoutLines.Count -eq 0 -and $stdoutResult.completed -and $stderrReadComplete) {
        $result = "PASS"
    }
}
elseif (-not $forcedTermination -and $exitCode -eq 0 -and $stdoutResult.completed -and $stderrReadComplete -and $stdoutLines.Count -eq 1 -and $responseStatus -eq $expectedDecision) {
    $result = "PASS"
    if ($Case -eq "frontend-failure") {
        $requiredEvents = @(
            "frontend_failure_injected_$FrontendFailureStage",
            "frontend_failed",
            "response_emitted",
            "host_exit_requested"
        )
        $forbiddenEvents = @("frontend_ready", "window_visible", "selection", "dismissed")
        if (@($requiredEvents | Where-Object { $_ -notin $events }).Count -gt 0 -or
            @($forbiddenEvents | Where-Object { $_ -in $events }).Count -gt 0) {
            $result = "FAIL"
        }
    }
}

$binaryHash = (Get-FileHash -LiteralPath $psi.FileName -Algorithm SHA256).Hash.ToLowerInvariant()
$readinessObserved = -not [string]::IsNullOrWhiteSpace($readinessSignalPathResolved) -and
    (Test-Path -LiteralPath $readinessSignalPathResolved -PathType Leaf)
$run = [ordered]@{
    run_id = $runId
    plan = "PLAN-20260829-DECISION-UI-TAURI-SVELTE-REMEDIATION.md"
    revision = (git rev-parse HEAD).Trim()
    platform = [ordered]@{
        os = "Windows"
        shell = "PowerShell"
        interactive_desktop = $true
    }
    toolchains = [ordered]@{
        rustc = (& rustc --version).Trim()
        cargo = (& cargo --version).Trim()
        powershell = $PSVersionTable.PSVersion.ToString()
        webview2 = "recorded separately by the live run"
    }
    commands = @([ordered]@{
        command = "tests/decision_ui_process_harness.ps1 -Case $Case"
        working_directory = (Get-Location).Path
        exit_code = [int]$exitCode
        result = $result
        stdout_log = "stdout.log"
        stderr_log = "stderr.log"
        notes = "release sidecar SHA-256=$binaryHash; elapsed_ms=$elapsedMs; expected_decision=$expectedDecision; observed_decision=$responseStatus; forced_termination=$forcedTermination; forced_termination_error=$forcedTerminationError; frontend_ready_observed=$readinessObserved; frontend_failure_seam=$(if ($Case -eq 'frontend-failure') { $FrontendFailureStage } else { 'not-requested' }); stdout_read_complete=$($stdoutResult.completed); stdout_read_reason=$($stdoutResult.reason); stderr_read_complete=$stderrReadComplete; stderr_read_reason=$stderrReadReason; stderr_reader_error=$stderrReaderError"
    })
    cases = @([ordered]@{
        case_id = "DUI008-real-sidecar-$Case"
        finding_ids = @("DUI-008", "DUI-004")
        layer = "process integration"
        platform = "Windows"
        result = $result
        artifact = "run.json"
    })
}
$run | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $runDirectory "run.json") -Encoding utf8

Write-Output "RUN_ID=$runId"
Write-Output "RESULT=$result"
Write-Output "EXIT_CODE=$exitCode"
Write-Output "ELAPSED_MS=$elapsedMs"
Write-Output "RUN_DIRECTORY=$runDirectory"
Write-Output "EVENT_COUNT=$($events.Count)"
if ($events.Count -gt 0) {
    Write-Output ("EVENTS=" + ($events -join ","))
}

if ($result -ne "PASS") {
    exit 1
}
