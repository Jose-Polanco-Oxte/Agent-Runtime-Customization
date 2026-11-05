#requires -Version 7.0
[CmdletBinding()]
param(
    [string]$Binary = '',
    [string]$OutputRoot = '',
    [string]$RunId = '',
    [string]$RerunRunId = '',
    [string[]]$ProfileId,
    [string[]]$CaseType,
    [string[]]$RerunCaseId,
    [ValidateRange(100, 86400000)]
    [int]$DecisionTimeoutMs = 30000,
    [ValidateRange(1000, 86405000)]
    [int]$SupervisorTimeoutMs = 35000,
    [bool]$CaptureScreenshots = $true,
    [switch]$Build,
    [switch]$SkipX10,
    [switch]$SkipConcurrentX2,
    [switch]$RerunOnlyNotRun,
    [switch]$FreshRun,
    [switch]$PlanOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    throw 'La matriz live requiere Windows interactivo'
}
if ([Threading.Thread]::CurrentThread.ApartmentState -ne [Threading.ApartmentState]::STA) {
    throw 'Ejecutar el runner con PowerShell STA: pwsh.exe -NoProfile -STA -File tests/decision_ui_live_matrix_runner.ps1'
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class ArcLiveMatrixNative
{
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool SetWindowPos(
        IntPtr hWnd,
        IntPtr hWndInsertAfter,
        int x,
        int y,
        int width,
        int height,
        uint flags);

    [DllImport("user32.dll")]
    public static extern uint GetDpiForWindow(IntPtr hWnd);
}

public static class ArcLiveMatrixControl
{
    private static readonly object Sync = new object();
    private static ConsoleCancelEventHandler cancelHandler;
    private static int abortRequested;

    public static void InstallCancelHandler()
    {
        lock (Sync)
        {
            if (cancelHandler != null)
            {
                return;
            }
            cancelHandler = (sender, args) =>
            {
                System.Threading.Interlocked.Exchange(ref abortRequested, 1);
                args.Cancel = true;
            };
            Console.CancelKeyPress += cancelHandler;
        }
    }

    public static bool ConsumeAbortRequest()
    {
        return System.Threading.Interlocked.Exchange(ref abortRequested, 0) == 1;
    }

    public static void RemoveCancelHandler()
    {
        lock (Sync)
        {
            if (cancelHandler == null)
            {
                return;
            }
            Console.CancelKeyPress -= cancelHandler;
            cancelHandler = null;
            System.Threading.Interlocked.Exchange(ref abortRequested, 0);
        }
    }
}
'@

[ArcLiveMatrixControl]::InstallCancelHandler()

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$harnessPath = (Resolve-Path (Join-Path $PSScriptRoot 'decision_ui_process_harness.ps1')).Path
$defaultBinary = Join-Path $repoRoot 'target\release\arc-decision-ui-host.exe'
if ([string]::IsNullOrWhiteSpace($Binary)) {
    $Binary = $defaultBinary
}
$Binary = [System.IO.Path]::GetFullPath($Binary)
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $repoRoot 'docs\internal\evidence\decision-ui\live-runs'
}
$OutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)

$allDpis = @(100, 125, 150, 200)
$allMonitors = @('primary', 'secondary', 'workarea-reduced')
$allThemes = @('light', 'dark')
$allActions = @('allow', 'deny', 'escape', 'x', 'timeout')
$allFailures = @('parent-death', 'frontend-failure', 'udf-no-write')
$excludedCaseDefinitions = @()
$excludedCaseTypes = @($excludedCaseDefinitions | ForEach-Object { [string]$_.case_type })
$allCaseTypes = @($allActions + $allFailures)
$plannedCaseTypes = @($allCaseTypes + $excludedCaseTypes)

function Get-PropertyValue {
    param(
        [AllowNull()]
        [object]$InputObject,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }
    if ($InputObject -is [System.Collections.IDictionary] -and $InputObject.Contains($Name)) {
        return $InputObject[$Name]
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Protect-Note {
    param([AllowNull()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }
    $singleLine = [regex]::Replace($Text, '[\r\n\t]+', ' ').Trim()
    $singleLine = [regex]::Replace($singleLine, '(?i)(password|token|secret|credential)\s*[:=]\s*\S+', '$1=<redacted>')
    if ($singleLine.Length -gt 500) {
        return $singleLine.Substring(0, 500)
    }
    return $singleLine
}

function Get-CurrentTheme {
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'
    $settings = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
    if ($null -eq $settings) {
        return 'unknown'
    }
    $appsTheme = Get-PropertyValue -InputObject $settings -Name 'AppsUseLightTheme'
    if ($null -eq $appsTheme) {
        return 'unknown'
    }
    if ([int]$appsTheme -eq 1) {
        return 'light'
    }
    return 'dark'
}

function Convert-Rectangle {
    param([System.Drawing.Rectangle]$Rectangle)

    return [ordered]@{
        x = $Rectangle.X
        y = $Rectangle.Y
        width = $Rectangle.Width
        height = $Rectangle.Height
    }
}

function Get-ScreenSnapshot {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    return @([System.Windows.Forms.Screen]::AllScreens | ForEach-Object {
        [ordered]@{
            device_name = $_.DeviceName
            primary = [bool]$_.Primary
            bounds = Convert-Rectangle -Rectangle $_.Bounds
            working_area = Convert-Rectangle -Rectangle $_.WorkingArea
        }
    })
}

function Get-TargetScreen {
    param([Parameter(Mandatory = $true)][string]$Monitor)

    $screens = @([System.Windows.Forms.Screen]::AllScreens)
    switch ($Monitor) {
        'primary' {
            return $screens | Where-Object Primary | Select-Object -First 1
        }
        'secondary' {
            return $screens | Where-Object { -not $_.Primary } | Select-Object -First 1
        }
        'workarea-reduced' {
            return $screens | Where-Object {
                $_.WorkingArea.Width -lt $_.Bounds.Width -or $_.WorkingArea.Height -lt $_.Bounds.Height
            } | Select-Object -First 1
        }
        default {
            throw "Monitor no soportado: $Monitor"
        }
    }
}

function Test-ProfileEnvironment {
    param([Parameter(Mandatory = $true)][object]$Profile)

    $screens = @([System.Windows.Forms.Screen]::AllScreens)
    $reasons = [System.Collections.Generic.List[string]]::new()
    $theme = Get-CurrentTheme
    if ($theme -ne $Profile.theme) {
        $reasons.Add("tema actual $theme, esperado $($Profile.theme)")
    }
    switch ($Profile.monitor) {
        'primary' {
            if (@($screens | Where-Object Primary).Count -ne 1) {
                $reasons.Add('Windows no expone exactamente un monitor primario')
            }
        }
        'secondary' {
            if (@($screens | Where-Object { -not $_.Primary }).Count -lt 1) {
                $reasons.Add('no existe un segundo monitor físico observable')
            }
        }
        'workarea-reduced' {
            $reduced = @($screens | Where-Object {
                $_.WorkingArea.Width -lt $_.Bounds.Width -or $_.WorkingArea.Height -lt $_.Bounds.Height
            })
            if ($reduced.Count -eq 0) {
                $reasons.Add('no existe una WorkingArea menor que Bounds')
            }
        }
    }
    return [ordered]@{
        result = if ($reasons.Count -eq 0) { 'READY' } else { 'BLOCKED' }
        theme = $theme
        screens = Get-ScreenSnapshot
        reasons = @($reasons)
    }
}

function Get-WindowRect {
    param([Parameter(Mandatory = $true)][IntPtr]$Handle)

    $rect = [ArcLiveMatrixNative+RECT]::new()
    if (-not [ArcLiveMatrixNative]::GetWindowRect($Handle, [ref]$rect)) {
        return $null
    }
    return [ordered]@{
        left = $rect.Left
        top = $rect.Top
        right = $rect.Right
        bottom = $rect.Bottom
        width = $rect.Right - $rect.Left
        height = $rect.Bottom - $rect.Top
    }
}

function Get-WindowScreen {
    param([Parameter(Mandatory = $true)][IntPtr]$Handle)

    $rect = Get-WindowRect -Handle $Handle
    if ($null -eq $rect) {
        return $null
    }
    $center = [System.Drawing.Point]::new(
        [int](($rect.left + $rect.right) / 2),
        [int](($rect.top + $rect.bottom) / 2))
    return [System.Windows.Forms.Screen]::AllScreens |
        Where-Object { $_.Bounds.Contains($center) } |
        Select-Object -First 1
}

function Set-DecisionWindowPosition {
    param(
        [Parameter(Mandatory = $true)][IntPtr]$Handle,
        [Parameter(Mandatory = $true)][string]$Monitor,
        [int]$PairIndex = -1
    )

    $screen = Get-TargetScreen -Monitor $Monitor
    if ($null -eq $screen) {
        return $false
    }
    $rect = Get-WindowRect -Handle $Handle
    if ($null -eq $rect) {
        return $false
    }
    $width = [Math]::Max(320, $rect.width)
    $height = [Math]::Max(240, $rect.height)
    $left = $screen.WorkingArea.Left + [int](($screen.WorkingArea.Width - $width) / 2)
    $top = $screen.WorkingArea.Top + [int](($screen.WorkingArea.Height - $height) / 2)
    if ($PairIndex -eq 0) {
        $left = $screen.WorkingArea.Left + 20
    }
    elseif ($PairIndex -eq 1) {
        $left = $screen.WorkingArea.Right - $width - 20
    }
    $flags = [uint32](0x0004 -bor 0x0010 -bor 0x0040)
    return [ArcLiveMatrixNative]::SetWindowPos(
        $Handle,
        [IntPtr]::Zero,
        $left,
        $top,
        $width,
        $height,
        $flags)
}

function Save-WindowScreenshot {
    param(
        [Parameter(Mandatory = $true)][IntPtr]$Handle,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $rect = Get-WindowRect -Handle $Handle
    if ($null -eq $rect -or $rect.width -le 0 -or $rect.height -le 0) {
        return $false
    }
    $bitmap = [System.Drawing.Bitmap]::new($rect.width, $rect.height)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    try {
        $graphics.CopyFromScreen(
            $rect.left,
            $rect.top,
            0,
            0,
            [System.Drawing.Size]::new($rect.width, $rect.height),
            [System.Drawing.CopyPixelOperation]::SourceCopy)
        $bitmap.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
        return $true
    }
    catch [System.ComponentModel.Win32Exception] {
        return $false
    }
    catch [System.Runtime.InteropServices.ExternalException] {
        return $false
    }
    finally {
        $graphics.Dispose()
        $bitmap.Dispose()
    }
}

function Find-NewHostProcess {
    param([int[]]$BaselineProcessIds)

    $baseline = @($BaselineProcessIds)
    $candidate = $null
    foreach ($process in @(Get-Process -Name 'arc-decision-ui-host' -ErrorAction SilentlyContinue)) {
        if ($baseline -contains $process.Id) {
            continue
        }
        if ($null -eq $candidate) {
            $candidate = $process
            continue
        }
        try {
            if ($process.StartTime -lt $candidate.StartTime) {
                $candidate = $process
            }
        }
        catch [System.InvalidOperationException] {
            continue
        }
        catch [System.ComponentModel.Win32Exception] {
            continue
        }
    }
    return $candidate
}

function Stop-ChildTree {
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process)

    try {
        if ($Process.HasExited) {
            return $true
        }
        $Process.Kill($true)
        return $Process.WaitForExit(5000)
    }
    catch [System.InvalidOperationException] {
        return $true
    }
    catch [System.ComponentModel.Win32Exception] {
        return $false
    }
}

function Test-ProcessActive {
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process)

    try {
        return -not $Process.HasExited
    }
    catch [System.InvalidOperationException] {
        return $false
    }
}

function Stop-ControllerContexts {
    param([Parameter(Mandatory = $true)][object[]]$Contexts)

    foreach ($context in $Contexts) {
        $context.aborted = $true
        if (Test-ProcessActive -Process $context.process) {
            if (-not (Stop-ChildTree -Process $context.process)) {
                $context.stop_failed = $true
            }
        }
    }
}

function Get-ActiveContextCount {
    param([Parameter(Mandatory = $true)][object[]]$Contexts)

    $active = 0
    foreach ($context in $Contexts) {
        if (Test-ProcessActive -Process $context.process) {
            $active++
        }
    }
    return $active
}

function Get-ReadyContextCount {
    param([Parameter(Mandatory = $true)][object[]]$Contexts)

    $ready = 0
    foreach ($context in $Contexts) {
        if (Test-Path -LiteralPath $context.readiness_signal_path -PathType Leaf) {
            $ready++
        }
    }
    return $ready
}

function Request-ControllerAbort {
    param(
        [Parameter(Mandatory = $true)][hashtable]$State,
        [Parameter(Mandatory = $true)][object[]]$Contexts,
        [AllowNull()][System.Windows.Forms.Form]$Form,
        [AllowNull()][System.Windows.Forms.Timer]$Timer,
        [Parameter(Mandatory = $true)][string]$Reason
    )

    if ($State.completed) {
        return
    }
    $State.aborted = $true
    $State.problem = $true
    $State.abort_reason = $Reason
    $State.completed = $true
    try {
        Stop-ControllerContexts -Contexts $Contexts
    }
    finally {
        if ($null -ne $Timer) {
            $Timer.Stop()
        }
        if ($null -ne $Form -and -not $Form.IsDisposed) {
            $Form.Close()
        }
    }
}

function Request-ControllerSuiteStop {
    param(
        [Parameter(Mandatory = $true)][hashtable]$State,
        [Parameter(Mandatory = $true)][object[]]$Contexts,
        [AllowNull()][System.Windows.Forms.Form]$Form,
        [AllowNull()][System.Windows.Forms.Timer]$Timer,
        [Parameter(Mandatory = $true)][string]$Reason
    )

    if ($State.completed) {
        return
    }
    $State.aborted = $true
    $State.suite_stop_requested = $true
    $State.problem = $true
    $State.abort_reason = $Reason
    $State.completed = $true
    try {
        Stop-ControllerContexts -Contexts $Contexts
    }
    finally {
        if ($null -ne $Timer) {
            $Timer.Stop()
        }
        if ($null -ne $Form -and -not $Form.IsDisposed) {
            $Form.Close()
        }
    }
}

function Request-ControllerStopForScope {
    param(
        [Parameter(Mandatory = $true)][hashtable]$State,
        [Parameter(Mandatory = $true)][object[]]$Contexts,
        [AllowNull()][System.Windows.Forms.Form]$Form,
        [AllowNull()][System.Windows.Forms.Timer]$Timer,
        [Parameter(Mandatory = $true)][bool]$FullSuite,
        [Parameter(Mandatory = $true)][string]$Reason
    )

    if ($FullSuite) {
        Request-ControllerSuiteStop -State $State -Contexts $Contexts -Form $Form -Timer $Timer -Reason $Reason
        return
    }
    Request-ControllerAbort -State $State -Contexts $Contexts -Form $Form -Timer $Timer -Reason $Reason
}

function Test-SuiteStopRequested {
    param([Parameter(Mandatory = $true)][object]$ControllerState)

    return [bool](Get-PropertyValue -InputObject $ControllerState -Name 'suite_stop_requested')
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

function Get-PowerShellExecutable {
    $candidate = Join-Path $PSHOME 'pwsh.exe'
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
        return $candidate
    }
    $command = Get-Command pwsh.exe -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }
    throw 'No se encontró pwsh.exe para lanzar el harness'
}

function Invoke-LoggedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$LogPath,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory
    )

    Push-Location -LiteralPath $WorkingDirectory
    try {
        & $FilePath @Arguments 2>&1 | Tee-Object -FilePath $LogPath | Out-Host
        $exitCode = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }
    if ($exitCode -ne 0) {
        throw "Comando falló con exit code ${exitCode}: $FilePath $($Arguments -join ' ')"
    }
}

function Invoke-PreflightBuild {
    param([Parameter(Mandatory = $true)][string]$PreflightRoot)

    New-Item -ItemType Directory -Force -Path $PreflightRoot | Out-Null
    $npm = (Get-Command npm.cmd -ErrorAction Stop).Source
    $cargo = (Get-Command cargo.exe -ErrorAction Stop).Source
    Invoke-LoggedCommand -FilePath $npm -Arguments @('ci', '--ignore-scripts') -LogPath (Join-Path $PreflightRoot 'npm-ci.log') -WorkingDirectory (Join-Path $repoRoot 'ui\decision')
    Invoke-LoggedCommand -FilePath $npm -Arguments @('run', 'test:webdriver:types') -LogPath (Join-Path $PreflightRoot 'webdriver-types.log') -WorkingDirectory (Join-Path $repoRoot 'ui\decision')
    Invoke-LoggedCommand -FilePath $npm -Arguments @('test', '--', '--run') -LogPath (Join-Path $PreflightRoot 'frontend-tests.log') -WorkingDirectory (Join-Path $repoRoot 'ui\decision')
    Invoke-LoggedCommand -FilePath $npm -Arguments @('run', 'build') -LogPath (Join-Path $PreflightRoot 'frontend-build.log') -WorkingDirectory (Join-Path $repoRoot 'ui\decision')
    Invoke-LoggedCommand -FilePath $cargo -Arguments @('build', '--locked', '--release', '--manifest-path', 'ui/decision/src-tauri/Cargo.toml', '--features', 'custom-protocol,frontend-failure-seam', '--bin', 'arc-decision-ui-host') -LogPath (Join-Path $PreflightRoot 'cargo-release.log') -WorkingDirectory $repoRoot
}

function Get-HarnessInstruction {
    param([Parameter(Mandatory = $true)][string]$SelectedCase)

    switch ($SelectedCase) {
        'allow' { return 'Observa foco inicial, Tab/Shift+Tab y Enter; al final pulsa Allow una sola vez.' }
        'deny' { return 'Pulsa Deny una sola vez para rechazar el scope mostrado.' }
        'escape' { return 'No pulses botones. Pulsa Escape y confirma cierre sin Deny.' }
        'x' { return 'No pulses botones. Cierra por X o Alt+F4 y confirma Closed.' }
        'timeout' { return 'No pulses mouse ni teclado. Espera la terminal TimedOut.' }
        'parent-death' { return 'No selecciones una decisión. El runner espera TransportFailed.' }
        'frontend-failure' { return 'No pulses ni interactúes. El seam test-only debe producir frontend_failed y TransportFailed sin mostrar la ventana.' }
        'udf-no-write' { return 'No selecciones una decisión. El runner espera el fallo tipado del UDF.' }
        default { throw "Caso no soportado: $SelectedCase" }
    }
}

function Get-PhaseLabel {
    param(
        [Parameter(Mandatory = $true)][string]$Suite,
        [Parameter(Mandatory = $true)][string]$Iteration
    )

    switch ($Suite) {
        'base' { return 'Base' }
        'x10' { return "Sucesiva x10 | iteración $Iteration" }
        'concurrent-x2' { return 'Concurrente x2' }
        default { return "$Suite | iteración $Iteration" }
    }
}

function Start-HarnessContext {
    param(
        [Parameter(Mandatory = $true)][string]$SelectedCase,
        [Parameter(Mandatory = $true)][object]$Profile,
        [Parameter(Mandatory = $true)][string]$CaseRoot,
        [Parameter(Mandatory = $true)][string]$UdfRoot,
        [Parameter(Mandatory = $true)][string]$BinaryPath,
        [Parameter(Mandatory = $true)][int]$DecisionTimeout,
        [Parameter(Mandatory = $true)][int]$SupervisorTimeout,
        [int[]]$BaselineProcessIds,
        [int]$PairIndex = -1
    )

    New-Item -ItemType Directory -Force -Path $CaseRoot | Out-Null
    $caseUdfRoot = $UdfRoot
    $aclApplied = $false
    $aclApplyExit = $null
    $aclRestoreExit = $null
    if ($SelectedCase -eq 'udf-no-write') {
        $caseUdfRoot = Join-Path $CaseRoot 'udf-blocked'
        New-Item -ItemType Directory -Force -Path $caseUdfRoot | Out-Null
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $aclLog = Join-Path $CaseRoot 'icacls-apply.log'
        & icacls.exe $caseUdfRoot /inheritance:r /grant:r "${identity}:(OI)(CI)(RX)" /deny "${identity}:(OI)(CI)(M)" 2>&1 |
            Tee-Object -FilePath $aclLog | Out-Null
        $aclApplyExit = $LASTEXITCODE
        if ($aclApplyExit -ne 0) {
            throw "No se pudo aplicar ACL de solo lectura al UDF: $caseUdfRoot"
        }
        $aclApplied = $true
    }

    try {
        $powershell = Get-PowerShellExecutable
        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = $powershell
        $psi.WorkingDirectory = $repoRoot
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $readinessSignalPath = Join-Path $CaseRoot 'frontend-ready.signal'
        $arguments = @(
            '-NoLogo',
            '-NoProfile',
            '-File',
            $harnessPath,
            '-Case',
            $SelectedCase,
            '-Binary',
            $BinaryPath,
            '-OutputRoot',
            $CaseRoot,
            '-DecisionTimeoutMs',
            [string]$DecisionTimeout,
            '-SupervisorTimeoutMs',
            [string]$SupervisorTimeout,
            '-ReadinessSignalPath',
            $readinessSignalPath
        )
        foreach ($argument in $arguments) {
            $psi.ArgumentList.Add($argument)
        }
        $psi.Environment['ARC_DECISION_UI_TRACE'] = '1'
        $psi.Environment['ARC_DECISION_UI_TIMEOUT_MS'] = [string]$DecisionTimeout
        $psi.Environment['ARC_DECISION_UI_UDF_ROOT'] = $caseUdfRoot
        if ($SelectedCase -eq 'frontend-failure') {
            $psi.Environment['ARC_DECISION_UI_TEST_FRONTEND_FAILURE'] = 'load_request'
        }

        $process = [System.Diagnostics.Process]::new()
        $process.StartInfo = $psi
        $startedUtc = Get-Date -AsUTC
        if (-not $process.Start()) {
            throw "No se pudo iniciar el harness para $SelectedCase"
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        return [pscustomobject]@{
        case_type = $SelectedCase
        profile = $Profile
        case_root = $CaseRoot
        case_udf_root = $caseUdfRoot
        acl_applied = $aclApplied
        acl_apply_exit = $aclApplyExit
        acl_restore_exit = $aclRestoreExit
        process = $process
        stdout_task = $stdoutTask
        stderr_task = $stderrTask
        readiness_signal_path = $readinessSignalPath
        started_utc = $startedUtc
        finished_utc = $null
        baseline_process_ids = @($BaselineProcessIds)
        host_process_id = $null
        window_handle = [IntPtr]::Zero
        window_observed_utc = $null
        window_placed = $false
        actual_dpi = $null
        actual_monitor = $null
        actual_theme = Get-CurrentTheme
        screenshot_path = $null
        screenshot_captured = $false
        pair_index = $PairIndex
        aborted = $false
        stop_failed = $false
        stdout_read_complete = $false
        stderr_read_complete = $false
        stdout_read_reason = ''
        stderr_read_reason = ''
        operator_problem = $false
        operator_note = ''
        }
    }
    catch {
        if ($aclApplied) {
            $restoreLog = Join-Path $CaseRoot 'icacls-restore-start-failure.log'
            & icacls.exe $caseUdfRoot /reset /T /C 2>&1 |
                Tee-Object -FilePath $restoreLog | Out-Null
        }
        throw
    }
}

function Show-CaseController {
    param(
        [Parameter(Mandatory = $true)][object[]]$Contexts,
        [Parameter(Mandatory = $true)][int]$DecisionTimeout,
        [Parameter(Mandatory = $true)][int]$SupervisorTimeout,
        [Parameter(Mandatory = $true)][bool]$FullSuite,
        [string]$Suite = 'base',
        [string]$Iteration = 'base',
        [string]$RunModeLabel = 'NUEVO RUN DESDE CERO',
        [int]$SelectedCaseNumber = 0,
        [int]$SelectedCaseTotal = 0,
        [int]$SuiteTotalCases = 0,
        [int]$SuitePreservedPassCases = 0,
        [int]$SuitePreservedOtherCases = 0
    )

    $state = @{
        problem = $false
        aborted = $false
        suite_stop_requested = $false
        completed = $false
        checklist_confirmed = $false
        note = ''
        abort_reason = ''
    }
    if ([ArcLiveMatrixControl]::ConsumeAbortRequest()) {
        Request-ControllerSuiteStop -State $state -Contexts $Contexts -Form $null -Timer $null -Reason 'operator_ctrl_c'
        return [pscustomobject]$state
    }
    $requiresChecklist = @($Contexts | Where-Object { $_.case_type -eq 'allow' }).Count -gt 0
    $phaseLabel = Get-PhaseLabel -Suite $Suite -Iteration $Iteration
    $form = [System.Windows.Forms.Form]::new()
    $form.Text = "Arc — Live Matrix Runner — $phaseLabel"
    $form.StartPosition = 'Manual'
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedToolWindow
    $form.ClientSize = [System.Drawing.Size]::new(620, 500)
    $form.MinimizeBox = $false
    $form.MaximizeBox = $false
    $form.ShowInTaskbar = $true
    $form.KeyPreview = $true

    $title = [System.Windows.Forms.Label]::new()
    $title.Text = 'Ejecución live en curso'
    $title.Font = [System.Drawing.Font]::new('Segoe UI', 14, [System.Drawing.FontStyle]::Bold)
    $title.Location = [System.Drawing.Point]::new(18, 16)
    $title.AutoSize = $true
    $form.Controls.Add($title)

    $details = [System.Windows.Forms.Label]::new()
    $details.Location = [System.Drawing.Point]::new(18, 55)
    $details.Size = [System.Drawing.Size]::new(584, 145)
    $details.Font = [System.Drawing.Font]::new('Segoe UI', 10)
    $suiteProgress = if ($SuiteTotalCases -gt 0) {
        "Suite acumulada: $SuiteTotalCases casos | PASS conservados: $SuitePreservedPassCases | otros previos no seleccionados: $SuitePreservedOtherCases | esta ejecución: $SelectedCaseTotal"
    }
    else {
        "Casos de esta ejecución: $SelectedCaseTotal"
    }
    $selectedProgress = if ($SelectedCaseNumber -gt 0 -and $SelectedCaseTotal -gt 0) {
        "Progreso de esta ejecución: caso $SelectedCaseNumber de $SelectedCaseTotal"
    }
    else {
        ''
    }
    $contextDetails = (($Contexts | ForEach-Object {
        "Fase: $phaseLabel`nPerfil: $($_.profile.profile_id) | DPI $($_.profile.dpi_percent)% | monitor $($_.profile.monitor) | tema $($_.profile.theme)`nCaso: $($_.case_type)`nAcción: $(Get-HarnessInstruction -SelectedCase $_.case_type)"
    }) -join "`n`n")
    $detailLines = @(
        "Modo: $RunModeLabel"
        $suiteProgress
        $selectedProgress
        $contextDetails
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    $details.Text = $detailLines -join "`n"
    $form.Controls.Add($details)

    $status = [System.Windows.Forms.Label]::new()
    $status.Location = [System.Drawing.Point]::new(18, 190)
    $status.Size = [System.Drawing.Size]::new(584, 32)
    $automatedFrontendFailure = @($Contexts | Where-Object { $_.case_type -eq 'frontend-failure' }).Count -eq $Contexts.Count
    $status.Text = if ($automatedFrontendFailure) {
        "$phaseLabel | Caso $SelectedCaseNumber/$SelectedCaseTotal | Ejecutando seam frontend-failure; no debe aparecer la ventana."
    }
    else {
        "$phaseLabel | Caso $SelectedCaseNumber/$SelectedCaseTotal | Iniciando proceso y esperando la ventana de decisión."
    }
    $form.Controls.Add($status)

    $progress = [System.Windows.Forms.ProgressBar]::new()
    $progress.Location = [System.Drawing.Point]::new(18, 230)
    $progress.Size = [System.Drawing.Size]::new(584, 22)
    $progress.Minimum = 0
    $progress.Maximum = 100
    $form.Controls.Add($progress)

    $checklist = [System.Windows.Forms.CheckBox]::new()
    $checklist.Text = 'Checklist de foco/teclado ejecutado'
    $checklist.Location = [System.Drawing.Point]::new(18, 260)
    $checklist.AutoSize = $true
    $checklist.Visible = $requiresChecklist
    $form.Controls.Add($checklist)

    $noteLabel = [System.Windows.Forms.Label]::new()
    $noteLabel.Text = 'Nota opcional: escribir solo una incidencia sanitizada.'
    $noteLabel.Location = [System.Drawing.Point]::new(18, 290)
    $noteLabel.AutoSize = $true
    $form.Controls.Add($noteLabel)

    $note = [System.Windows.Forms.TextBox]::new()
    $note.Multiline = $true
    $note.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
    $note.Location = [System.Drawing.Point]::new(18, 316)
    $note.Size = [System.Drawing.Size]::new(584, 70)
    $form.Controls.Add($note)

    $problemButton = [System.Windows.Forms.Button]::new()
    $problemButton.Text = 'Marcar problema visual'
    $problemButton.Location = [System.Drawing.Point]::new(18, 405)
    $problemButton.Size = [System.Drawing.Size]::new(180, 34)
    $problemButton.Add_Click({
        try {
            $state.problem = $true
            $status.Text = 'Problema visual marcado; el caso quedará FAIL.'
            $problemButton.Enabled = $false
        }
        catch [System.Management.Automation.PipelineStoppedException] {
            $state.problem = $true
            $state.abort_reason = 'controller_pipeline_stopped'
        }
    })
    $form.Controls.Add($problemButton)

    $skipButton = [System.Windows.Forms.Button]::new()
    $skipButton.Text = 'Saltar caso'
    $skipButton.Location = if ($FullSuite) {
        [System.Drawing.Point]::new(208, 405)
    }
    else {
        [System.Drawing.Point]::new(422, 405)
    }
    $skipButton.Size = [System.Drawing.Size]::new(180, 34)
    $skipButton.Add_Click({
        try {
            Request-ControllerAbort -State $state -Contexts $Contexts -Form $form -Timer $timer -Reason 'operator_skip'
        }
        catch [System.Management.Automation.PipelineStoppedException] {
            Request-ControllerAbort -State $state -Contexts $Contexts -Form $null -Timer $timer -Reason 'controller_pipeline_stopped'
        }
        catch [System.InvalidOperationException] {
            Request-ControllerAbort -State $state -Contexts $Contexts -Form $null -Timer $timer -Reason 'controller_invalid_operation'
        }
    })
    $form.Controls.Add($skipButton)

    $stopSuiteButton = [System.Windows.Forms.Button]::new()
    $stopSuiteButton.Text = 'Detener suite'
    $stopSuiteButton.Location = [System.Drawing.Point]::new(408, 405)
    $stopSuiteButton.Size = [System.Drawing.Size]::new(194, 34)
    $stopSuiteButton.Visible = $FullSuite
    $stopSuiteButton.Add_Click({
        try {
            Request-ControllerSuiteStop -State $state -Contexts $Contexts -Form $form -Timer $timer -Reason 'operator_suite_stop'
        }
        catch [System.Management.Automation.PipelineStoppedException] {
            Request-ControllerSuiteStop -State $state -Contexts $Contexts -Form $null -Timer $timer -Reason 'controller_pipeline_stopped'
        }
        catch [System.InvalidOperationException] {
            Request-ControllerSuiteStop -State $state -Contexts $Contexts -Form $null -Timer $timer -Reason 'controller_invalid_operation'
        }
    })
    $form.Controls.Add($stopSuiteButton)

    $timer = [System.Windows.Forms.Timer]::new()
    $timer.Interval = 100
    $timer.Add_Tick({
        try {
            if ($state.completed) {
                return
            }
            if ([ArcLiveMatrixControl]::ConsumeAbortRequest()) {
                Request-ControllerSuiteStop -State $state -Contexts $Contexts -Form $form -Timer $timer -Reason 'operator_ctrl_c'
                return
            }
            $now = Get-Date -AsUTC
            $firstStarted = $Contexts[0].started_utc
            foreach ($context in $Contexts) {
                if ($context.started_utc -lt $firstStarted) {
                    $firstStarted = $context.started_utc
                }
            }
            $elapsed = ($now - $firstStarted).TotalMilliseconds
            $progress.Value = [Math]::Min(100, [Math]::Max(0, [int](($elapsed * 100) / $DecisionTimeout)))
            foreach ($context in $Contexts) {
                if ($null -eq $context.host_process_id) {
                    $baseline = [System.Collections.Generic.List[int]]::new()
                    foreach ($baselineId in $context.baseline_process_ids) {
                        $baseline.Add([int]$baselineId)
                    }
                    foreach ($otherContext in $Contexts) {
                        if ($null -ne $otherContext.host_process_id) {
                            $baseline.Add([int]$otherContext.host_process_id)
                        }
                    }
                    $hostProcessCandidate = Find-NewHostProcess -BaselineProcessIds @($baseline)
                    if ($null -ne $hostProcessCandidate) {
                        $context.host_process_id = $hostProcessCandidate.Id
                    }
                }
                if ($null -ne $context.host_process_id -and $context.window_handle -eq [IntPtr]::Zero) {
                    $hostProcess = Get-Process -Id $context.host_process_id -ErrorAction SilentlyContinue
                    if ($null -ne $hostProcess -and $hostProcess.MainWindowHandle -ne [IntPtr]::Zero) {
                        $context.window_handle = $hostProcess.MainWindowHandle
                        $context.window_observed_utc = Get-Date -AsUTC
                    }
                }
                if ($context.window_handle -ne [IntPtr]::Zero -and -not $context.window_placed) {
                    $placed = Set-DecisionWindowPosition -Handle $context.window_handle -Monitor $context.profile.monitor -PairIndex $context.pair_index
                    $context.window_placed = $placed
                }
                if ($context.window_handle -ne [IntPtr]::Zero) {
                    $screen = Get-WindowScreen -Handle $context.window_handle
                    if ($null -ne $screen) {
                        $context.actual_monitor = $screen.DeviceName
                    }
                    $context.actual_dpi = [ArcLiveMatrixNative]::GetDpiForWindow($context.window_handle)
                    if ($CaptureScreenshots -and -not $context.screenshot_captured) {
                        $screenshot = Join-Path $context.case_root 'window-observed.png'
                        if (Save-WindowScreenshot -Handle $context.window_handle -Path $screenshot) {
                            $context.screenshot_path = 'window-observed.png'
                            $context.screenshot_captured = $true
                        }
                    }
                }
            }

            $activeCount = Get-ActiveContextCount -Contexts $Contexts
            $readyCount = Get-ReadyContextCount -Contexts $Contexts
            $windowCount = 0
            foreach ($context in $Contexts) {
                if ($context.window_handle -ne [IntPtr]::Zero) {
                    $windowCount++
                }
            }
            $status.Text = "$phaseLabel | Procesos activos: $activeCount. Ventanas observadas: $windowCount. frontend_ready: $readyCount/$($Contexts.Count)."
            if ($automatedFrontendFailure -and $activeCount -gt 0) {
                $status.Text = "$phaseLabel | Ejecutando seam frontend-failure; esperando frontend_failed y cierre del host."
            }
            elseif ($readyCount -lt $Contexts.Count -and $activeCount -gt 0) {
                $status.Text = "$phaseLabel | Esperando frontend_ready: $readyCount/$($Contexts.Count). No interactuar todavía con la ventana."
            }
            if ($activeCount -eq 0) {
                $state.checklist_confirmed = -not $requiresChecklist -or $checklist.Checked
                if (-not $state.checklist_confirmed) {
                    $state.problem = $true
                }
                $state.completed = $true
                $timer.Stop()
                $form.Close()
                return
            }
            if ($elapsed -ge $SupervisorTimeout) {
                $state.aborted = $true
                $state.problem = $true
                $state.abort_reason = 'supervisor_timeout'
                $state.completed = $true
                Stop-ControllerContexts -Contexts $Contexts
                $timer.Stop()
                $form.Close()
                return
            }
            if ($elapsed -ge $DecisionTimeout) {
                $status.Text = "$phaseLabel | Venció el timeout de decisión; esperando cleanup hasta $SupervisorTimeout ms. Usa Saltar caso o Detener suite si no termina."
            }
        }
        catch [System.Management.Automation.PipelineStoppedException] {
            Request-ControllerStopForScope -State $state -Contexts $Contexts -Form $form -Timer $timer -FullSuite $FullSuite -Reason 'controller_pipeline_stopped'
        }
        catch [System.InvalidOperationException] {
            Request-ControllerStopForScope -State $state -Contexts $Contexts -Form $form -Timer $timer -FullSuite $FullSuite -Reason 'controller_invalid_operation'
        }
    })

    $form.Add_FormClosing({
        try {
            if (-not $state.completed -and -not $state.aborted) {
                $closeReason = if ($FullSuite) { 'operator_suite_window_close' } else { 'controller_window_closed' }
                Request-ControllerStopForScope -State $state -Contexts $Contexts -Form $null -Timer $timer -FullSuite $FullSuite -Reason $closeReason
            }
        }
        catch [System.Management.Automation.PipelineStoppedException] {
            Request-ControllerStopForScope -State $state -Contexts $Contexts -Form $null -Timer $timer -FullSuite $FullSuite -Reason 'controller_pipeline_stopped'
        }
        catch [System.InvalidOperationException] {
            Request-ControllerStopForScope -State $state -Contexts $Contexts -Form $null -Timer $timer -FullSuite $FullSuite -Reason 'controller_invalid_operation'
        }
    })

    $form.Add_KeyDown({
        try {
            if ($_.Control -and $_.Shift -and $_.KeyCode -eq [System.Windows.Forms.Keys]::Q) {
                if ($FullSuite) {
                    $stopSuiteButton.PerformClick()
                }
                else {
                    $skipButton.PerformClick()
                }
            }
        }
        catch [System.Management.Automation.PipelineStoppedException] {
            Request-ControllerStopForScope -State $state -Contexts $Contexts -Form $null -Timer $timer -FullSuite $FullSuite -Reason 'controller_pipeline_stopped'
        }
        catch [System.InvalidOperationException] {
            Request-ControllerStopForScope -State $state -Contexts $Contexts -Form $null -Timer $timer -FullSuite $FullSuite -Reason 'controller_invalid_operation'
        }
    })

    $workingArea = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
    $form.Location = [System.Drawing.Point]::new($workingArea.Left + 20, $workingArea.Top + 20)
    try {
        $timer.Start()
        [void]$form.ShowDialog()
    }
    catch [System.Management.Automation.PipelineStoppedException] {
        Request-ControllerStopForScope -State $state -Contexts $Contexts -Form $null -Timer $timer -FullSuite $FullSuite -Reason 'controller_pipeline_stopped'
    }
    catch [System.InvalidOperationException] {
        Request-ControllerStopForScope -State $state -Contexts $Contexts -Form $null -Timer $timer -FullSuite $FullSuite -Reason 'controller_invalid_operation'
    }
    finally {
        $timer.Stop()
        $state.note = Protect-Note -Text $note.Text
        $form.Dispose()
    }
    return [pscustomobject]$state
}

function Get-ProcessRunDirectory {
    param([Parameter(Mandatory = $true)][string]$CaseRoot)

    return Get-ChildItem -LiteralPath $CaseRoot -Directory -Filter 'process-*' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
}

function Get-TraceEvents {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return @()
    }
    return @(Get-Content -LiteralPath $Path | ForEach-Object {
        if ($_ -match 'arc embedded decision ui trace: ([^\r\n]+)') {
            $Matches[1]
        }
    })
}

function Get-HarnessRunData {
    param([Parameter(Mandatory = $true)][string]$CaseRoot)

    $processDirectory = Get-ProcessRunDirectory -CaseRoot $CaseRoot
    if ($null -eq $processDirectory) {
        return [pscustomobject]@{ directory = $null; data = $null; result = $null; events = @() }
    }
    $runJson = Join-Path $processDirectory.FullName 'run.json'
    if (-not (Test-Path -LiteralPath $runJson -PathType Leaf)) {
        return [pscustomobject]@{ directory = $processDirectory; data = $null; result = $null; events = @() }
    }
    $data = Get-Content -Raw -LiteralPath $runJson | ConvertFrom-Json
    $commands = @((Get-PropertyValue -InputObject $data -Name 'commands'))
    $result = if ($commands.Count -eq 1) { Get-PropertyValue -InputObject $commands[0] -Name 'result' } else { $null }
    $stderrPath = Join-Path $processDirectory.FullName 'stderr.log'
    return [pscustomobject]@{
        directory = $processDirectory
        data = $data
        result = $result
        events = Get-TraceEvents -Path $stderrPath
    }
}

function Measure-Cleanup {
    param(
        [Parameter(Mandatory = $true)][object[]]$Contexts,
        [Parameter(Mandatory = $true)][string]$UdfRoot,
        [Parameter(Mandatory = $true)][int]$TimeoutMs
    )

    $started = Get-Date -AsUTC
    $deadline = $started.AddMilliseconds($TimeoutMs)
    $remaining = @()
    do {
        $remaining = @($Contexts | Where-Object {
            $null -ne $_.host_process_id -and $null -ne (Get-Process -Id $_.host_process_id -ErrorAction SilentlyContinue)
        })
        if ($remaining.Count -eq 0) {
            break
        }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date -AsUTC) -lt $deadline)
    $finished = Get-Date -AsUTC
    $markers = @(Get-ChildItem -LiteralPath $UdfRoot -Filter '.arc-decision-ui.active' -File -Force -Recurse -ErrorAction SilentlyContinue)
    return [ordered]@{
        cleanup_started_utc = $started.ToString('o')
        cleanup_finished_utc = $finished.ToString('o')
        cleanup_elapsed_ms = [int](($finished - $started).TotalMilliseconds)
        host_processes_after = $remaining.Count
        webdriver_processes_after = 'NOT-APPLICABLE'
        windows_after = $remaining.Count
        udf_active_markers_after = $markers.Count
        recent_markers_retained_by_policy = $true
        result = if ($remaining.Count -eq 0) { 'PASS' } else { 'FAIL' }
    }
}

function Complete-HarnessContext {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$ControllerState,
        [Parameter(Mandatory = $true)][int]$CleanupTimeoutMs,
        [Parameter(Mandatory = $true)][string]$UdfRoot,
        [string]$Suite = 'base',
        [string]$CaseIdOverride = '',
        [string]$Iteration = 'base'
    )

    if (Test-ProcessActive -Process $Context.process) {
        if (-not (Stop-ChildTree -Process $Context.process)) {
            $Context.stop_failed = $true
        }
        $Context.aborted = $true
    }
    $Context.finished_utc = Get-Date -AsUTC
    $stdoutResult = Receive-TaskText -Task $Context.stdout_task -TimeoutMs 5000
    $stderrResult = Receive-TaskText -Task $Context.stderr_task -TimeoutMs 5000
    $Context.stdout_read_complete = [bool]$stdoutResult.completed
    $Context.stderr_read_complete = [bool]$stderrResult.completed
    $Context.stdout_read_reason = [string]$stdoutResult.reason
    $Context.stderr_read_reason = [string]$stderrResult.reason
    $stdout = [string]$stdoutResult.text
    $stderr = [string]$stderrResult.text
    Set-Content -Encoding utf8 -LiteralPath (Join-Path $Context.case_root 'runner-harness-stdout.log') -Value $stdout
    Set-Content -Encoding utf8 -LiteralPath (Join-Path $Context.case_root 'runner-harness-stderr.log') -Value $stderr

    if ($Context.acl_applied) {
        $aclLog = Join-Path $Context.case_root 'icacls-restore.log'
        & icacls.exe $Context.case_udf_root /reset /T /C 2>&1 |
            Tee-Object -FilePath $aclLog | Out-Null
        $Context.acl_restore_exit = $LASTEXITCODE
        [ordered]@{
            acl_restore_exit = $Context.acl_restore_exit
            restored_utc = (Get-Date -AsUTC).ToString('o')
        } | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $Context.case_root 'acl-restore.json')
    }

    $harness = Get-HarnessRunData -CaseRoot $Context.case_root
    $cleanup = Measure-Cleanup -Contexts @($Context) -UdfRoot $UdfRoot -TimeoutMs $CleanupTimeoutMs
    $expected = switch ($Context.case_type) {
        'allow' { 'allow' }
        'deny' { 'deny' }
        'escape' { 'closed' }
        'x' { 'closed' }
        'timeout' { 'timed_out' }
        'parent-death' { 'transport_failed' }
        'frontend-failure' { 'transport_failed' }
        'udf-no-write' { 'transport_failed' }
        default { $null }
    }
    $harnessPass = $harness.result -eq 'PASS'
    $visualPass = -not [bool]$ControllerState.problem
    $checklistRequired = $Context.case_type -eq 'allow'
    $checklistPass = -not $checklistRequired -or [bool]$ControllerState.checklist_confirmed
    $readinessExpected = $Context.case_type -in @('allow', 'deny', 'escape', 'x', 'timeout')
    $readinessObserved = Test-Path -LiteralPath $Context.readiness_signal_path -PathType Leaf
    $readinessPass = -not $readinessExpected -or $readinessObserved
    $profilePass = $true
    $targetScreen = Get-TargetScreen -Monitor $Context.profile.monitor
    if ($null -eq $targetScreen) {
        $profilePass = $false
    }
    if ($null -ne $Context.actual_dpi -and [int]$Context.actual_dpi -gt 0) {
        $expectedDpi = [int]$Context.profile.dpi_percent
        $actualPercent = [int][Math]::Round(([int]$Context.actual_dpi * 100.0) / 96.0)
        if ($actualPercent -ne $expectedDpi) {
            $profilePass = $false
        }
    }
    if ($null -ne $Context.actual_monitor -and $null -ne $targetScreen -and $Context.actual_monitor -ne $targetScreen.DeviceName) {
        $profilePass = $false
    }
    $failureReasons = [System.Collections.Generic.List[string]]::new()
    if ($Context.aborted) { $failureReasons.Add('runner_aborted') }
    if ($Context.stop_failed) { $failureReasons.Add('runner_stop_timeout') }
    if (-not $Context.stdout_read_complete) { $failureReasons.Add("runner_stdout_read_$($Context.stdout_read_reason)") }
    if (-not $Context.stderr_read_complete) { $failureReasons.Add("runner_stderr_read_$($Context.stderr_read_reason)") }
    if (-not $harnessPass) { $failureReasons.Add("harness_result_$($harness.result)") }
    if (-not $visualPass) { $failureReasons.Add('operator_marked_visual_problem') }
    if (-not $checklistPass) { $failureReasons.Add('focus_keyboard_checklist_not_confirmed') }
    if (-not $profilePass) { $failureReasons.Add('profile_observation_mismatch') }
    if (-not $readinessPass) { $failureReasons.Add('frontend_ready_signal_missing') }
    if ($cleanup.result -ne 'PASS') { $failureReasons.Add('cleanup_failed') }
    if ($null -ne $Context.acl_restore_exit -and $Context.acl_restore_exit -ne 0) { $failureReasons.Add('udf_acl_restore_failed') }
    $status = if ($failureReasons.Count -eq 0) { 'PASS' } else { 'FAIL' }
    $harnessExitCode = -1
    if (-not (Test-ProcessActive -Process $Context.process)) {
        try {
            $harnessExitCode = [int]$Context.process.ExitCode
        }
        catch [System.InvalidOperationException] {
            $harnessExitCode = -1
        }
    }
    $processDirectory = if ($null -ne $harness.directory) { $harness.directory.FullName } else { $null }
    $reportCaseId = if ([string]::IsNullOrWhiteSpace($CaseIdOverride)) { "$($Context.profile.profile_id)-$($Context.case_type)" } else { $CaseIdOverride }
    $report = [ordered]@{
        schema_version = 1
        case_id = $reportCaseId
        suite = $Suite
        iteration = $Iteration
        profile_id = $Context.profile.profile_id
        dpi_percent = [int]$Context.profile.dpi_percent
        monitor = $Context.profile.monitor
        theme = $Context.profile.theme
        actual_theme = $Context.actual_theme
        actual_monitor = $Context.actual_monitor
        actual_dpi = $Context.actual_dpi
        case_type = $Context.case_type
        instruction = Get-HarnessInstruction -SelectedCase $Context.case_type
        expected = $expected
        harness_result = $harness.result
        harness_exit_code = $harnessExitCode
        runner_status = $status
        started_utc = $Context.started_utc.ToString('o')
        finished_utc = $Context.finished_utc.ToString('o')
        window_observed_utc = if ($null -ne $Context.window_observed_utc) { $Context.window_observed_utc.ToString('o') } else { $null }
        frontend_ready_signal = 'frontend-ready.signal'
        frontend_ready_observed = $readinessObserved
        focus_keyboard_checklist_required = $checklistRequired
        focus_keyboard_checklist_confirmed = [bool]$ControllerState.checklist_confirmed
        binary_sha256 = $script:binaryHash
        revision = $script:revision
        events = @($harness.events)
        process_run_directory = $processDirectory
        screenshot = $Context.screenshot_path
        operator_problem = [bool]$ControllerState.problem
        operator_note = Protect-Note -Text $ControllerState.note
        abort_reason = Get-PropertyValue -InputObject $ControllerState -Name 'abort_reason'
        stdout_read_complete = [bool]$Context.stdout_read_complete
        stderr_read_complete = [bool]$Context.stderr_read_complete
        stdout_read_reason = $Context.stdout_read_reason
        stderr_read_reason = $Context.stderr_read_reason
        cleanup = $cleanup
        reason = ($failureReasons -join '; ')
        evidence_negative = if ($status -eq 'PASS') { '' } else { 'Revisar harness, observación visual, perfil o cleanup.' }
    }
    $report | ConvertTo-Json -Depth 10 | Set-Content -Encoding utf8 (Join-Path $Context.case_root 'case.json')
    $markdown = @"
# $($report.case_id)

- Estado: $status
- Suite/iteración: $($report.suite) / $($report.iteration)
- Perfil: $($report.profile_id)
- DPI esperado/observado: $($report.dpi_percent)% / $($report.actual_dpi)
- Monitor esperado/observado: $($report.monitor) / $($report.actual_monitor)
- Tema esperado/observado: $($report.theme) / $($report.actual_theme)
- Tipo: $($report.case_type)
- Inicio UTC: $($report.started_utc)
- Fin UTC: $($report.finished_utc)
- Resultado harness: $($report.harness_result)
- Exit code: $($report.harness_exit_code)
- Eventos: $(([string[]]$report.events) -join ', ')
- Screenshot: $($report.screenshot)
- Proceso harness: $($report.process_run_directory)
- Nota operador: $($report.operator_note)
- Cleanup: $($cleanup.result), $($cleanup.cleanup_elapsed_ms) ms, host restantes $($cleanup.host_processes_after)
- Evidencia negativa: $($report.evidence_negative)
"@
    Set-Content -Encoding utf8 -LiteralPath (Join-Path $Context.case_root 'case.md') -Value $markdown
    return $report
}

function Write-NotRunCase {
    param(
        [Parameter(Mandatory = $true)][object]$Profile,
        [Parameter(Mandatory = $true)][string]$SelectedCase,
        [Parameter(Mandatory = $true)][string]$CaseRoot,
        [Parameter(Mandatory = $true)][string]$Reason,
        [ValidateSet('NOT-RUN', 'BLOCKED', 'FAIL')]
        [string]$StatusValue = 'NOT-RUN'
    )

    New-Item -ItemType Directory -Force -Path $CaseRoot | Out-Null
    $caseId = "$($Profile.profile_id)-$SelectedCase"
    $report = [ordered]@{
        schema_version = 1
        case_id = $caseId
        suite = 'base'
        profile_id = $Profile.profile_id
        dpi_percent = [int]$Profile.dpi_percent
        monitor = $Profile.monitor
        theme = $Profile.theme
        case_type = $SelectedCase
        runner_status = $StatusValue
        reason = $Reason
        revision = $script:revision
        binary_sha256 = $script:binaryHash
    }
    $report | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 (Join-Path $CaseRoot 'case.json')
    @"
# $caseId

- Estado: $StatusValue
- Perfil: $($Profile.profile_id)
- Tipo: $SelectedCase
- Razón: $Reason
- Revisión: $script:revision
- SHA-256: $script:binaryHash
"@ | Set-Content -Encoding utf8 (Join-Path $CaseRoot 'case.md')
    return $report
}

function Write-AbortedCase {
    param(
        [Parameter(Mandatory = $true)][object]$CaseRow,
        [AllowNull()][object]$Profile,
        [Parameter(Mandatory = $true)][string]$Reason
    )

    $caseRoot = Split-Path -Parent $CaseRow.case_file
    New-Item -ItemType Directory -Force -Path $caseRoot | Out-Null
    $dpi = if ($null -ne $Profile) { [int]$Profile.dpi_percent } else { $null }
    $monitor = if ($null -ne $Profile) { [string]$Profile.monitor } else { $null }
    $theme = if ($null -ne $Profile) { [string]$Profile.theme } else { $null }
    $report = [ordered]@{
        schema_version = 1
        case_id = [string]$CaseRow.case_id
        suite = [string]$CaseRow.suite
        iteration = [string]$CaseRow.iteration
        profile_id = [string]$CaseRow.profile_id
        dpi_percent = $dpi
        monitor = $monitor
        theme = $theme
        case_type = [string]$CaseRow.case_type
        runner_status = 'NOT-RUN'
        reason = $Reason
        revision = $script:revision
        binary_sha256 = $script:binaryHash
        source_run_id = [string](Get-PropertyValue -InputObject $CaseRow -Name 'source_run_id')
        source_case_id = [string](Get-PropertyValue -InputObject $CaseRow -Name 'source_case_id')
        source_status = [string](Get-PropertyValue -InputObject $CaseRow -Name 'source_status')
        source_reason = [string](Get-PropertyValue -InputObject $CaseRow -Name 'source_reason')
        evidence_negative = 'La suite fue detenida antes de iniciar este caso.'
    }
    $report | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 (Join-Path $caseRoot 'case.json')
    @"
# $($report.case_id)

- Estado: NOT-RUN
- Suite/iteración: $($report.suite) / $($report.iteration)
- Perfil: $($report.profile_id)
- Tipo: $($report.case_type)
- Razón: $Reason
- Revisión: $script:revision
- SHA-256: $script:binaryHash
- Run de origen: $($report.source_run_id)
- Caso de origen: $($report.source_case_id)
- Estado de origen: $($report.source_status)
"@ | Set-Content -Encoding utf8 (Join-Path $caseRoot 'case.md')
    return [pscustomobject]$report
}

function Write-RunnerFailureCase {
    param(
        [Parameter(Mandatory = $true)][object]$Profile,
        [Parameter(Mandatory = $true)][string]$CaseId,
        [Parameter(Mandatory = $true)][string]$Suite,
        [Parameter(Mandatory = $true)][string]$CaseType,
        [Parameter(Mandatory = $true)][string]$CaseRoot,
        [Parameter(Mandatory = $true)][string]$Reason,
        [string]$Iteration = 'base'
    )

    New-Item -ItemType Directory -Force -Path $CaseRoot | Out-Null
    $report = [ordered]@{
        schema_version = 1
        case_id = $CaseId
        suite = $Suite
        iteration = $Iteration
        profile_id = [string]$Profile.profile_id
        dpi_percent = [int]$Profile.dpi_percent
        monitor = [string]$Profile.monitor
        theme = [string]$Profile.theme
        case_type = $CaseType
        runner_status = 'FAIL'
        reason = $Reason
        revision = $script:revision
        binary_sha256 = $script:binaryHash
        evidence_negative = 'La ejecución inició pero no alcanzó un resultado válido.'
    }
    $report | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 (Join-Path $CaseRoot 'case.json')
    @"
# $CaseId

- Estado: FAIL
- Suite/iteración: $Suite / $Iteration
- Perfil: $($Profile.profile_id)
- Tipo: $CaseType
- Razón: $Reason
- Revisión: $script:revision
- SHA-256: $script:binaryHash
- Evidencia negativa: $($report.evidence_negative)
"@ | Set-Content -Encoding utf8 (Join-Path $CaseRoot 'case.md')
    return [pscustomobject]$report
}

function Get-CaseResultReason {
    param(
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][string]$PassReason,
        [Parameter(Mandatory = $true)][string]$FailureReason
    )

    if ($Status -eq 'PASS') {
        return $PassReason
    }
    return $FailureReason
}

function Get-StatusCounts {
    param(
        [AllowNull()][object[]]$Rows,
        [Parameter(Mandatory = $true)][string]$StatusProperty
    )

    $counts = [ordered]@{
        PASS = 0
        FAIL = 0
        NOT_RUN = 0
        BLOCKED = 0
    }
    foreach ($row in @($Rows)) {
        if ($null -eq $row) {
            continue
        }
        $status = [string](Get-PropertyValue -InputObject $row -Name $StatusProperty)
        switch ($status) {
            'PASS' { $counts.PASS++ }
            'FAIL' { $counts.FAIL++ }
            'NOT-RUN' { $counts.NOT_RUN++ }
            'BLOCKED' { $counts.BLOCKED++ }
            default { throw "Estado no soportado en $StatusProperty`: '$status'" }
        }
    }
    return [pscustomobject]$counts
}

function Get-RerunSourceSelection {
    param(
        [Parameter(Mandatory = $true)][string]$SourceRunRoot,
        [AllowNull()][AllowEmptyCollection()][string[]]$RequestedProfileIds = @(),
        [AllowNull()][AllowEmptyCollection()][string[]]$RequestedCaseTypes = @(),
        [AllowNull()][string[]]$RequestedCaseIds,
        [Parameter(Mandatory = $true)][bool]$OnlyNotRun
    )

    $metadataPath = Join-Path $SourceRunRoot 'metadata.json'
    $casesPath = Join-Path $SourceRunRoot 'cases.csv'
    if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) {
        throw "No existe metadata.json en el run de origen: $SourceRunRoot"
    }
    if (-not (Test-Path -LiteralPath $casesPath -PathType Leaf)) {
        throw "No existe cases.csv en el run de origen: $SourceRunRoot"
    }

    $sourceMetadata = Get-Content -Raw -LiteralPath $metadataPath | ConvertFrom-Json
    $rawSourceRows = @(Import-Csv -LiteralPath $casesPath)
    if ($rawSourceRows.Count -eq 0) {
        throw "cases.csv no contiene casos: $casesPath"
    }
    $excludedSourceRows = @($rawSourceRows | Where-Object { $_.case_type -in $excludedCaseTypes })
    $sourceRows = @($rawSourceRows | Where-Object { $_.case_type -notin $excludedCaseTypes })
    if ($sourceRows.Count -eq 0) {
        throw "cases.csv solo contiene casos sin implementación ejecutable: $($excludedCaseTypes -join ', ')"
    }
    $allSourceRows = @($sourceRows)

    $requestedIds = @($RequestedCaseIds | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($requestedIds.Count -gt 0) {
        $knownIds = @($sourceRows | ForEach-Object { [string]$_.case_id })
        $unknownIds = @($requestedIds | Where-Object { $_ -notin $knownIds })
        if ($unknownIds.Count -gt 0) {
            throw "RerunCaseId no existe en el run de origen: $($unknownIds -join ', ')"
        }
        $selectedRows = @($sourceRows | Where-Object { $_.case_id -in $requestedIds })
        $selectionMode = 'case-id'
    }
    elseif ($OnlyNotRun) {
        $selectedRows = @($sourceRows | Where-Object { $_.status -eq 'NOT-RUN' })
        $selectionMode = 'not-run'
    }
    else {
        $selectedRows = @($sourceRows | Where-Object { $_.status -ne 'PASS' })
        $selectionMode = 'non-pass'
    }

    $requestedProfiles = @($RequestedProfileIds | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $requestedTypes = @($RequestedCaseTypes | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($requestedProfiles.Count -gt 0) {
        $selectedRows = @($selectedRows | Where-Object { $_.profile_id -in $requestedProfiles })
    }
    if ($requestedTypes.Count -gt 0) {
        $selectedRows = @($selectedRows | Where-Object { $_.case_type -in $requestedTypes })
    }
    if ($selectedRows.Count -eq 0) {
        throw "El run de origen no tiene casos elegibles para el reintento ($selectionMode)."
    }

    $selectedIds = @{}
    foreach ($row in $selectedRows) {
        $selectedIds[[string]$row.case_id] = $true
    }
    $selectedConcurrent = @($selectedRows | Where-Object { $_.suite -eq 'concurrent-x2' })
    foreach ($row in $selectedConcurrent) {
        $pairRows = @($sourceRows | Where-Object {
            $_.suite -eq 'concurrent-x2' -and $_.profile_id -eq $row.profile_id
        })
        foreach ($pairRow in $pairRows) {
            $selectedIds[[string]$pairRow.case_id] = $true
        }
    }
    $selectedRows = @($sourceRows | Where-Object { $selectedIds.ContainsKey([string]$_.case_id) })

    return [pscustomobject]@{
        source_root = $SourceRunRoot
        metadata = $sourceMetadata
        all_rows = $allSourceRows
        excluded_rows = $excludedSourceRows
        rows = $selectedRows
        selection_mode = $selectionMode
    }
}

function New-CaseRow {
    param(
        [Parameter(Mandatory = $true)][string]$CaseId,
        [Parameter(Mandatory = $true)][string]$Suite,
        [Parameter(Mandatory = $true)][string]$ProfileIdValue,
        [Parameter(Mandatory = $true)][string]$CaseTypeValue,
        [Parameter(Mandatory = $true)][string]$CaseRootValue,
        [string]$Iteration = 'base',
        [string]$SourceRunId = '',
        [string]$SourceCaseId = '',
        [string]$SourceStatus = '',
        [string]$SourceReason = ''
    )
    return [pscustomobject]@{
        case_id = $CaseId
        suite = $Suite
        profile_id = $ProfileIdValue
        case_type = $CaseTypeValue
        iteration = $Iteration
        status = 'NOT-RUN'
        reason = 'Pendiente de ejecución'
        case_file = (Join-Path $CaseRootValue 'case.md')
        source_run_id = $SourceRunId
        source_case_id = $SourceCaseId
        source_status = $SourceStatus
        source_reason = $SourceReason
    }
}

function Update-CaseRow {
    param(
        [Parameter(Mandatory = $true)][string]$CasesCsv,
        [Parameter(Mandatory = $true)][string]$CaseIdValue,
        [Parameter(Mandatory = $true)][string]$StatusValue,
        [Parameter(Mandatory = $true)][string]$ReasonValue
    )
    $rows = @(Import-Csv -LiteralPath $CasesCsv)
    $row = $rows | Where-Object { $_.case_id -eq $CaseIdValue }
    if ($null -eq $row) {
        throw "No existe case_id en cases.csv: $CaseIdValue"
    }
    $row.status = $StatusValue
    $row.reason = $ReasonValue
    $rows | Export-Csv -NoTypeInformation -Encoding utf8 -LiteralPath $CasesCsv
}

function Set-RunMetadata {
    param(
        [Parameter(Mandatory = $true)][string]$MetadataPath,
        [Parameter(Mandatory = $true)][string]$StatusValue,
        [Parameter(Mandatory = $true)][object[]]$Reports,
        [Parameter(Mandatory = $true)][object]$SuiteCounts,
        [Parameter(Mandatory = $true)][int]$SuiteTotalCases,
        [Parameter(Mandatory = $true)][string]$SuiteResult,
        [Parameter(Mandatory = $true)][int]$SelectedCases,
        [Parameter(Mandatory = $true)][int]$PreservedPassCases,
        [Parameter(Mandatory = $true)][int]$PreservedOtherCases
    )
    $counts = @{}
    foreach ($countStatus in @('PASS', 'FAIL', 'NOT-RUN', 'BLOCKED')) {
        $counts[$countStatus] = @($Reports | Where-Object { $_.runner_status -eq $countStatus }).Count
    }
    $metadata = Get-Content -Raw -LiteralPath $MetadataPath | ConvertFrom-Json
    $metadata.finished_utc = (Get-Date -AsUTC).ToString('o')
    $metadata.status = $StatusValue
    $metadata.counts = $counts
    $metadata | Add-Member -MemberType NoteProperty -Name executed_cases -Value $Reports.Count -Force
    $metadata | Add-Member -MemberType NoteProperty -Name selected_cases -Value $SelectedCases -Force
    $metadata | Add-Member -MemberType NoteProperty -Name suite_total_cases -Value $SuiteTotalCases -Force
    $metadata | Add-Member -MemberType NoteProperty -Name suite_result -Value $SuiteResult -Force
    $metadata | Add-Member -MemberType NoteProperty -Name suite_counts -Value $SuiteCounts -Force
    $metadata | Add-Member -MemberType NoteProperty -Name suite_preserved_pass_cases -Value $PreservedPassCases -Force
    $metadata | Add-Member -MemberType NoteProperty -Name suite_preserved_other_cases -Value $PreservedOtherCases -Force
    $metadata | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 $MetadataPath
}

if ($PlanOnly) {
    $selectedProfilesForPlan = foreach ($dpi in $allDpis) {
        foreach ($monitor in $allMonitors) {
            foreach ($theme in $allThemes) {
                [pscustomobject]@{
                    profile_id = "dpi${dpi}-${monitor}-${theme}"
                    dpi_percent = $dpi
                    monitor = $monitor
                    theme = $theme
                }
            }
        }
    }
    $selectedCaseTypesForPlan = $allCaseTypes
    $excludedBaseCasesForPlan = $selectedProfilesForPlan.Count * $excludedCaseTypes.Count
    [pscustomobject]@{
        profiles = $selectedProfilesForPlan.Count
        base_cases = $selectedProfilesForPlan.Count * $selectedCaseTypesForPlan.Count
        planned_base_cases = $selectedProfilesForPlan.Count * $plannedCaseTypes.Count
        excluded_base_cases = $excludedBaseCasesForPlan
        excluded_case_types = @($excludedCaseDefinitions)
        x10_cases = $allActions.Count * 10
        concurrent_x2_pairs = 1
        decision_timeout_ms = $DecisionTimeoutMs
        supervisor_timeout_ms = $SupervisorTimeoutMs
    } | ConvertTo-Json -Depth 5
    exit 0
}

if (-not (Test-Path -LiteralPath $harnessPath -PathType Leaf)) {
    throw "No existe el harness: $harnessPath"
}
if ($Build) {
    $temporaryPreflight = Join-Path $OutputRoot 'runner-preflight'
    Invoke-PreflightBuild -PreflightRoot $temporaryPreflight
}
if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
    throw "No existe el binario release: $Binary. Ejecutar el runner con -Build o preparar el release antes de iniciar la matriz."
}

$profiles = foreach ($dpi in $allDpis) {
    foreach ($monitor in $allMonitors) {
        foreach ($theme in $allThemes) {
            [pscustomobject]@{
                profile_id = "dpi${dpi}-${monitor}-${theme}"
                dpi_percent = $dpi
                monitor = $monitor
                theme = $theme
            }
        }
    }
}
if ($null -ne $ProfileId -and $ProfileId.Count -gt 0) {
    $unknownProfiles = @($ProfileId | Where-Object { $_ -notin @($profiles.profile_id) })
    if ($unknownProfiles.Count -gt 0) {
        throw "ProfileId no soportado: $($unknownProfiles -join ', ')"
    }
    $profiles = @($profiles | Where-Object { $_.profile_id -in $ProfileId })
}
$selectedCaseTypes = if ($null -eq $CaseType -or $CaseType.Count -eq 0) { $allCaseTypes } else { @($CaseType) }
$unknownCases = @($selectedCaseTypes | Where-Object { $_ -notin $allCaseTypes })
if ($unknownCases.Count -gt 0) {
    $excludedRequestedCases = @($unknownCases | Where-Object { $_ -in $excludedCaseTypes })
    if ($excludedRequestedCases.Count -gt 0) {
        throw "CaseType declarado pero no ejecutable: $($excludedRequestedCases -join ', '). No existe un seam test-only de load/ready; el runner no crea una ficha NOT-RUN falsa."
    }
    throw "CaseType no soportado: $($unknownCases -join ', ')"
}

$requestedRerunCaseIds = @($RerunCaseId | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
if ($RerunOnlyNotRun -and [string]::IsNullOrWhiteSpace($RerunRunId)) {
    throw '-RerunOnlyNotRun requiere -RerunRunId'
}
if ($requestedRerunCaseIds.Count -gt 0 -and [string]::IsNullOrWhiteSpace($RerunRunId)) {
    throw '-RerunCaseId requiere -RerunRunId'
}

$isRerunMode = -not [string]::IsNullOrWhiteSpace($RerunRunId)
if ($FreshRun -and $isRerunMode) {
    throw '-FreshRun y -RerunRunId son excluyentes: elige un run nuevo o una reanudación.'
}
if ($FreshRun -and ($RerunOnlyNotRun -or $requestedRerunCaseIds.Count -gt 0)) {
    throw '-FreshRun no puede combinarse con filtros de reanudación.'
}
$rerunSelection = $null
if ($isRerunMode) {
    if ($RerunRunId -notmatch '^[A-Za-z0-9_-]+$') {
        throw 'RerunRunId solo puede contener letras, números, guion y guion bajo'
    }
    $sourceRunRoot = Join-Path $OutputRoot $RerunRunId
    $rerunSelection = Get-RerunSourceSelection `
        -SourceRunRoot $sourceRunRoot `
        -RequestedProfileIds @($ProfileId) `
        -RequestedCaseTypes @($CaseType) `
        -RequestedCaseIds $requestedRerunCaseIds `
        -OnlyNotRun $RerunOnlyNotRun
    $sourceRows = @($rerunSelection.rows)
    if ($SkipX10) {
        $sourceRows = @($sourceRows | Where-Object { $_.suite -ne 'x10' })
    }
    if ($SkipConcurrentX2) {
        $sourceRows = @($sourceRows | Where-Object { $_.suite -ne 'concurrent-x2' })
    }
    if ($sourceRows.Count -eq 0) {
        throw 'Los filtros de suite no dejaron casos para reintentar.'
    }
    $rerunSelection.rows = $sourceRows
    $rerunProfileIds = @($sourceRows | ForEach-Object { [string]$_.profile_id } | Select-Object -Unique)
    $profiles = @($profiles | Where-Object { $_.profile_id -in $rerunProfileIds })
    if ($profiles.Count -eq 0) {
        throw 'Los casos del run de origen no coinciden con los perfiles solicitados.'
    }
}
$isFullSuite = if ($isRerunMode) {
    $requestedRerunCaseIds.Count -ne 1
}
else {
    ($null -eq $ProfileId -or $ProfileId.Count -eq 0) -and
        ($null -eq $CaseType -or $CaseType.Count -eq 0)
}

if ([string]::IsNullOrWhiteSpace($RunId)) {
    $RunId = "live-matrix-$(Get-Date -Format 'yyyyMMddTHHmmssfff')"
}
if ($RunId -notmatch '^[A-Za-z0-9_-]+$') {
    throw 'RunId solo puede contener letras, números, guion y guion bajo'
}
$runRoot = Join-Path $OutputRoot $RunId
if (Test-Path -LiteralPath $runRoot) {
    throw "El run ya existe; no se reutiliza ni se reinicia sobre el mismo directorio: $runRoot. Usa otro -RunId."
}
New-Item -ItemType Directory -Force -Path $runRoot | Out-Null
$udfRoot = Join-Path $runRoot 'udf'
$casesRoot = Join-Path $runRoot 'cases'
New-Item -ItemType Directory -Force -Path $udfRoot | Out-Null
New-Item -ItemType Directory -Force -Path $casesRoot | Out-Null

$script:revision = (git -C $repoRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($script:revision)) {
    throw 'No se pudo obtener la revisión Git'
}
$script:binaryHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Binary).Hash.ToLowerInvariant()
$runMode = if ($isRerunMode) {
    if ($requestedRerunCaseIds.Count -gt 0) { 'rerun-case-id' } elseif ($RerunOnlyNotRun) { 'rerun-not-run' } else { 'rerun-non-pass' }
}
else {
    'fresh'
}
$runModeLabel = if ($isRerunMode) {
    if ($requestedRerunCaseIds.Count -gt 0) { 'REPETICIÓN POR ID' }
    elseif ($RerunOnlyNotRun) { 'REANUDACIÓN: SOLO NOT-RUN' }
    else { 'REANUDACIÓN: CASOS NO PASS' }
}
elseif ($FreshRun) {
    'NUEVO RUN DESDE CERO (EXPLÍCITO)'
}
else {
    'NUEVO RUN DESDE CERO'
}
$sourceRevision = ''
$sourceBinaryHash = ''
$sourceSelectionMode = ''
$sourceSelectedCases = 0
if ($isRerunMode) {
    $sourceRevision = [string](Get-PropertyValue -InputObject $rerunSelection.metadata -Name 'revision')
    $sourceBinaryHash = [string](Get-PropertyValue -InputObject $rerunSelection.metadata -Name 'binary_sha256')
    $sourceSelectionMode = [string]$rerunSelection.selection_mode
    $sourceSelectedCases = @($rerunSelection.rows).Count
}
$excludedCaseCount = if ($isRerunMode) {
    @($rerunSelection.excluded_rows).Count
}
else {
    $profiles.Count * $excludedCaseTypes.Count
}
$coverageStatus = if ($excludedCaseCount -eq 0) { 'COMPLETE' } else { 'INCOMPLETE' }
$metadataPath = Join-Path $runRoot 'metadata.json'
$metadata = [ordered]@{
    schema_version = 1
    run_id = $RunId
    started_utc = (Get-Date -AsUTC).ToString('o')
    operator = [Environment]::UserName
    revision = $script:revision
    binary_relative = [System.IO.Path]::GetRelativePath($repoRoot, $Binary).Replace('\', '/')
    binary_sha256 = $script:binaryHash
    finished_utc = 'PENDING'
    decision_timeout_ms = $DecisionTimeoutMs
    supervisor_timeout_ms = $SupervisorTimeoutMs
    execution_scope = if ($isFullSuite) { 'full-suite' } else { 'filtered-run' }
    run_mode = $runMode
    run_mode_label = $runModeLabel
    fresh_run = -not $isRerunMode
    rerun_source_run_id = if ($isRerunMode) { $RerunRunId } else { '' }
    rerun_source_revision = $sourceRevision
    rerun_source_binary_sha256 = $sourceBinaryHash
    rerun_source_selection_mode = $sourceSelectionMode
    rerun_selected_cases = $sourceSelectedCases
    rerun_binary_hash_changed = $isRerunMode -and ($sourceBinaryHash -ne $script:binaryHash)
    capture_screenshots = $CaptureScreenshots
    executable_case_types = @($allCaseTypes)
    excluded_case_types = @($excludedCaseDefinitions)
    excluded_case_count = $excludedCaseCount
    coverage_status = $coverageStatus
    counts = [ordered]@{}
    status = 'IN-PROGRESS'
}
$metadata | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 $metadataPath
Get-ScreenSnapshot | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 (Join-Path $runRoot 'screens-before.json')
Get-CurrentTheme | Set-Content -Encoding utf8 (Join-Path $runRoot 'theme-before.txt')

$profileCsv = Join-Path $runRoot 'profiles.csv'
$profiles | ForEach-Object {
    [pscustomobject]@{
        profile_id = $_.profile_id
        dpi_percent = $_.dpi_percent
        monitor = $_.monitor
        theme = $_.theme
        status = 'NOT-RUN'
        reason = 'Pendiente de ejecución'
    }
} | Export-Csv -NoTypeInformation -Encoding utf8 $profileCsv

$script:suiteStopRequested = $false
$script:suiteStopReason = ''
$caseRows = [System.Collections.Generic.List[object]]::new()
$profilesById = @{}
foreach ($profile in $profiles) {
    $profilesById[[string]$profile.profile_id] = $profile
}

if ($isRerunMode) {
    $caseIdsAdded = @{}
    foreach ($sourceRow in @($rerunSelection.rows)) {
        $sourceCaseId = [string]$sourceRow.case_id
        if ($caseIdsAdded.ContainsKey($sourceCaseId)) {
            throw "El run de origen contiene case_id duplicado: $sourceCaseId"
        }
        $caseIdsAdded[$sourceCaseId] = $true

        $sourceProfileId = [string]$sourceRow.profile_id
        if (-not $profilesById.ContainsKey($sourceProfileId)) {
            throw "No se pudo reconstruir el perfil del caso de origen: $sourceCaseId"
        }
        $sourceSuite = [string]$sourceRow.suite
        $sourceCaseType = [string]$sourceRow.case_type
        $sourceIteration = [string]$sourceRow.iteration
        $newCaseRoot = switch ($sourceSuite) {
            'base' {
                Join-Path $casesRoot $sourceCaseId
            }
            'x10' {
                Join-Path $runRoot "repeat-x10\$sourceProfileId-$sourceCaseType\$sourceIteration"
            }
            'concurrent-x2' {
                Join-Path $runRoot "concurrent-x2\$sourceCaseType"
            }
            default {
                throw "Suite no soportada en el run de origen ($sourceCaseId): $sourceSuite"
            }
        }
        $caseRows.Add((New-CaseRow `
                -CaseId $sourceCaseId `
                -Suite $sourceSuite `
                -ProfileIdValue $sourceProfileId `
                -CaseTypeValue $sourceCaseType `
                -CaseRootValue $newCaseRoot `
                -Iteration $sourceIteration `
                -SourceRunId $RerunRunId `
                -SourceCaseId $sourceCaseId `
                -SourceStatus ([string]$sourceRow.status) `
                -SourceReason ([string]$sourceRow.reason)))
    }
}
else {
    foreach ($profile in $profiles) {
        foreach ($selectedCase in $selectedCaseTypes) {
            $caseRows.Add((New-CaseRow -CaseId "$($profile.profile_id)-$selectedCase" -Suite 'base' -ProfileIdValue $profile.profile_id -CaseTypeValue $selectedCase -CaseRootValue (Join-Path $casesRoot "$($profile.profile_id)-$selectedCase")))
        }
    }
}
$selectedCaseLookup = @{}
foreach ($caseRow in $caseRows) {
    $selectedCaseLookup[[string]$caseRow.case_id] = $true
}
$repeatActions = @(
    if ($isRerunMode) {
        @($caseRows | Where-Object { $_.suite -eq 'x10' } | ForEach-Object { [string]$_.case_type } | Select-Object -Unique)
    }
    else {
        @($selectedCaseTypes | Where-Object { $_ -in $allActions })
    }
)
$repeatProfile = $profiles | Select-Object -First 1
if (-not $isRerunMode -and -not $script:suiteStopRequested -and -not $SkipX10 -and $repeatActions.Count -gt 0 -and $null -ne $repeatProfile) {
    foreach ($repeatAction in $repeatActions) {
        for ($iteration = 1; $iteration -le 10; $iteration++) {
            if ([ArcLiveMatrixControl]::ConsumeAbortRequest()) {
                $script:suiteStopRequested = $true
                $script:suiteStopReason = 'operator_ctrl_c'
                break
            }
            $iterationId = '{0:D2}' -f $iteration
            $repeatCaseId = "$($repeatProfile.profile_id)-x10-$repeatAction-$iterationId"
            $repeatCaseRoot = Join-Path $runRoot "repeat-x10\$($repeatProfile.profile_id)-$repeatAction\$iterationId"
            $caseRows.Add((New-CaseRow -CaseId $repeatCaseId -Suite 'x10' -ProfileIdValue $repeatProfile.profile_id -CaseTypeValue $repeatAction -CaseRootValue $repeatCaseRoot -Iteration $iterationId))
        }
    }
}
if (-not $isRerunMode -and -not $SkipConcurrentX2 -and $null -ne $repeatProfile) {
    $caseRows.Add((New-CaseRow -CaseId "$($repeatProfile.profile_id)-concurrent-x2-allow" -Suite 'concurrent-x2' -ProfileIdValue $repeatProfile.profile_id -CaseTypeValue 'allow' -CaseRootValue (Join-Path $runRoot "concurrent-x2\allow")))
    $caseRows.Add((New-CaseRow -CaseId "$($repeatProfile.profile_id)-concurrent-x2-deny" -Suite 'concurrent-x2' -ProfileIdValue $repeatProfile.profile_id -CaseTypeValue 'deny' -CaseRootValue (Join-Path $runRoot "concurrent-x2\deny")))
}
$casesCsv = Join-Path $runRoot 'cases.csv'
$caseRows | Export-Csv -NoTypeInformation -Encoding utf8 $casesCsv

$caseOrdinalById = @{}
$caseOrdinal = 0
foreach ($caseRow in $caseRows) {
    $caseOrdinal++
    $caseOrdinalById[[string]$caseRow.case_id] = $caseOrdinal
}
$selectedCaseTotal = [int]$caseRows.Count
$suiteTotalCases = [int]$caseRows.Count
$suitePreservedPassCases = 0
$suitePreservedOtherCases = 0
if ($isRerunMode) {
    $sourceCaseIdsSelected = @{}
    foreach ($caseRow in $caseRows) {
        $sourceCaseIdsSelected[[string]$caseRow.source_case_id] = $true
    }
    $sourceCatalogRows = @($rerunSelection.all_rows)
    $preservedSourceRows = @($sourceCatalogRows | Where-Object {
        -not $sourceCaseIdsSelected.ContainsKey([string]$_.case_id)
    })
    $suiteTotalCases = [int]$sourceCatalogRows.Count
    $suitePreservedPassCases = @($preservedSourceRows | Where-Object { $_.status -eq 'PASS' }).Count
    $suitePreservedOtherCases = @($preservedSourceRows | Where-Object { $_.status -ne 'PASS' }).Count
}

$reports = [System.Collections.Generic.List[object]]::new()
foreach ($profile in $profiles) {
    if ($script:suiteStopRequested) {
        break
    }
    if ([ArcLiveMatrixControl]::ConsumeAbortRequest()) {
        $script:suiteStopRequested = $true
        $script:suiteStopReason = 'operator_ctrl_c'
        break
    }
    $environment = Test-ProfileEnvironment -Profile $profile
    $environment | ConvertTo-Json -Depth 10 | Set-Content -Encoding utf8 (Join-Path $runRoot "profile-$($profile.profile_id)-environment.json")
    foreach ($selectedCase in $selectedCaseTypes) {
        if ([ArcLiveMatrixControl]::ConsumeAbortRequest()) {
            $script:suiteStopRequested = $true
            $script:suiteStopReason = 'operator_ctrl_c'
            break
        }
        $caseId = "$($profile.profile_id)-$selectedCase"
        if (-not $selectedCaseLookup.ContainsKey($caseId)) {
            continue
        }
        $caseRoot = Join-Path $casesRoot $caseId
        if ($environment.result -ne 'READY') {
            $report = Write-NotRunCase -Profile $profile -SelectedCase $selectedCase -CaseRoot $caseRoot -Reason (($environment.reasons) -join '; ') -StatusValue 'BLOCKED'
            $reports.Add($report)
            Update-CaseRow -CasesCsv $casesCsv -CaseIdValue $caseId -StatusValue 'BLOCKED' -ReasonValue (($environment.reasons) -join '; ')
            continue
        }
        $baseline = @(Get-Process -Name 'arc-decision-ui-host','tauri-driver','msedgedriver' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
        $context = $null
        $controller = $null
        try {
            $context = Start-HarnessContext -SelectedCase $selectedCase -Profile $profile -CaseRoot $caseRoot -UdfRoot $udfRoot -BinaryPath $Binary -DecisionTimeout $DecisionTimeoutMs -SupervisorTimeout $SupervisorTimeoutMs -BaselineProcessIds $baseline
            $controller = Show-CaseController -Contexts @($context) -DecisionTimeout $DecisionTimeoutMs -SupervisorTimeout $SupervisorTimeoutMs -FullSuite $isFullSuite -Suite 'base' -Iteration 'base' -RunModeLabel $runModeLabel -SelectedCaseNumber $caseOrdinalById[$caseId] -SelectedCaseTotal $selectedCaseTotal -SuiteTotalCases $suiteTotalCases -SuitePreservedPassCases $suitePreservedPassCases -SuitePreservedOtherCases $suitePreservedOtherCases
            if (Test-SuiteStopRequested -ControllerState $controller) {
                $script:suiteStopRequested = $true
                $script:suiteStopReason = if ([string]::IsNullOrWhiteSpace($controller.abort_reason)) { 'operator_suite_stop' } else { $controller.abort_reason }
            }
            $report = Complete-HarnessContext -Context $context -ControllerState $controller -CleanupTimeoutMs 10000 -UdfRoot $udfRoot
            $reports.Add($report)
            $caseReason = Get-CaseResultReason -Status $report.runner_status -PassReason 'Evidencia y cleanup revisados' -FailureReason 'Fallo de harness, visual, perfil o cleanup'
            Update-CaseRow -CasesCsv $casesCsv -CaseIdValue $caseId -StatusValue $report.runner_status -ReasonValue $caseReason
        }
        catch {
            if ($null -ne $context) {
                Stop-ControllerContexts -Contexts @($context)
            }
            $failureReason = Protect-Note -Text $_.Exception.Message
            if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) {
                $script:suiteStopRequested = $true
                $script:suiteStopReason = 'controller_pipeline_stopped'
            }
            $report = Write-NotRunCase -Profile $profile -SelectedCase $selectedCase -CaseRoot $caseRoot -Reason "runner_error: $failureReason" -StatusValue 'FAIL'
            $reports.Add($report)
            Update-CaseRow -CasesCsv $casesCsv -CaseIdValue $caseId -StatusValue 'FAIL' -ReasonValue $failureReason
        }
        if ($script:suiteStopRequested) {
            break
        }
    }
    if ($script:suiteStopRequested) {
        break
    }
}

if (-not $script:suiteStopRequested -and -not $SkipX10 -and $repeatActions.Count -gt 0 -and $null -ne $repeatProfile) {
    foreach ($repeatAction in $repeatActions) {
        for ($iteration = 1; $iteration -le 10; $iteration++) {
            if ([ArcLiveMatrixControl]::ConsumeAbortRequest()) {
                $script:suiteStopRequested = $true
                $script:suiteStopReason = 'operator_ctrl_c'
                break
            }
            $iterationId = '{0:D2}' -f $iteration
            $caseId = "$($repeatProfile.profile_id)-x10-$repeatAction-$iterationId"
            if (-not $selectedCaseLookup.ContainsKey($caseId)) {
                continue
            }
            $caseRoot = Join-Path $runRoot "repeat-x10\$($repeatProfile.profile_id)-$repeatAction\$iterationId"
            $baseline = @(Get-Process -Name 'arc-decision-ui-host','tauri-driver','msedgedriver' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
            try {
                $context = Start-HarnessContext -SelectedCase $repeatAction -Profile $repeatProfile -CaseRoot $caseRoot -UdfRoot $udfRoot -BinaryPath $Binary -DecisionTimeout $DecisionTimeoutMs -SupervisorTimeout $SupervisorTimeoutMs -BaselineProcessIds $baseline
                $controller = Show-CaseController -Contexts @($context) -DecisionTimeout $DecisionTimeoutMs -SupervisorTimeout $SupervisorTimeoutMs -FullSuite $isFullSuite -Suite 'x10' -Iteration $iterationId -RunModeLabel $runModeLabel -SelectedCaseNumber $caseOrdinalById[$caseId] -SelectedCaseTotal $selectedCaseTotal -SuiteTotalCases $suiteTotalCases -SuitePreservedPassCases $suitePreservedPassCases -SuitePreservedOtherCases $suitePreservedOtherCases
                if (Test-SuiteStopRequested -ControllerState $controller) {
                    $script:suiteStopRequested = $true
                    $script:suiteStopReason = if ([string]::IsNullOrWhiteSpace($controller.abort_reason)) { 'operator_suite_stop' } else { $controller.abort_reason }
                }
                $report = Complete-HarnessContext -Context $context -ControllerState $controller -CleanupTimeoutMs 10000 -UdfRoot $udfRoot -Suite 'x10' -CaseIdOverride $caseId -Iteration $iterationId
                $reports.Add($report)
                $caseReason = Get-CaseResultReason -Status $report.runner_status -PassReason 'Iteración x10 revisada' -FailureReason 'Iteración x10 fallida'
                Update-CaseRow -CasesCsv $casesCsv -CaseIdValue $caseId -StatusValue $report.runner_status -ReasonValue $caseReason
            }
            catch {
                $failureReason = Protect-Note -Text $_.Exception.Message
                if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) {
                    $script:suiteStopRequested = $true
                    $script:suiteStopReason = 'controller_pipeline_stopped'
                }
                $report = Write-RunnerFailureCase -Profile $repeatProfile -CaseId $caseId -Suite 'x10' -CaseType $repeatAction -CaseRoot $caseRoot -Iteration $iterationId -Reason $failureReason
                $reports.Add($report)
                Update-CaseRow -CasesCsv $casesCsv -CaseIdValue $caseId -StatusValue 'FAIL' -ReasonValue $failureReason
            }
            if ($script:suiteStopRequested) {
                break
            }
        }
        if ($script:suiteStopRequested) {
            break
        }
    }
}

if (-not $script:suiteStopRequested -and -not $SkipConcurrentX2 -and $null -ne $repeatProfile -and @($caseRows | Where-Object { $_.suite -eq 'concurrent-x2' }).Count -gt 0) {
    $pairRoot = Join-Path $runRoot 'concurrent-x2'
    $pairCases = @(
        [pscustomobject]@{ type = 'allow'; root = Join-Path $pairRoot 'allow'; index = 0 },
        [pscustomobject]@{ type = 'deny'; root = Join-Path $pairRoot 'deny'; index = 1 }
    )
    $baseline = @(Get-Process -Name 'arc-decision-ui-host','tauri-driver','msedgedriver' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
    $contexts = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($pairCase in $pairCases) {
            $contexts.Add((Start-HarnessContext -SelectedCase $pairCase.type -Profile $repeatProfile -CaseRoot $pairCase.root -UdfRoot $udfRoot -BinaryPath $Binary -DecisionTimeout $DecisionTimeoutMs -SupervisorTimeout $SupervisorTimeoutMs -BaselineProcessIds $baseline -PairIndex $pairCase.index))
        }
        $controller = Show-CaseController -Contexts @($contexts) -DecisionTimeout $DecisionTimeoutMs -SupervisorTimeout $SupervisorTimeoutMs -FullSuite $isFullSuite -Suite 'concurrent-x2' -Iteration 'base' -RunModeLabel $runModeLabel -SelectedCaseNumber $caseOrdinalById["$($repeatProfile.profile_id)-concurrent-x2-allow"] -SelectedCaseTotal $selectedCaseTotal -SuiteTotalCases $suiteTotalCases -SuitePreservedPassCases $suitePreservedPassCases -SuitePreservedOtherCases $suitePreservedOtherCases
        if (Test-SuiteStopRequested -ControllerState $controller) {
            $script:suiteStopRequested = $true
            $script:suiteStopReason = if ([string]::IsNullOrWhiteSpace($controller.abort_reason)) { 'operator_suite_stop' } else { $controller.abort_reason }
        }
        foreach ($context in $contexts) {
            $pairCaseId = "$($repeatProfile.profile_id)-concurrent-x2-$($context.case_type)"
            $report = Complete-HarnessContext -Context $context -ControllerState $controller -CleanupTimeoutMs 10000 -UdfRoot $udfRoot -Suite 'concurrent-x2' -CaseIdOverride $pairCaseId
            $reports.Add($report)
            $caseReason = Get-CaseResultReason -Status $report.runner_status -PassReason 'Par simultáneo revisado' -FailureReason 'Par simultáneo fallido'
            Update-CaseRow -CasesCsv $casesCsv -CaseIdValue $pairCaseId -StatusValue $report.runner_status -ReasonValue $caseReason
        }
    }
    catch {
        Stop-ControllerContexts -Contexts @($contexts)
        $failureReason = Protect-Note -Text $_.Exception.Message
        if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) {
            $script:suiteStopRequested = $true
            $script:suiteStopReason = 'controller_pipeline_stopped'
        }
        foreach ($pairCase in $pairCases) {
            $caseId = "$($repeatProfile.profile_id)-concurrent-x2-$($pairCase.type)"
            $report = Write-RunnerFailureCase -Profile $repeatProfile -CaseId $caseId -Suite 'concurrent-x2' -CaseType $pairCase.type -CaseRoot $pairCase.root -Reason $failureReason
            $reports.Add($report)
            Update-CaseRow -CasesCsv $casesCsv -CaseIdValue $caseId -StatusValue 'FAIL' -ReasonValue $failureReason
        }
        if ($script:suiteStopRequested) {
            break
        }
    }
    if ($script:suiteStopRequested) {
        break
    }
}

if ($script:suiteStopRequested) {
    $suiteStopReasonValue = if ([string]::IsNullOrWhiteSpace($script:suiteStopReason)) { 'operator_suite_stop' } else { $script:suiteStopReason }
    $pendingRows = @(Import-Csv -LiteralPath $casesCsv | Where-Object { $_.status -eq 'NOT-RUN' })
    foreach ($pendingRow in $pendingRows) {
        $pendingProfile = $profiles | Where-Object { $_.profile_id -eq $pendingRow.profile_id } | Select-Object -First 1
        $pendingReport = Write-AbortedCase -CaseRow $pendingRow -Profile $pendingProfile -Reason "suite_stopped:$suiteStopReasonValue"
        $reports.Add($pendingReport)
        Update-CaseRow -CasesCsv $casesCsv -CaseIdValue $pendingRow.case_id -StatusValue 'NOT-RUN' -ReasonValue "suite_stopped:$suiteStopReasonValue"
    }
}

$profileRows = @(Import-Csv -LiteralPath $profileCsv)
foreach ($profileRow in $profileRows) {
    $profileReports = @($reports | Where-Object {
        (Get-PropertyValue -InputObject $_ -Name 'profile_id') -eq $profileRow.profile_id
    })
    $profileRow.status = if ($profileReports.Count -eq 0) {
        'NOT-RUN'
    }
    elseif (@($profileReports | Where-Object { $_.runner_status -eq 'BLOCKED' }).Count -gt 0) {
        'BLOCKED'
    }
    elseif (@($profileReports | Where-Object { $_.runner_status -ne 'PASS' }).Count -gt 0) {
        'FAIL'
    }
    else {
        'PASS'
    }
    $profileRow.reason = (@($profileReports | Where-Object { $_.runner_status -ne 'PASS' } | ForEach-Object {
        Get-PropertyValue -InputObject $_ -Name 'reason'
    }) -join '; ')
}
$profileRows | Export-Csv -NoTypeInformation -Encoding utf8 $profileCsv

$currentCatalogRows = @(Import-Csv -LiteralPath $casesCsv)
$executionCounts = Get-StatusCounts -Rows @($reports) -StatusProperty 'runner_status'
$sourceCounts = [pscustomobject]@{ PASS = 0; FAIL = 0; NOT_RUN = 0; BLOCKED = 0 }
$effectiveSuiteRows = [System.Collections.Generic.List[object]]::new()
if ($isRerunMode) {
    $currentStatusByCaseId = @{}
    foreach ($currentRow in $currentCatalogRows) {
        $currentCaseId = [string]$currentRow.case_id
        if ($currentStatusByCaseId.ContainsKey($currentCaseId)) {
            throw "El run actual contiene case_id duplicado: $currentCaseId"
        }
        $currentStatusByCaseId[$currentCaseId] = [string]$currentRow.status
    }
    $sourceCounts = Get-StatusCounts -Rows @($rerunSelection.all_rows) -StatusProperty 'status'
    foreach ($sourceRow in @($rerunSelection.all_rows)) {
        $sourceCaseId = [string]$sourceRow.case_id
        $effectiveStatus = if ($currentStatusByCaseId.ContainsKey($sourceCaseId)) {
            $currentStatusByCaseId[$sourceCaseId]
        }
        else {
            [string]$sourceRow.status
        }
        $effectiveSuiteRows.Add([pscustomobject]@{ case_id = $sourceCaseId; status = $effectiveStatus })
    }
}
else {
    foreach ($currentRow in $currentCatalogRows) {
        $effectiveSuiteRows.Add([pscustomobject]@{
                case_id = [string]$currentRow.case_id
                status = [string]$currentRow.status
            })
    }
}
$suiteCounts = Get-StatusCounts -Rows @($effectiveSuiteRows) -StatusProperty 'status'
$suiteResult = if ($suiteCounts.FAIL -eq 0 -and $suiteCounts.NOT_RUN -eq 0 -and $suiteCounts.BLOCKED -eq 0) { 'PASS' } else { 'FAIL' }
$runResult = if (@($reports | Where-Object { $_.runner_status -ne 'PASS' }).Count -eq 0) { 'PASS' } else { 'FAIL' }
Set-RunMetadata `
    -MetadataPath $metadataPath `
    -StatusValue $runResult `
    -Reports @($reports) `
    -SuiteCounts $suiteCounts `
    -SuiteTotalCases $suiteTotalCases `
    -SuiteResult $suiteResult `
    -SelectedCases $selectedCaseTotal `
    -PreservedPassCases $suitePreservedPassCases `
    -PreservedOtherCases $suitePreservedOtherCases
$summary = [ordered]@{
    schema_version = 1
    run_id = $RunId
    result = $runResult
    run_mode = $runMode
    run_mode_label = $runModeLabel
    fresh_run = -not $isRerunMode
    source_run_id = if ($isRerunMode) { $RerunRunId } else { '' }
    source_selection_mode = $sourceSelectionMode
    source_revision = $sourceRevision
    source_binary_sha256 = $sourceBinaryHash
    binary_hash_changed = $isRerunMode -and ($sourceBinaryHash -ne $script:binaryHash)
    suite_stopped = [bool]$script:suiteStopRequested
    suite_stop_reason = if ($script:suiteStopRequested) { $script:suiteStopReason } else { '' }
    profiles = $profiles.Count
    cases = $reports.Count
    selected_cases = $selectedCaseTotal
    executed_cases = $reports.Count
    counts = $executionCounts
    suite_total_cases = $suiteTotalCases
    suite_result = $suiteResult
    suite_counts = $suiteCounts
    suite_preserved_pass_cases = $suitePreservedPassCases
    suite_preserved_other_cases = $suitePreservedOtherCases
    executable_case_types = @($allCaseTypes)
    excluded_case_types = @($excludedCaseDefinitions)
    excluded_case_count = $excludedCaseCount
    coverage_status = $coverageStatus
    source_total_cases = if ($isRerunMode) { @($rerunSelection.all_rows).Count } else { 0 }
    source_counts = $sourceCounts
    failures = @($reports | Where-Object { $_.runner_status -ne 'PASS' } | ForEach-Object {
        [ordered]@{
            case_id = $_.case_id
            status = $_.runner_status
            reason = Get-PropertyValue -InputObject $_ -Name 'reason'
        }
    })
}
$summary | ConvertTo-Json -Depth 10 | Set-Content -Encoding utf8 (Join-Path $runRoot 'summary.json')
@"
# Live Matrix Run

- Run: $RunId
- Modo: $runModeLabel
- Run de origen: $($summary.source_run_id)
- Selección de origen: $($summary.source_selection_mode)
- Resultado de esta ejecución: $runResult
- Resultado acumulado de suite: $($summary.suite_result)
- Suite detenida: $($summary.suite_stopped)
- Razón de detención: $($summary.suite_stop_reason)
- Casos seleccionados: $($summary.selected_cases)
- Casos materializados en esta ejecución: $($summary.executed_cases)
- Suite acumulada: $($summary.suite_total_cases)
- Suite PASS: $($summary.suite_counts.PASS)
- Suite FAIL: $($summary.suite_counts.FAIL)
- Suite NOT-RUN: $($summary.suite_counts.NOT_RUN)
- Suite BLOCKED: $($summary.suite_counts.BLOCKED)
- PASS conservados del origen: $($summary.suite_preserved_pass_cases)
- Otros estados conservados del origen: $($summary.suite_preserved_other_cases)
- Cobertura ejecutable: $($summary.coverage_status)
- Casos excluidos por falta de implementación: $($summary.excluded_case_count)

## Conteos de esta ejecución

- PASS: $($summary.counts.PASS)
- FAIL: $($summary.counts.FAIL)
- NOT-RUN: $($summary.counts.NOT_RUN)
- BLOCKED: $($summary.counts.BLOCKED)

## Exclusiones explícitas

$(@($summary.excluded_case_types | ForEach-Object { "- $($_.case_type): $($_.reason) ($($_.scope))" }) -join "`n")

## Celdas no PASS

$(@($summary.failures | ForEach-Object { "- $($_.case_id): $($_.status) — $($_.reason)" }) -join "`n")
"@ | Set-Content -Encoding utf8 (Join-Path $runRoot 'summary.md')

[ArcLiveMatrixControl]::RemoveCancelHandler()

Write-Output "RUN_ID=$RunId"
Write-Output "RUN_DIRECTORY=$runRoot"
Write-Output "RUN_MODE=$runMode"
Write-Output "RUN_MODE_LABEL=$runModeLabel"
Write-Output "SOURCE_RUN_ID=$($summary.source_run_id)"
Write-Output "SOURCE_SELECTION_MODE=$($summary.source_selection_mode)"
Write-Output "RESULT=$runResult"
Write-Output "SUITE_RESULT=$($summary.suite_result)"
Write-Output "CASES=$($reports.Count)"
Write-Output "SELECTED_CASES=$($summary.selected_cases)"
Write-Output "EXECUTED_CASES=$($summary.executed_cases)"
Write-Output "SUITE_CASES=$($summary.suite_total_cases)"
Write-Output "PASS=$($summary.counts.PASS)"
Write-Output "FAIL=$($summary.counts.FAIL)"
Write-Output "NOT_RUN=$($summary.counts.NOT_RUN)"
Write-Output "BLOCKED=$($summary.counts.BLOCKED)"
Write-Output "SUITE_PASS=$($summary.suite_counts.PASS)"
Write-Output "SUITE_FAIL=$($summary.suite_counts.FAIL)"
Write-Output "SUITE_NOT_RUN=$($summary.suite_counts.NOT_RUN)"
Write-Output "SUITE_BLOCKED=$($summary.suite_counts.BLOCKED)"
Write-Output "SUITE_PRESERVED_PASS=$($summary.suite_preserved_pass_cases)"
Write-Output "SUITE_PRESERVED_OTHER=$($summary.suite_preserved_other_cases)"
Write-Output "COVERAGE_STATUS=$($summary.coverage_status)"
Write-Output "EXCLUDED_CASES=$($summary.excluded_case_count)"
Write-Output "EXCLUDED_CASE_TYPES=$(($excludedCaseTypes -join ','))"
Write-Output "SUITE_STOPPED=$($summary.suite_stopped)"
Write-Output "SUITE_STOP_REASON=$($summary.suite_stop_reason)"
if ($runResult -ne 'PASS') {
    exit 1
}
