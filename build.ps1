#requires -Version 5.1
<#
.SYNOPSIS
    Script de compilación completa e instalación para Arc Core y Arc Decision UI.

.DESCRIPTION
    Orquesta de forma determinista la compilación completa del frontend Svelte/Vite,
    el ejecutable sidecar de Tauri/Rust (arc-decision-ui-host) con assets embebidos,
    el ejecutable principal CLI (arc), y opcionalmente instala ambos binarios como
    hermanos co-localizados en el directorio bin de Cargo (o en una ruta especificada).

.PARAMETER Install
    Instala arc mediante 'cargo install --path . --force' y copia el ejecutable
    arc-decision-ui-host al mismo directorio bin para garantizar la resolución hermana.

.PARAMETER InstallDir
    Ruta de instalación personalizada. Por defecto usa $CARGO_HOME/bin o ~/.cargo/bin.

.PARAMETER ProfileType
    Perfil de compilación de Cargo: 'Release' (predeterminado) o 'Debug'.

.PARAMETER SkipFrontend
    Omite la compilación del frontend Svelte si los assets en ui/decision/dist ya están actualizados.

.PARAMETER SkipNpmInstall
    Omite 'npm ci' / 'npm install' incluso si node_modules no existe.

.PARAMETER Clean
    Ejecuta 'cargo clean' y elimina el directorio ui/decision/dist antes de compilar.

.PARAMETER Check
    Ejecuta un smoke test de verificación (comprobando 'arc --version' y la resolución del sidecar).

.PARAMETER Help
    Muestra la ayuda de uso.

.EXAMPLE
    .\build.ps1
    Compila el frontend y ambos binarios de Rust en modo Release dentro de target\release.

.EXAMPLE
    .\build.ps1 -Install
    Compila todo e instala arc.exe y arc-decision-ui-host.exe en ~/.cargo/bin.

.EXAMPLE
    .\build.ps1 -Install -Check
    Compila, instala y ejecuta un smoke test de verificación.
#>

[CmdletBinding(PositionalBinding = $false)]
param(
    [switch]$Install,
    [string]$InstallDir = '',
    [ValidateSet('Release', 'Debug')]
    [string]$ProfileType = 'Release',
    [switch]$SkipFrontend,
    [switch]$SkipNpmInstall,
    [switch]$Clean,
    [switch]$Check,
    [switch]$Help,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RemainingArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Normalizar banderas pasadas con formato GNU (--install, --check, --skip-frontend, etc.)
if ($null -ne $RemainingArgs) {
    if ($RemainingArgs -contains '--help' -or $RemainingArgs -contains '-h') {
        $Help = $true
    }
    if (-not $Install -and ($RemainingArgs -contains '--install' -or $RemainingArgs -contains '-install')) {
        $Install = $true
    }
    if (-not $Check -and ($RemainingArgs -contains '--check' -or $RemainingArgs -contains '-check' -or $RemainingArgs -contains '--smoke-test')) {
        $Check = $true
    }
    if (-not $Clean -and ($RemainingArgs -contains '--clean' -or $RemainingArgs -contains '-clean')) {
        $Clean = $true
    }
    if (-not $SkipFrontend -and ($RemainingArgs -contains '--skip-frontend' -or $RemainingArgs -contains '-skip-frontend')) {
        $SkipFrontend = $true
    }
    if (-not $SkipNpmInstall -and ($RemainingArgs -contains '--skip-npm-install' -or $RemainingArgs -contains '-skip-npm-install')) {
        $SkipNpmInstall = $true
    }
    for ($i = 0; $i -lt $RemainingArgs.Count; $i++) {
        if ($RemainingArgs[$i] -in @('--install-dir', '-install-dir') -and ($i + 1) -lt $RemainingArgs.Count) {
            $InstallDir = $RemainingArgs[$i + 1]
        }
        if ($RemainingArgs[$i] -in @('--profile', '-profile') -and ($i + 1) -lt $RemainingArgs.Count) {
            $parsedProfile = $RemainingArgs[$i + 1]
            if ($parsedProfile -match '^(?i)release$') { $ProfileType = 'Release' }
            elseif ($parsedProfile -match '^(?i)debug$') { $ProfileType = 'Debug' }
        }
    }
}

if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path -Detailed
    exit 0
}

$repoRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
$uiDir = Join-Path $repoRoot 'ui\decision'
$targetProfileDir = if ($ProfileType -eq 'Release') { 'release' } else { 'debug' }
$onWindows = if ($null -ne (Get-Variable -Name IsWindows -ErrorAction SilentlyContinue)) { $IsWindows } else { $env:OS -eq 'Windows_NT' }
$exeSuffix = if ($onWindows) { '.exe' } else { '' }

$arcExeName = "arc$exeSuffix"
$hostExeName = "arc-decision-ui-host$exeSuffix"

$targetBinDir = Join-Path $repoRoot "target\$targetProfileDir"
$arcTargetExe = Join-Path $targetBinDir $arcExeName
$hostTargetExe = Join-Path $targetBinDir $hostExeName

function Write-Step {
    param([string]$Message)
    Write-Host "`n=== $Message ===" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "  [OK] $Message" -ForegroundColor Green
}

function Write-WarningMsg {
    param([string]$Message)
    Write-Host "  [WARN] $Message" -ForegroundColor Yellow
}

function Write-Failure {
    param([string]$Message)
    Write-Host "  [ERROR] $Message" -ForegroundColor Red
}

function Assert-Command {
    param([string]$Name)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -eq $cmd) {
        throw "La herramienta requerida '$Name' no se encuentra en el PATH."
    }
    return $cmd.Source
}

# ---------------------------------------------------------------------------
# Paso 0: Preflight y Validaciones de Entorno
# ---------------------------------------------------------------------------
Write-Step "Paso 0: Verificaciones previas del entorno"

$cargoPath = Assert-Command 'cargo'
$rustcPath = Assert-Command 'rustc'
$rustVersion = (& $rustcPath --version).Trim()
Write-Success "Rust toolchain: $rustVersion ($cargoPath)"

if (-not $SkipFrontend) {
    $nodePath = Assert-Command 'node'
    $npmPath = Assert-Command 'npm'
    $nodeVersion = (& $nodePath --version).Trim()
    $npmVersion = (& $npmPath --version).Trim()
    Write-Success "Node.js & npm: Node $nodeVersion, npm $npmVersion"
}

if (-not (Test-Path -LiteralPath (Join-Path $repoRoot 'Cargo.toml') -PathType Leaf)) {
    throw "No se encontró Cargo.toml en la raíz del repositorio: $repoRoot"
}
if (-not (Test-Path -LiteralPath (Join-Path $uiDir 'package.json') -PathType Leaf)) {
    throw "No se encontró ui/decision/package.json en: $uiDir"
}

if ($onWindows) {
    $wvRegistryPaths = @(
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}',
        'HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
    )
    $wvFound = $false
    foreach ($reg in $wvRegistryPaths) {
        if (Test-Path -LiteralPath $reg) {
            $item = Get-ItemProperty -LiteralPath $reg
            $pv = [string]$item.pv
            Write-Success "Microsoft Edge WebView2 Runtime detectado (versión $pv)"
            $wvFound = $true
            break
        }
    }
    if (-not $wvFound) {
        Write-WarningMsg "No se detectó registro de WebView2 Runtime en HKLM. Asegúrese de tenerlo instalado."
    }
}

# ---------------------------------------------------------------------------
# Limpieza opcional (-Clean)
# ---------------------------------------------------------------------------
if ($Clean) {
    Write-Step "Limpieza de artefactos previos (-Clean)"
    Push-Location $repoRoot
    try {
        & $cargoPath clean
    }
    finally {
        Pop-Location
    }
    $distDir = Join-Path $uiDir 'dist'
    if (Test-Path -LiteralPath $distDir) {
        Remove-Item -LiteralPath $distDir -Recurse -Force
        Write-Success "Directorio $distDir eliminado."
    }
}

# ---------------------------------------------------------------------------
# Paso 1: Compilación del Frontend (Svelte + Vite)
# ---------------------------------------------------------------------------
if (-not $SkipFrontend) {
    Write-Step "Paso 1: Compilación del Frontend Svelte/Vite (ui/decision)"
    $nodeModulesDir = Join-Path $uiDir 'node_modules'
    if (-not (Test-Path -LiteralPath $nodeModulesDir) -and -not $SkipNpmInstall) {
        Write-Host "  Instalando dependencias de npm en ui/decision..."
        Push-Location $uiDir
        try {
            & npm ci --ignore-scripts
            if ($LASTEXITCODE -ne 0) {
                Write-WarningMsg "'npm ci' falló. Intentando 'npm install'..."
                & npm install --ignore-scripts
                if ($LASTEXITCODE -ne 0) {
                    throw "Instalación de dependencias de npm falló con código $LASTEXITCODE."
                }
            }
        }
        finally {
            Pop-Location
        }
        Write-Success "Dependencias de npm instaladas."
    }

    Push-Location $uiDir
    try {
        Write-Host "  Ejecutando 'npm run build' (svelte-check y vite build)..."
        & npm run build
        if ($LASTEXITCODE -ne 0) {
            throw "El build del frontend de la UI falló con código $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }

    $frontendIndex = Join-Path $uiDir 'dist\index.html'
    if (-not (Test-Path -LiteralPath $frontendIndex -PathType Leaf)) {
        throw "El build del frontend finalizó pero no se generó '$frontendIndex'."
    }
    Write-Success "Frontend compilado correctamente en ui/decision/dist."
}
else {
    Write-Step "Paso 1: Frontend omitido (-SkipFrontend)"
    $frontendIndex = Join-Path $uiDir 'dist\index.html'
    if (-not (Test-Path -LiteralPath $frontendIndex -PathType Leaf)) {
        throw "No se puede omitir el frontend porque '$frontendIndex' no existe. Ejecute sin -SkipFrontend."
    }
    Write-Success "Utilizando assets de frontend preexistentes en ui/decision/dist."
}

# ---------------------------------------------------------------------------
# Paso 2: Compilación del Ejecutable de Decision UI Host (Rust/Tauri sidecar)
# ---------------------------------------------------------------------------
Write-Step "Paso 2: Compilación de Decision UI Host sidecar (arc-decision-ui-host)"

$sidecarCargoArgs = @(
    'build',
    '--manifest-path', (Join-Path $repoRoot 'Cargo.toml'),
    '-p', 'arc-decision-ui-host',
    '--features', 'arc-decision-ui-host/custom-protocol'
)
if ($ProfileType -eq 'Release') {
    $sidecarCargoArgs += '--release'
}

Push-Location $repoRoot
try {
    Write-Host "  cargo $($sidecarCargoArgs -join ' ')..."
    & $cargoPath @sidecarCargoArgs
    if ($LASTEXITCODE -ne 0) {
        throw "La compilación de arc-decision-ui-host falló con código $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}

if (-not (Test-Path -LiteralPath $hostTargetExe -PathType Leaf)) {
    throw "No se encontró el binario generado de arc-decision-ui-host en: $hostTargetExe"
}
$hostItem = Get-Item -LiteralPath $hostTargetExe
Write-Success "Decision UI Host generado: $hostTargetExe ($([math]::Round($hostItem.Length / 1MB, 2)) MB)"

# ---------------------------------------------------------------------------
# Paso 3: Compilación de Arc Core CLI (Rust)
# ---------------------------------------------------------------------------
Write-Step "Paso 3: Compilación de Arc Core CLI (arc)"

$arcCargoArgs = @(
    'build',
    '--manifest-path', (Join-Path $repoRoot 'Cargo.toml'),
    '-p', 'arc',
    '--bin', 'arc'
)
if ($ProfileType -eq 'Release') {
    $arcCargoArgs += '--release'
}

Push-Location $repoRoot
try {
    Write-Host "  cargo $($arcCargoArgs -join ' ')..."
    & $cargoPath @arcCargoArgs
    if ($LASTEXITCODE -ne 0) {
        throw "La compilación de arc falló con código $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}

if (-not (Test-Path -LiteralPath $arcTargetExe -PathType Leaf)) {
    throw "No se encontró el binario generado de arc en: $arcTargetExe"
}
$arcItem = Get-Item -LiteralPath $arcTargetExe
Write-Success "Arc Core CLI generado: $arcTargetExe ($([math]::Round($arcItem.Length / 1MB, 2)) MB)"
Write-Success "Ambos binarios son hermanos co-localizados en: $targetBinDir"

# ---------------------------------------------------------------------------
# Paso 4: Instalación en el PATH (-Install)
# ---------------------------------------------------------------------------
if ($Install) {
    Write-Step "Paso 4: Instalación y Co-localización de Binarios Hermanos (-Install)"

    # Determinar directorio binario de destino
    $resolvedInstallDir = if (-not [string]::IsNullOrWhiteSpace($InstallDir)) {
        [System.IO.Path]::GetFullPath($InstallDir)
    }
    elseif ($env:CARGO_HOME) {
        Join-Path $env:CARGO_HOME 'bin'
    }
    else {
        Join-Path $env:USERPROFILE '.cargo\bin'
    }

    if (-not (Test-Path -LiteralPath $resolvedInstallDir)) {
        New-Item -ItemType Directory -Force -Path $resolvedInstallDir | Out-Null
    }

    Write-Host "  Directorio de instalación: $resolvedInstallDir"

    # Ejecutar cargo install --path . --force para registrar arc en Cargo
    Push-Location $repoRoot
    try {
        $installArgs = @('install', '--path', '.', '--force')
        if (-not [string]::IsNullOrWhiteSpace($InstallDir)) {
            $installArgs += @('--root', (Split-Path -Parent $resolvedInstallDir))
        }
        Write-Host "  Ejecutando: cargo $($installArgs -join ' ')..."
        & $cargoPath @installArgs
        if ($LASTEXITCODE -ne 0) {
            throw "cargo install falló con código $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }

    # Copiar el sidecar hermano (arc-decision-ui-host) al mismo directorio
    $installedHostPath = Join-Path $resolvedInstallDir $hostExeName
    Write-Host "  Copiando sidecar hermano $hostExeName a $resolvedInstallDir..."
    Copy-Item -LiteralPath $hostTargetExe -Destination $installedHostPath -Force

    $installedArcPath = Join-Path $resolvedInstallDir $arcExeName
    if (-not (Test-Path -LiteralPath $installedArcPath -PathType Leaf)) {
        throw "El binario arc no se encuentra instalado en: $installedArcPath"
    }
    if (-not (Test-Path -LiteralPath $installedHostPath -PathType Leaf)) {
        throw "El binario arc-decision-ui-host no se encuentra instalado en: $installedHostPath"
    }

    $installedArcHash = (Get-FileHash -LiteralPath $installedArcPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $installedHostHash = (Get-FileHash -LiteralPath $installedHostPath -Algorithm SHA256).Hash.ToLowerInvariant()

    Write-Success "Instalación completada exitosamente en: $resolvedInstallDir"
    Write-Host "    - $arcExeName             (SHA256: $installedArcHash)" -ForegroundColor DarkGray
    Write-Host "    - $hostExeName (SHA256: $installedHostHash)" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Paso 5: Verificación y Smoke Test (-Check)
# ---------------------------------------------------------------------------
if ($Check) {
    Write-Step "Paso 5: Verificación y Smoke Test (-Check)"

    $testArcPath = if ($Install) {
        Join-Path $resolvedInstallDir $arcExeName
    }
    else {
        $arcTargetExe
    }

    Write-Host "  Probando ejecución de '$testArcPath --version'..."
    $versionOutput = (& $testArcPath --version).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "La ejecución de '$testArcPath --version' falló con código $LASTEXITCODE."
    }
    Write-Success "Versión verificada: $versionOutput"

    # Verificar que el sidecar hermano exista físicamente junto a él
    $siblingDir = Split-Path -Parent $testArcPath
    $expectedSibling = Join-Path $siblingDir $hostExeName
    if (-not (Test-Path -LiteralPath $expectedSibling -PathType Leaf)) {
        throw "El ejecutable hermano $hostExeName no existe en $siblingDir."
    }
    Write-Success "Resolución de sidecar hermano verificada en: $expectedSibling"
}

Write-Step "Build Completado con Éxito"
Write-Host "Artefactos listos en: $targetBinDir" -ForegroundColor Green
if ($Install) {
    Write-Host "Instalados y disponibles en PATH: $resolvedInstallDir" -ForegroundColor Green
}
exit 0
