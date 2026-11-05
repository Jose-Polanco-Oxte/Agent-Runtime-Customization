[CmdletBinding()]
param([switch]$InventoryOnly)

$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
Push-Location $taskRoot
try {
    python tools/audit-contracts.py --check-bridge --output target/contract-audit/inventory.json
    if ($LASTEXITCODE -ne 0) { throw 'Contract inventory failed.' }
    if ($InventoryOnly) { return }
    $failures = [System.Collections.Generic.List[string]]::new()

    # Compile shipping configuration separately: all-features can hide cfg(not(feature)).
    cargo check --workspace --all-targets --locked --offline
    if ($LASTEXITCODE -ne 0) { $failures.Add('Workspace compilation failed.') }
    cargo check --workspace --all-targets --all-features --locked --offline
    if ($LASTEXITCODE -ne 0) { $failures.Add('Feature configuration compilation failed.') }

    # force-warn exposes existing allow(dead_code); JSON is also useful to compare baselines.
    $lintOutput = @(cargo clippy --workspace --lib --bins --locked --offline --message-format=json -- --force-warn dead_code --force-warn unused_imports --force-warn unused_variables --force-warn unreachable_pub)
    $lintExit = $LASTEXITCODE
    $lintOutput | Set-Content -LiteralPath target/contract-audit/compiler.jsonl -Encoding utf8
    $unused = @($lintOutput | ForEach-Object {
        $entry = $_ | ConvertFrom-Json
        if ($entry.reason -eq 'compiler-message' -and $entry.message.code.code -in @('dead_code', 'unused_imports', 'unused_variables', 'unreachable_pub')) {
            $entry.message.rendered
        }
    })
    foreach ($diagnostic in $unused) { Write-Output $diagnostic }
    if ($lintExit -ne 0) { $failures.Add('Clippy compilation failed.') }

    Push-Location ui/decision
    try {
        npm run check:audit
        if ($LASTEXITCODE -ne 0) { $failures.Add('Frontend unused-code/type check failed.') }
        npm run test:webdriver:types
        if ($LASTEXITCODE -ne 0) { $failures.Add('Webdriver consumer compilation failed.') }
    } finally { Pop-Location }
    if ($unused.Count -gt 0) { $failures.Add("Unused/visibility diagnostics: $($unused.Count). See target/contract-audit/compiler.jsonl.") }
    if ($failures.Count -gt 0) { throw ($failures -join [Environment]::NewLine) }
} finally { Pop-Location }
