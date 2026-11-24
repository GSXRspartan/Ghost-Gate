# Starts the local mainnet L2 lab: the fixture bridge bound to a mainnet Crypt gate
# (network 0x00, native TARI resource, 100 TARI threshold) against the real mainnet indexer.
#
# Fail-closed by construction: no bot key is configured, so every bot/admission route refuses;
# no access plane is configured, so no session can ever be issued; the gate is credential-only.
param(
    [switch]$StopServices,
    [switch]$Status
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$StateDir = if ($env:GG_MAINNET_STATE_DIR) { $env:GG_MAINNET_STATE_DIR } else { 'D:\OpenCodeTemp\mainnet-lab' }
$BridgeBin = if ($env:GG_BRIDGE_BIN) { $env:GG_BRIDGE_BIN } else { 'D:\GG-Target\debug\m16-fixture-bridge.exe' }
$BridgePort = 7798

if (-not (Test-Path -LiteralPath $BridgeBin)) { throw "missing bridge binary: $BridgeBin (build tools\m16-fixture-bridge first)" }
New-Item -ItemType Directory -Path $StateDir -Force | Out-Null

function Test-Port([int]$Port) {
    $c = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    return [bool]$c
}

if ($StopServices) {
    Get-NetTCPConnection -LocalPort $BridgePort -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
        Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
        Write-Host "stopped mainnet bridge (pid $($_.OwningProcess))"
    }
    return
}

if ($Status) {
    $up = Test-Port $BridgePort
    Write-Host "mainnet bridge port ${BridgePort}: $(if ($up) { 'listening' } else { 'down' })"
    if ($up) {
        try { (Invoke-RestMethod -Uri "http://127.0.0.1:$BridgePort/lab/gates" -TimeoutSec 5) | ConvertTo-Json -Compress | Write-Host } catch { Write-Host 'gates: unavailable' }
    }
    try { $h = Invoke-RestMethod -Uri 'https://indexer-a.ootle.tari.com/health' -TimeoutSec 10; Write-Host "mainnet indexer: $($h.version) epoch $($h.current_epoch)" } catch { Write-Host 'mainnet indexer: unavailable' }
    return
}

if (Test-Port $BridgePort) { Write-Host "mainnet bridge already listening on $BridgePort"; return }

$start = {
    $env:GG_BRIDGE_BIND = "127.0.0.1:$BridgePort"
    $env:GG_BRIDGE_ORIGINS = "http://127.0.0.1:$BridgePort"
    $env:GG_BRIDGE_RELYING_SITE = "http://127.0.0.1:$BridgePort"
    $env:GG_GATE_ID = 'Crypt'
    $env:GG_GATE_NETWORK_HEX = '00'
    $env:GG_GATE_SYMBOL = 'TARI'
    $env:GG_GATE_DIVISIBILITY = '6'
    $env:GG_GATE_THRESHOLD = '100000000'
    $env:GG_INDEXER_ENDPOINT = 'https://indexer-a.ootle.tari.com/'
    $env:GG_BOT_AUTH_DB_DIR = Join-Path $StateDir 'auth-db'
    Remove-Item Env:GG_BOT_KEY -ErrorAction SilentlyContinue
    Remove-Item Env:GG_GGBP1_TEST -ErrorAction SilentlyContinue
    return Start-Process -FilePath $BridgeBin -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $StateDir 'bridge.stdout.log') `
        -RedirectStandardError (Join-Path $StateDir 'bridge.stderr.log') -WorkingDirectory $RepoRoot
}
$proc = & $start
Start-Sleep -Seconds 2
Write-Host "mainnet lab bridge started (pid $($proc.Id)): http://127.0.0.1:$BridgePort/lab"
Write-Host 'Gate: Crypt, network 0x00 (mainnet), threshold 100000000 raw (100 TARI), real mainnet indexer chain reader.'
Write-Host 'No bot routes, no access plane: every proof verdict is non-authorizing by construction.'
