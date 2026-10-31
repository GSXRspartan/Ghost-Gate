[CmdletBinding()]
param(
    [Parameter(Position = 0, Mandatory = $true)] [ValidateSet('start', 'stop', 'status', 'health-check')] [string] $Command,
    [ValidateSet('browser', 'walletd')] [string] $Mode = 'browser'
)

$ErrorActionPreference = 'Stop'
$Repo = (git -C $PSScriptRoot\.. rev-parse --show-toplevel).Trim()
$StateDir = Join-Path $Repo '.ghost-gate'
$StateFile = Join-Path $StateDir 'dev-state.json'
$ConfigFile = Join-Path $Repo '.env.dev'
$BridgePort = if ($env:GG_BRIDGE_PORT) { [int]$env:GG_BRIDGE_PORT } elseif ($Mode -eq 'walletd') { 7898 } else { 7897 }
$BridgeUrl = "http://127.0.0.1:$BridgePort"
$WalletdUrl = if ($env:GG_WALLETD_ENDPOINT) { $env:GG_WALLETD_ENDPOINT } else { 'http://127.0.0.1:5110/json_rpc' }

function Read-LocalConfig {
    if (!(Test-Path -LiteralPath $ConfigFile)) { return }
    Get-Content -LiteralPath $ConfigFile | ForEach-Object {
        if ($_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
            $name, $value = $Matches[1], $Matches[2].Trim().Trim('"')
            if (!(Test-Path "Env:$name")) { Set-Item -Path "Env:$name" -Value $value }
        }
    }
}
function Read-State { if (Test-Path $StateFile) { Get-Content -Raw $StateFile | ConvertFrom-Json } }
function Write-State($value) { New-Item -ItemType Directory -Force $StateDir | Out-Null; $value | ConvertTo-Json | Set-Content -NoNewline $StateFile }
function Test-Bridge { try { (Invoke-RestMethod "$BridgeUrl/health" -TimeoutSec 3).service -eq 'ghost-gate-bridge' } catch { $false } }
function Get-WalletdInfo {
    $body = '{"jsonrpc":"2.0","id":1,"method":"wallet.get_info","params":{}}'
    try { $reply = Invoke-RestMethod -Method Post -Uri $WalletdUrl -ContentType 'application/json' -Body $body -TimeoutSec 4 } catch { throw "walletd is unavailable at ${WalletdUrl}: $($_.Exception.Message)" }
    if (!$reply.result -or $reply.result.network -ne 'esmeralda' -or $reply.result.network_byte -ne 38 -or $reply.result.version -ne '0.47.0') {
        throw 'walletd must report Esmeralda, network byte 38, and version 0.47.0'
    }
    $reply.result
}
function Get-BridgeBinary {
    $target = (
        (cargo metadata --no-deps --format-version 1 |
        ConvertFrom-Json).target_directory
    )

    $candidates = @(
    (Join-Path $target 'release\ghost-gate-bridge.exe'),
    (Join-Path $target 'debug\ghost-gate-bridge.exe')
)

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            Write-Host "Using bridge: $candidate"
            return $candidate
        }
    }

    throw "No native Windows Ghost Gate bridge executable found."
}
function Assert-Configuration {
    if (!$env:GG_BRIDGE_GATES) { $env:GG_BRIDGE_GATES = 'esm10=:resource_0101010101010101010101010101010101010101010101010101010101010101:10000000:6:tTARI' }
    if (!$env:GG_OOTLE_NETWORK) { $env:GG_OOTLE_NETWORK = '26' }
    if ($env:GG_BRIDGE_GATES -notmatch '^[^=]+=:[^:]+:[0-9]+:[0-9]+:[^,]+$') { throw 'GG_BRIDGE_GATES must describe one credential-only gate: id=:resource:threshold:divisibility:symbol' }
}
function Assert-PortFree {
    $listener = Get-NetTCPConnection -LocalPort $BridgePort -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($listener) { throw "port $BridgePort is occupied by PID $($listener.OwningProcess); refusing to stop or replace it" }
}
function Assert-Owned($state) {
    if (!$state) { return $false }
    $process = Get-Process -Id $state.pid -ErrorAction SilentlyContinue
    if (!$process -or !$process.Path -or $process.Path -ne $state.executable -or $process.StartTime.ToUniversalTime().ToString('o') -ne $state.started) { return $false }
    $true
}

Read-LocalConfig
if ($Command -eq 'status' -or $Command -eq 'health-check') {
    $state = Read-State; $owned = Assert-Owned $state
    [pscustomobject]@{ bridge_url = $BridgeUrl; bridge_healthy = (Test-Bridge); owned_process = $owned; walletd_endpoint = $WalletdUrl } | Format-List
    if ($Mode -eq 'walletd') { Get-WalletdInfo | Format-List }
    exit
}
if ($Command -eq 'stop') {
    $state = Read-State
    if (Assert-Owned $state) { Stop-Process -Id $state.pid; Remove-Item -LiteralPath $StateFile -Force; Write-Host 'Stopped launcher-owned bridge.' } else { Write-Host 'No launcher-owned bridge to stop.' }
    exit
}

Assert-Configuration
$state = Read-State
if (Assert-Owned $state) { if (Test-Bridge) { Write-Host "Bridge already healthy at $BridgeUrl"; exit } throw 'launcher-owned bridge exists but is unhealthy; use stop before retrying' }
if ($state) { Write-Warning 'Ignoring stale launcher state; it does not identify the recorded process.' }
Assert-PortFree
if ($Mode -eq 'walletd') {
    Get-WalletdInfo | Out-Null
    if (!$env:GG_WALLETD_TOKEN) { throw 'walletd mode requires GG_WALLETD_TOKEN in this PowerShell process; it is never stored or printed' }
} else { Remove-Item Env:GG_WALLETD_ENDPOINT -ErrorAction SilentlyContinue; Remove-Item Env:GG_WALLETD_TOKEN -ErrorAction SilentlyContinue }

$binary = Get-BridgeBinary
$env:GG_BRIDGE_BIND = "127.0.0.1:$BridgePort"
$env:GG_BRIDGE_ORIGINS = $BridgeUrl
if ($Mode -eq 'walletd') { $env:GG_WALLETD_ENDPOINT = $WalletdUrl }
New-Item -ItemType Directory -Force $StateDir | Out-Null
$log = Join-Path $StateDir 'bridge.log'
$errorLog = Join-Path $StateDir 'bridge-error.log'
$proc = Start-Process -FilePath $binary -WorkingDirectory $Repo -RedirectStandardOutput $log -RedirectStandardError $errorLog -PassThru
$record = [pscustomobject]@{ pid=$proc.Id; started=$proc.StartTime.ToUniversalTime().ToString('o'); executable=$binary; mode=$Mode; port=$BridgePort }
Write-State $record
Start-Sleep -Milliseconds 800
if (!(Test-Bridge)) { if (Assert-Owned $record) { Stop-Process -Id $proc.Id }; Remove-Item $StateFile -Force -ErrorAction SilentlyContinue; throw "bridge did not become healthy; see $log" }
Write-Host "Ghost Gate $Mode mode is healthy: $BridgeUrl"
