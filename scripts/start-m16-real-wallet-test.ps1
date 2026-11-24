param(
    [switch]$StartServices,
    [switch]$StopServices,
    [switch]$Status,
    [int]$TelegramUser = 424242
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$StateDir = if ($env:GG_M16_STATE_DIR) { $env:GG_M16_STATE_DIR } else { 'D:\OpenCodeTemp\m16-real-wallet' }
$StateFile = Join-Path $StateDir 'state.json'
$BridgeBin = if ($env:GG_BRIDGE_BIN) { $env:GG_BRIDGE_BIN } else { 'D:\GG-Target\debug\m16-fixture-bridge.exe' }
$BotBin = if ($env:GG_TELEGRAM_BIN) { $env:GG_TELEGRAM_BIN } else { 'D:\GG-Target\debug\ghost-gate-telegram.exe' }
$Python = if ($env:GG_PYTHON) { $env:GG_PYTHON } else { 'D:\GG-Target\Python314\python.exe' }
$FixtureScript = Join-Path $RepoRoot 'scripts\fixture-telegram-server.py'

$BridgePort = 7799
$ClaimPort = 7808
$FixturePort = 7811
$ChatId = '-1001234567890'
$BotKey = '0102030405060708091011121314151617181920212223242526272829303132'
$PolicyHash = 'feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface'

New-Item -ItemType Directory -Path $StateDir -Force | Out-Null

function Test-Port([int]$Port) {
    $c = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    return [bool]$c
}

function Save-State($state) {
    $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $StateFile -Encoding ascii
}

function Load-State {
    if (Test-Path -LiteralPath $StateFile) {
        return Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
    }
    return $null
}

function Set-EnvThenStart($FilePath, $ArgumentList, $EnvMap, $LogName, $WorkDir) {
    $old = @{}
    foreach ($k in $EnvMap.Keys) { $old[$k] = [Environment]::GetEnvironmentVariable($k); [Environment]::SetEnvironmentVariable($k, [string]$EnvMap[$k]) }
    try {
        $startArgs = @{
            FilePath = $FilePath
            PassThru = $true
            WindowStyle = 'Hidden'
            RedirectStandardOutput = (Join-Path $StateDir "$LogName.stdout.log")
            RedirectStandardError = (Join-Path $StateDir "$LogName.stderr.log")
            WorkingDirectory = $WorkDir
        }
        if ($ArgumentList -and @($ArgumentList).Count -gt 0) { $startArgs.ArgumentList = @($ArgumentList) }
        return Start-Process @startArgs
    }
    finally {
        foreach ($k in $old.Keys) { [Environment]::SetEnvironmentVariable($k, $old[$k]) }
    }
}

function Start-All {
    $state = Load-State
    if (-not $state) { $state = @{ bridge = 0; bot = 0; fixture = 0 } }
    $pids = @{}
    foreach ($p in @('bridge','bot','fixture')) { $pids[$p] = [int]$state.$p }

    if (-not (Test-Path -LiteralPath $BridgeBin)) { throw "missing bridge binary: $BridgeBin" }
    if (-not (Test-Path -LiteralPath $BotBin)) { throw "missing bot binary: $BotBin" }
    if (-not (Test-Path -LiteralPath $Python)) { throw "missing python: $Python" }
    if (-not (Test-Path -LiteralPath $FixtureScript)) { throw "missing fixture server: $FixtureScript" }

    if (-not (Test-Port $FixturePort)) {
        $proc = Start-Process -FilePath $Python -ArgumentList @($FixtureScript, "$FixturePort", $ChatId) -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput (Join-Path $StateDir 'fixture.stdout.log') `
            -RedirectStandardError (Join-Path $StateDir 'fixture.stderr.log') -WorkingDirectory $RepoRoot
        $pids.fixture = $proc.Id
    }
    if (-not (Test-Port $BridgePort)) {
        $envMap = @{
            GG_BRIDGE_BIND = "127.0.0.1:$BridgePort"
            GG_BRIDGE_ORIGINS = "http://127.0.0.1:$BridgePort"
            GG_BRIDGE_RELYING_SITE = "http://127.0.0.1:$BridgePort"
            GG_GATE_THRESHOLD = '100000000'
            GG_INDEXER_ENDPOINT = 'https://esme-indexer-a.ootle.tari.com/'
            GG_BOT_KEY = $BotKey
            GG_BOT_AUTH_DB_DIR = (Join-Path $StateDir 'auth-db')
            GG_BOT_GATE_ID = 'esme'
            GG_BOT_POLICY_HASH = $PolicyHash
            GG_BOT_SESSION_TTL_SECS = '600'
        }
        $proc = Set-EnvThenStart $BridgeBin @() $envMap 'bridge' $RepoRoot
        $pids.bridge = $proc.Id
    }
    if (-not (Test-Port $ClaimPort)) {
        $envMap = @{
            GG_TG_FIXTURE = '1'
            GG_TG_API_URL = "http://127.0.0.1:$FixturePort"
            GG_TG_BOT_TOKEN = 'fixture_m16test'
            GG_TG_CHAT_ID = $ChatId
            GG_TG_FIXTURE_TEST_CHAT_ID = $ChatId
            GG_BOT_ESMERALDA_KEY = $BotKey
            GG_BOT_ESMERALDA_BRIDGE = "http://127.0.0.1:$BridgePort"
            GG_BOT_ESMERALDA_GATE_ID = 'esme'
            GG_BOT_ESMERALDA_POLICY_HASH = $PolicyHash
            GG_BOT_SESSION_STORE_DIR = (Join-Path $StateDir 'bot-store')
            GG_BOT_SESSION_TTL_SECS = '600'
            GG_JOIN_BASE_URL = "http://127.0.0.1:$BridgePort"
            GG_TG_CLAIM_PORT = "$ClaimPort"
            GG_TG_GATE = 'esme'
        }
        $proc = Set-EnvThenStart $BotBin @() $envMap 'bot' $RepoRoot
        $pids.bot = $proc.Id
    }
    @{ bridge = $pids.bridge; bot = $pids.bot; fixture = $pids.fixture } | Save-State
    Write-Host "M16 fixture services ready: bridge $BridgePort, claim $ClaimPort, telegram fixture $FixturePort"
}

function Stop-All {
    $state = Load-State
    if ($state) {
        foreach ($p in @('bridge','bot','fixture')) {
            $pidValue = [int]$state.$p
            if ($pidValue -gt 0) {
                $proc = Get-Process -Id $pidValue -ErrorAction SilentlyContinue
                if ($proc) { Stop-Process -Id $pidValue -Force; Write-Host "stopped $p ($pidValue)" }
            }
        }
    }
    Remove-Item -LiteralPath $StateFile -ErrorAction SilentlyContinue
}

function Show-Status {
    foreach ($p in @($BridgePort, $ClaimPort, $FixturePort)) {
        $listening = Test-Port $p
        Write-Host ("port {0}: {1}" -f $p, $(if ($listening) { 'listening' } else { 'down' }))
    }
    try { $h = Invoke-RestMethod -Uri "http://127.0.0.1:$BridgePort/health" -TimeoutSec 5; Write-Host "bridge health: $($h.status)" } catch { Write-Host 'bridge health: unavailable' }
    try { $h = Invoke-RestMethod -Uri "https://esme-indexer-a.ootle.tari.com/health" -TimeoutSec 10; Write-Host "indexer: $($h.version) epoch $($h.current_epoch)" } catch { Write-Host 'indexer: unavailable' }
}

function New-Session {
    if (-not (Test-Port $FixturePort) -or -not (Test-Port $BridgePort) -or -not (Test-Port $ClaimPort)) {
        throw 'fixture services are not running; run with -StartServices first'
    }
    $updateId = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    # Results accumulate across runs; clear them so only THIS run's sendMessage is matched,
    # never a stale (possibly expired) session URL from an earlier invocation.
    try { Invoke-RestMethod -Method Delete -Uri "http://127.0.0.1:$FixturePort/fixture/results" -TimeoutSec 5 | Out-Null } catch { }
    $body = @{
        update_id = $updateId
        message = @{
            message_id = $updateId
            date = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
            from = @{ id = $TelegramUser; is_bot = $false; first_name = 'TestUser'; username = 'testuser' }
            chat = @{ id = [long]$ChatId; type = 'supergroup'; title = 'M16 Fixture Group' }
            text = '/join'
            entities = @(@{ offset = 0; length = 5; type = 'bot_command' })
        }
    } | ConvertTo-Json -Depth 8
    Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$FixturePort/fixture/inject" -ContentType 'application/json' -Body $body | Out-Null

    $url = $null
    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Seconds 1
        $calls = Invoke-RestMethod -Uri "http://127.0.0.1:$FixturePort/fixture/results" -TimeoutSec 5
        foreach ($call in $calls) {
            if ($call.method -ne 'sendMessage') { continue }
            $text = [string]$call.params.text
            foreach ($m in [regex]::Matches($text, 'https?://[^\s]+')) {
                if ($m.Value -match 'bot_session=') { $url = $m.Value; break }
            }
            if ($url) { break }
        }
        if ($url) { break }
    }
    if (-not $url) { throw 'fixture bot did not emit a session URL within 20 seconds' }
    Write-Host ''
    Write-Host 'OPEN THIS URL IN CHROME (Sapient profile):'
    Write-Host $url -ForegroundColor Cyan
    Write-Host ''
    Write-Host 'Session TTL: 600 seconds. No wallet approval has been requested.'
}

if ($StartServices) { Start-All }
elseif ($StopServices) { Stop-All }
elseif ($Status) { Show-Status }
else { New-Session }
