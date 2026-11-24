# Starts the experimental GGBP-1 v3 L1 tXTM lab, fully separate from the M16 Sapient fixture:
#
#   bridge  127.0.0.1:7801  - registers ONLY the experimental Minotari XTM gate (Esmeralda L1),
#                             GG_GGBP1_TEST=1, no bot key, no access plane: every verdict is a
#                             labelled non-authorizing test result.
#   https   127.0.0.1:7443  - local self-signed TLS termination proxy (Universe's embedded dApp
#                             browser requires an HTTPS origin). No certificate is installed into
#                             any certificate store; the browser warning is expected.
#
# The user's real L1 tXTM wallet interaction happens ONLY through Tari Universe's embedded
# browser, and only when the user explicitly approves the proof request.
param(
    [switch]$StopServices,
    [switch]$Status
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$StateDir = if ($env:GG_GGBP1_STATE_DIR) { $env:GG_GGBP1_STATE_DIR } else { 'D:\OpenCodeTemp\ggbp1-lab' }
$BridgeBin = if ($env:GG_BRIDGE_BIN) { $env:GG_BRIDGE_BIN } else { 'D:\GG-Target\debug\m16-fixture-bridge.exe' }
$BridgePort = 7801
$HttpsPort = 7443
$CertDir = Join-Path $StateDir 'tls'
$Node = (Get-Command node -ErrorAction SilentlyContinue).Source
$Openssl = 'C:\Program Files\Git\usr\bin\openssl.exe'

if (-not (Test-Path -LiteralPath $BridgeBin)) { throw "missing bridge binary: $BridgeBin (build tools\m16-fixture-bridge first)" }
if (-not $Node) { throw 'node not found on PATH' }
New-Item -ItemType Directory -Path $StateDir -Force | Out-Null

function Test-Port([int]$Port) {
    $c = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    return [bool]$c
}

if ($StopServices) {
    foreach ($p in @($HttpsPort, $BridgePort)) {
        Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
            Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
            Write-Host "stopped listener on $p (pid $($_.OwningProcess))"
        }
    }
    return
}

if ($Status) {
    foreach ($p in @($BridgePort, $HttpsPort)) {
        Write-Host "port ${p}: $(if (Test-Port $p) { 'listening' } else { 'down' })"
    }
    if (Test-Port $BridgePort) {
        try { (Invoke-RestMethod -Uri "http://127.0.0.1:$BridgePort/lab/gates" -TimeoutSec 5) | ConvertTo-Json -Compress | Write-Host } catch { Write-Host 'gates: unavailable' }
    }
    return
}

if (-not (Test-Path $Openssl)) { throw "openssl not found at $Openssl (needed for the local self-signed certificate)" }
New-Item -ItemType Directory -Path $CertDir -Force | Out-Null
$cert = Join-Path $CertDir 'cert.pem'
$key = Join-Path $CertDir 'key.pem'
if (-not (Test-Path $cert) -or -not (Test-Path $key)) {
    & $Openssl req -x509 -newkey rsa:2048 -keyout $key -out $cert -days 30 -nodes `
        -subj '/CN=127.0.0.1' -addext 'subjectAltName=IP:127.0.0.1' 2>$null
    if (-not (Test-Path $cert)) { throw 'self-signed certificate generation failed' }
    Write-Host "generated local self-signed certificate in $CertDir (NOT installed into any certificate store)"
}

if (-not (Test-Port $BridgePort)) {
    $env:GG_BRIDGE_BIND = "127.0.0.1:$BridgePort"
    $env:GG_BRIDGE_ORIGINS = "http://127.0.0.1:$BridgePort,https://127.0.0.1:$HttpsPort"
    $env:GG_BRIDGE_RELYING_SITE = "https://127.0.0.1:$HttpsPort"
    $env:GG_GATE_ID = 'ggbp1lab'
    $env:GG_GATE_NETWORK_HEX = '26'
    $env:GG_GATE_THRESHOLD = '1000000'
    $env:GG_INDEXER_ENDPOINT = 'https://esme-indexer-a.ootle.tari.com/'
    $env:GG_GGBP1_TEST = '1'
    $env:GG_GGBP1_GATE_ID = 'ggbp1xtm'
    $env:GG_GGBP1_THRESHOLD_MICRO = '1000000'
    Remove-Item Env:GG_BOT_KEY -ErrorAction SilentlyContinue
    Remove-Item Env:GG_BOT_AUTH_DB_DIR -ErrorAction SilentlyContinue
    $proc = Start-Process -FilePath $BridgeBin -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $StateDir 'bridge.stdout.log') `
        -RedirectStandardError (Join-Path $StateDir 'bridge.stderr.log') -WorkingDirectory $RepoRoot
    Start-Sleep -Seconds 2
    Write-Host "GGBP-1 bridge started (pid $($proc.Id)) on 127.0.0.1:$BridgePort"
} else {
    Write-Host "GGBP-1 bridge already listening on $BridgePort"
}

if (-not (Test-Port $HttpsPort)) {
    $pp = Start-Process -FilePath $Node -ArgumentList @((Join-Path $RepoRoot 'scripts\ggbp1-https-proxy.js'), '--port', "$HttpsPort", '--target', "http://127.0.0.1:$BridgePort", '--cert', $cert, '--key', $key) -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $StateDir 'proxy.stdout.log') `
        -RedirectStandardError (Join-Path $StateDir 'proxy.stderr.log') -WorkingDirectory $RepoRoot
    Start-Sleep -Seconds 2
    Write-Host "GGBP-1 HTTPS proxy started (pid $($pp.Id)) on https://127.0.0.1:$HttpsPort/lab"
} else {
    Write-Host "HTTPS proxy already listening on $HttpsPort"
}

Write-Host ''
Write-Host 'Embedded Tari Universe test (when YOU are ready):'
Write-Host '  1. Open Tari Universe -> Ootle L2 Apps and add the dApp URL https://127.0.0.1:7443/lab'
Write-Host '     (accept the local self-signed certificate warning; nothing is installed into any store).'
Write-Host '  2. The lab shows the experimental gate ggbp1xtm (Esmeralda L1 tXTM).'
Write-Host '  3. Press START GGBP-1 TEST only when you are ready to approve the balance proof in the wallet.'
Write-Host '  The verdict is always a labelled test result: authorized=false, no session, no access grant.'
