# Ghost Gate M6+ — process-isolation integration test
#
# Tests the bridge binary's bot-session admission routes in a process-isolated way:
# the bridge binary runs as a separate process; this script sends HMAC-authenticated
# HTTP requests directly to it, verifying session creation without a live wallet.
#
# KNOWN LIMITATION (documented, not a workaround):
#   The proof step (POST /v1/bot/sessions/:id/proof) requires a live walletd. That
#   step is exercised by the unit tests in ghost-gate-bridge/src/server.rs with mock
#   wallets. This script covers everything that can be tested without one:
#     - bridge starts and reports healthy
#     - bot session creation returns 201 with a session_id
#     - a replay (same update_id) is refused with 400/409
#     - a tampered HMAC is refused with 401
#     - a request from a non-loopback peer is refused (tested by bridge internal logic)
#
# Prerequisites:
#   - ghost-gate-bridge binary compiled (see step 1 or run manually first)
#   - No process already on port 7788 (the test port)
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\scripts\test-m6-process-isolation.ps1
#
# To skip the build step (if the binary is already compiled):
#   powershell -ExecutionPolicy Bypass -File .\scripts\test-m6-process-isolation.ps1 -SkipBuild

param(
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$REPO_ROOT = Split-Path $PSScriptRoot -Parent

# ── Binary paths ───────────────────────────────────────────────────────────────────────────────
# The debug binary is used for testing (faster compile; release is for production).
$BridgeBinary = "$REPO_ROOT\_cargo-target-native\debug\ghost-gate-bridge.exe"

# ── Test parameters ────────────────────────────────────────────────────────────────────────────
$TestPort    = 7788
$BridgeUrl   = "http://127.0.0.1:$TestPort"
$TestBotKey  = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"  # 64 hex = 32 bytes
$PolicyHash  = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"  # 64 hex
$ResourceAddr = "resource_0101010101010101010101010101010101010101010101010101010101010101"
$GateId      = "test-gate"
$ChatId      = "-1001234567890"

$TestDir     = Join-Path $env:TEMP "gg-isolation-test-$(Get-Date -Format 'yyyyMMddHHmmss')"
$AuthDbDir   = Join-Path $TestDir "auth-db"
$SessionDir  = Join-Path $TestDir "sessions"

$PASS = 0
$FAIL = 0
$bridgeProcess = $null

# ── HMAC helper ────────────────────────────────────────────────────────────────────────────────
function HexToBytes {
    param([string]$Hex)
    $b = [byte[]]::new($Hex.Length / 2)
    for ($i = 0; $i -lt $Hex.Length; $i += 2) {
        $b[$i / 2] = [System.Convert]::ToByte($Hex.Substring($i, 2), 16)
    }
    return $b
}

function Compute-BotHmac {
    param([string]$KeyHex, [byte[]]$Domain, [string]$BodyJson)
    $keyBytes  = HexToBytes $KeyHex
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($BodyJson)
    $data      = $Domain + $bodyBytes
    $hmac      = [System.Security.Cryptography.HMACSHA256]::new($keyBytes)
    $hash      = $hmac.ComputeHash($data)
    $hmac.Dispose()
    return [System.BitConverter]::ToString($hash).Replace('-', '').ToLower()
}

# Domain bytes: match bot_session_interface.rs exactly (null bytes as separators)
$CreateDomain = [System.Text.Encoding]::UTF8.GetBytes("ghost-gate/bot-session/v1`0POST`0/v1/bot/sessions`0")
$RedeemDomain = [System.Text.Encoding]::UTF8.GetBytes("ghost-gate/bot-redeem/v1`0POST`0/v1/bot/sessions/redeem`0")

function Assert-Pass {
    param([string]$Name, [scriptblock]$Check)
    try {
        & $Check
        Write-Host "  [PASS] $Name" -ForegroundColor Green
        $script:PASS++
    } catch {
        Write-Host "  [FAIL] $Name — $($_.Exception.Message)" -ForegroundColor Red
        $script:FAIL++
    }
}

function Post-BotSession {
    param([string]$BodyJson, [string]$AuthHeader)
    $resp = Invoke-WebRequest -Uri "$BridgeUrl/v1/bot/sessions" `
        -Method POST `
        -ContentType "application/json" `
        -Headers @{ Authorization = $AuthHeader } `
        -Body $BodyJson `
        -UseBasicParsing `
        -ErrorAction SilentlyContinue
    return $resp
}

# ── Step 1: Build the bridge binary ───────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== Ghost Gate M6+ Process-Isolation Test ===" -ForegroundColor Cyan
Write-Host ""

if (-not $SkipBuild) {
    Write-Host "Step 1: Building ghost-gate-bridge (isolated CARGO_TARGET_DIR)..." -ForegroundColor Yellow
    $env:CARGO_TARGET_DIR = "$REPO_ROOT\_cargo-target-native"
    $buildOut = & cargo build -p ghost-gate-walletd --bin ghost-gate-bridge 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Build FAILED:" -ForegroundColor Red
        $buildOut | Write-Host
        exit 1
    }
    Write-Host "  Build succeeded." -ForegroundColor Green
} else {
    Write-Host "Step 1: Skipping build (--SkipBuild)." -ForegroundColor Yellow
}

if (-not (Test-Path $BridgeBinary)) {
    Write-Host "ERROR: bridge binary not found at $BridgeBinary" -ForegroundColor Red
    Write-Host "       Run without -SkipBuild, or compile manually:" -ForegroundColor Red
    Write-Host "       `$env:CARGO_TARGET_DIR = `"$REPO_ROOT\_cargo-target-native`"; cargo build -p ghost-gate-walletd --bin ghost-gate-bridge"
    exit 1
}

# ── Step 2: Create test directories ───────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Step 2: Creating test directories..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $AuthDbDir | Out-Null
New-Item -ItemType Directory -Force -Path $SessionDir | Out-Null
Write-Host "  Auth DB:   $AuthDbDir"
Write-Host "  Sessions:  $SessionDir"

# ── Step 3: Start the bridge ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Step 3: Starting bridge on $BridgeUrl ..." -ForegroundColor Yellow

$env:GG_BRIDGE_BIND       = "127.0.0.1:$TestPort"
$env:GG_BRIDGE_ORIGINS    = $BridgeUrl
$env:GG_BRIDGE_GATES      = "$GateId=:${ResourceAddr}:10:0:tTARI"
$env:GG_OOTLE_NETWORK     = "0x26"
$env:GG_BOT_KEY           = $TestBotKey
$env:GG_BOT_AUTH_DB_DIR   = $AuthDbDir
$env:GG_BOT_GATE_ID       = $GateId
$env:GG_BOT_POLICY_HASH   = $PolicyHash
$env:GG_BOT_NETWORK       = "0x26"
$env:GG_BOT_RESOURCE      = $ResourceAddr
$env:GG_BOT_THRESHOLD     = "10"
$env:GG_BOT_CHAT_ID       = $ChatId

$bridgeProcess = Start-Process -FilePath $BridgeBinary `
    -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput "$TestDir\bridge-stdout.log" `
    -RedirectStandardError  "$TestDir\bridge-stderr.log"

# Remove env vars so they don't leak to other processes
Remove-Item Env:\GG_BRIDGE_BIND       -ErrorAction SilentlyContinue
Remove-Item Env:\GG_BRIDGE_ORIGINS    -ErrorAction SilentlyContinue
Remove-Item Env:\GG_BRIDGE_GATES      -ErrorAction SilentlyContinue
Remove-Item Env:\GG_OOTLE_NETWORK     -ErrorAction SilentlyContinue
Remove-Item Env:\GG_BOT_KEY           -ErrorAction SilentlyContinue
Remove-Item Env:\GG_BOT_AUTH_DB_DIR   -ErrorAction SilentlyContinue
Remove-Item Env:\GG_BOT_GATE_ID       -ErrorAction SilentlyContinue
Remove-Item Env:\GG_BOT_POLICY_HASH   -ErrorAction SilentlyContinue
Remove-Item Env:\GG_BOT_NETWORK       -ErrorAction SilentlyContinue
Remove-Item Env:\GG_BOT_RESOURCE      -ErrorAction SilentlyContinue
Remove-Item Env:\GG_BOT_THRESHOLD     -ErrorAction SilentlyContinue
Remove-Item Env:\GG_BOT_CHAT_ID       -ErrorAction SilentlyContinue

# Poll for health (up to 10 seconds)
$ready = $false
for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Milliseconds 500
    if ($bridgeProcess.HasExited) {
        Write-Host "  Bridge exited early (code $($bridgeProcess.ExitCode))" -ForegroundColor Red
        Write-Host "  stderr:" -ForegroundColor Red
        Get-Content "$TestDir\bridge-stderr.log" -ErrorAction SilentlyContinue | Write-Host
        exit 1
    }
    try {
        $health = Invoke-WebRequest -Uri "$BridgeUrl/health" -UseBasicParsing -ErrorAction Stop
        if ($health.StatusCode -eq 200) { $ready = $true; break }
    } catch { }
}

if (-not $ready) {
    Write-Host "  Bridge did not become healthy within 10 s" -ForegroundColor Red
    if ($bridgeProcess -and -not $bridgeProcess.HasExited) { $bridgeProcess.Kill() }
    exit 1
}
Write-Host "  Bridge is healthy." -ForegroundColor Green

# ── Step 4: Run test assertions ────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Step 4: Running tests..." -ForegroundColor Yellow
Write-Host ""

# --- T1: Health ---
Assert-Pass "T1: /health returns 200" {
    $r = Invoke-WebRequest -Uri "$BridgeUrl/health" -UseBasicParsing -ErrorAction Stop
    if ($r.StatusCode -ne 200) { throw "Expected 200, got $($r.StatusCode)" }
}

# --- T2: Bot session creation returns 201 ---
$sentUnix = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$createBody = "{`"update_id`":100001,`"telegram_user_id`":99001,`"telegram_chat_id`":$ChatId,`"gate_id`":`"$GateId`",`"policy_hash`":`"$PolicyHash`",`"sent_unix`":$sentUnix}"
$sig = Compute-BotHmac -KeyHex $TestBotKey -Domain $CreateDomain -BodyJson $createBody
$sessionId = $null

Assert-Pass "T2: POST /v1/bot/sessions returns 201 with session_id" {
    $r = Invoke-WebRequest -Uri "$BridgeUrl/v1/bot/sessions" `
        -Method POST -ContentType "application/json" `
        -Headers @{ Authorization = "GG-Bot-HMAC $sig" } `
        -Body $createBody -UseBasicParsing -ErrorAction Stop
    if ($r.StatusCode -ne 201) { throw "Expected 201, got $($r.StatusCode)" }
    $json = $r.Content | ConvertFrom-Json
    if ([string]::IsNullOrEmpty($json.session_id)) { throw "No session_id in response" }
    if ($json.expires_unix -le $sentUnix) { throw "expires_unix ($($json.expires_unix)) not after sent_unix ($sentUnix)" }
    $script:sessionId = $json.session_id
    Write-Host "    session_id: $($json.session_id)" -ForegroundColor DarkGray
    Write-Host "    expires_unix: $($json.expires_unix)" -ForegroundColor DarkGray
}

function Get-HttpErrorCode {
    param($Err)
    # Works on both PS5.1 (.NET Framework WebException) and PS7 (HttpResponseException)
    try {
        $r = $Err.Exception.Response
        if ($null -ne $r) { return [int]$r.StatusCode }
    } catch {}
    return 0
}

# --- T3: Replay (same update_id) is refused ---
Assert-Pass "T3: Replay of same update_id refused (409 or 400)" {
    try {
        $r = Invoke-WebRequest -Uri "$BridgeUrl/v1/bot/sessions" `
            -Method POST -ContentType "application/json" `
            -Headers @{ Authorization = "GG-Bot-HMAC $sig" } `
            -Body $createBody -UseBasicParsing -ErrorAction Stop
        throw "Expected non-2xx for replay, got $($r.StatusCode)"
    } catch {
        $code = Get-HttpErrorCode $_
        if ($code -notin @(400, 409)) { throw "Expected 400 or 409 for replay, got $code" }
    }
}

# --- T4: Tampered HMAC is refused (401) ---
Assert-Pass "T4: Tampered HMAC signature refused (401)" {
    $badSig = $sig.Substring(0, 60) + "00000000"  # corrupt last 4 bytes of hex
    try {
        $r2 = Invoke-WebRequest -Uri "$BridgeUrl/v1/bot/sessions" `
            -Method POST -ContentType "application/json" `
            -Headers @{ Authorization = "GG-Bot-HMAC $badSig" } `
            -Body $createBody -UseBasicParsing -ErrorAction Stop
        throw "Expected 401 for tampered HMAC, got $($r2.StatusCode)"
    } catch {
        $code = Get-HttpErrorCode $_
        if ($code -ne 401) { throw "Expected 401, got $code" }
    }
}

# --- T5: Different update_id creates a second session ---
$sentUnix2 = $sentUnix + 1
$createBody2 = "{`"update_id`":100002,`"telegram_user_id`":99002,`"telegram_chat_id`":$ChatId,`"gate_id`":`"$GateId`",`"policy_hash`":`"$PolicyHash`",`"sent_unix`":$sentUnix2}"
$sig2 = Compute-BotHmac -KeyHex $TestBotKey -Domain $CreateDomain -BodyJson $createBody2

Assert-Pass "T5: Second (different) update_id creates a new session" {
    $r = Invoke-WebRequest -Uri "$BridgeUrl/v1/bot/sessions" `
        -Method POST -ContentType "application/json" `
        -Headers @{ Authorization = "GG-Bot-HMAC $sig2" } `
        -Body $createBody2 -UseBasicParsing -ErrorAction Stop
    if ($r.StatusCode -ne 201) { throw "Expected 201, got $($r.StatusCode)" }
}

# --- T6: Wrong policy_hash is refused ---
$wrongHash = "0000000000000000000000000000000000000000000000000000000000000000"
$createBodyWrong = "{`"update_id`":100003,`"telegram_user_id`":99003,`"telegram_chat_id`":$ChatId,`"gate_id`":`"$GateId`",`"policy_hash`":`"$wrongHash`",`"sent_unix`":$sentUnix}"
$sigWrong = Compute-BotHmac -KeyHex $TestBotKey -Domain $CreateDomain -BodyJson $createBodyWrong

Assert-Pass "T6: Wrong policy_hash refused (400)" {
    try {
        $r = Invoke-WebRequest -Uri "$BridgeUrl/v1/bot/sessions" `
            -Method POST -ContentType "application/json" `
            -Headers @{ Authorization = "GG-Bot-HMAC $sigWrong" } `
            -Body $createBodyWrong -UseBasicParsing -ErrorAction Stop
        throw "Expected 400 for wrong policy_hash, got $($r.StatusCode)"
    } catch {
        $code = Get-HttpErrorCode $_
        if ($code -ne 400) { throw "Expected 400, got $code" }
    }
}

# --- T7: Redeem of non-existent session is refused ---
$redeemBody = "{`"session_id`":`"not-a-real-session`",`"sent_unix`":$sentUnix}"
$redeemSig  = Compute-BotHmac -KeyHex $TestBotKey -Domain $RedeemDomain -BodyJson $redeemBody

Assert-Pass "T7: Redeem of non-existent session refused (404 or 400)" {
    try {
        $r = Invoke-WebRequest -Uri "$BridgeUrl/v1/bot/sessions/redeem" `
            -Method POST -ContentType "application/json" `
            -Headers @{ Authorization = "GG-Bot-HMAC $redeemSig" } `
            -Body $redeemBody -UseBasicParsing -ErrorAction Stop
        throw "Expected non-2xx for bad session_id, got $($r.StatusCode)"
    } catch {
        $code = Get-HttpErrorCode $_
        if ($code -notin @(400, 404)) { throw "Expected 400 or 404, got $code" }
    }
}

# ── Step 5: Stop bridge and report ────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Step 5: Stopping bridge..." -ForegroundColor Yellow
if ($bridgeProcess -and -not $bridgeProcess.HasExited) {
    $bridgeProcess.Kill()
    $bridgeProcess.WaitForExit(3000) | Out-Null
}

# Clean up test directories
Remove-Item -Recurse -Force $TestDir -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== Results ===" -ForegroundColor Cyan
if ($FAIL -eq 0) {
    Write-Host "  $PASS passed, 0 failed — ALL PASS" -ForegroundColor Green
} else {
    Write-Host "  $PASS passed, $FAIL failed" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== KNOWN GAPS (require live walletd) ===" -ForegroundColor Yellow
Write-Host "  - POST /v1/bot/sessions/:id/proof (wallet challenge + signature)"
Write-Host "  - POST /v1/bot/sessions/redeem   (of a Verified session after proof)"
Write-Host "  - Full bot binary + bridge binary E2E with real Telegram updates"
Write-Host "  These are covered by ghost-gate-bridge/src/server.rs unit tests (mock wallet)"
Write-Host "  and by ghost-gate-telegram/src/main.rs unit tests (mock bridge + mock Telegram)."
Write-Host ""

if ($FAIL -gt 0) { exit 1 }
exit 0
