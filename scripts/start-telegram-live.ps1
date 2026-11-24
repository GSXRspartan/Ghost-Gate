# Ghost Gate Telegram — live testnet startup
# Reads the bot token via hidden input (never printed, never logged).
# Runs diagnostic first, then starts the live bot if permissions check out.
#
# Prerequisites:
#   - Bridge running on 127.0.0.1:7899 (registry-backed, operator-trusted indexer)
#   - Admin running on 127.0.0.1:7811 (esmeralda-crypt app with crypt gate published)
#   - Walletd running on 127.0.0.1:5110

$ErrorActionPreference = "Stop"

$BotBinary = "$PSScriptRoot\..\\_cargo-target-native\\release\\ghost-gate-telegram.exe"
if (-not (Test-Path $BotBinary)) {
    Write-Host "ERROR: ghost-gate-telegram.exe not found at $BotBinary" -ForegroundColor Red
    Write-Host "Build it:  CARGO_TARGET_DIR=_cargo-target-native cargo build --release -p ghost-gate-telegram"
    exit 1
}

# Bot identity and target group — hardcoded to the verified test infrastructure.
$ChatId = "-1003979379260"  # Ghost Gate Test Lab (private supergroup)

# Read the bot token with hidden input.
$token = Read-Host -Prompt "Enter GG_TG_BOT_TOKEN (hidden)" -AsSecureString
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($token)
$plainToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

if ([string]::IsNullOrWhiteSpace($plainToken)) {
    Write-Host "ERROR: no token entered" -ForegroundColor Red
    exit 1
}

$env:GG_TG_BOT_TOKEN       = $plainToken
$env:GG_TG_CHAT_ID         = $ChatId
$env:GG_TG_TEST_CHAT_ID    = $ChatId          # safety gate: must equal CHAT_ID
$env:GG_BRIDGE_ENDPOINT    = "http://127.0.0.1:7899"
$env:GG_JOIN_BASE_URL       = "http://127.0.0.1:7899"
$env:GG_TG_GATE            = "crypt"
$env:GG_TG_CLAIM_PORT      = "7808"

# Step 1: diagnostic — verify bot identity and group permissions without starting the bot.
Write-Host "`n=== Telegram diagnostic ===" -ForegroundColor Cyan
$env:GG_TG_DIAGNOSE = "1"
& $BotBinary
$diagExit = $LASTEXITCODE
Remove-Item Env:\GG_TG_DIAGNOSE -ErrorAction SilentlyContinue

if ($diagExit -ne 0) {
    Write-Host "`nDiagnostic FAILED (exit $diagExit). Fix the issue before starting the bot." -ForegroundColor Red
    # Clear the token from the environment before exiting.
    Remove-Item Env:\GG_TG_BOT_TOKEN -ErrorAction SilentlyContinue
    exit 1
}

Write-Host "`nDiagnostic passed. Bot is verified as admin of the target group." -ForegroundColor Green

# Step 2: start the live testnet bot.
Write-Host "`n=== Starting live testnet bot ===" -ForegroundColor Cyan
Write-Host "  Bridge:  $($env:GG_BRIDGE_ENDPOINT)"
Write-Host "  Gate:    $($env:GG_TG_GATE)"
Write-Host "  Claim:   http://127.0.0.1:$($env:GG_TG_CLAIM_PORT)"
Write-Host "  Chat:    $ChatId (Ghost Gate Test Lab)"
Write-Host ""

$env:GG_TG_LIVE_TESTNET = "1"
& $BotBinary
