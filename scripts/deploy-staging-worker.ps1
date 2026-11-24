$ErrorActionPreference = 'Stop'

$VPS = 'ubuntu@40.160.90.9'
$KEY = "$env:USERPROFILE\.ssh\ghostgate_vps"
$WRANGLER_CONFIG = 'wrangler.staging.toml'

Write-Host "`n=== Step 1: Deploy Worker ===" -ForegroundColor Cyan
Set-Location "$PSScriptRoot\..\cloudflare"
npx wrangler deploy --config $WRANGLER_CONFIG
if ($LASTEXITCODE -ne 0) { throw "Worker deployment failed" }
Write-Host "Worker deployed." -ForegroundColor Green

Write-Host "`n=== Step 2: Set Worker secrets from VPS ===" -ForegroundColor Cyan
$secrets = @('GG_COORDINATOR_TOKEN', 'GG_VERIFIER_TOKEN', 'GG_VERIFIER_REQUEST_KEY', 'GG_VERIFIER_RESPONSE_KEY')
foreach ($name in $secrets) {
    Write-Host "  Setting $name..."
    $value = ssh -i $KEY -o ConnectTimeout=15 $VPS "sudo grep -oP '(?<=^${name}=).+' /opt/ghost-gate/etc/.wrangler-secrets"
    if (-not $value) { throw "Could not read $name from VPS" }
    $value | npx wrangler secret put $name --config $WRANGLER_CONFIG
    if ($LASTEXITCODE -ne 0) { throw "Failed to set $name" }
}
Write-Host "All 4 Worker secrets set." -ForegroundColor Green

Write-Host "`n=== Step 3: Verify Worker health ===" -ForegroundColor Cyan
Start-Sleep -Seconds 5
$health = Invoke-RestMethod -Uri 'https://ghost-gate-staging.gsxrspartan.workers.dev/_edge/health' -TimeoutSec 10
$health | ConvertTo-Json
Write-Host "`nDone. Worker is live." -ForegroundColor Green
