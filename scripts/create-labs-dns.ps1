[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ApiToken,
    [string] $ZoneId = '06d6832a76933976f5cfca35401e7ecc',
    [string] $AccountId = '5559a22c41edea43ef2bf6323c8c6fb6'
)

# One-time helper for the two NEW staging DNS records. It never writes the token
# to disk or to Git; pass it from your password manager at run time.
$ErrorActionPreference = 'Stop'
$headers = @{ Authorization = "Bearer $ApiToken"; 'Content-Type' = 'application/json' }
$api = 'https://api.cloudflare.com/client/v4'
$routes = @(
    @{ name = 'labs-mainnet.ghostgate.boo'; target = '30f709ca-6936-4927-9931-c4e88f06687f.cfargotunnel.com' },
    @{ name = 'labs-ggbp1.ghostgate.boo'; target = '37946028-c85e-499a-b2cf-e87133c8502d.cfargotunnel.com' }
)
foreach ($route in $routes) {
    $existing = Invoke-RestMethod -Uri "$api/zones/$ZoneId/dns_records?name=$($route.name)" -Headers $headers -TimeoutSec 30
    if ($existing.result.Count -gt 0) {
        Write-Output "$($route.name): already exists; refusing to overwrite"
        continue
    }
    $body = @{ type = 'CNAME'; name = $route.name; content = $route.target; proxied = $true; ttl = 1 } | ConvertTo-Json -Compress
    $created = Invoke-RestMethod -Method Post -Uri "$api/zones/$ZoneId/dns_records" -Headers $headers -Body $body -TimeoutSec 30
    Write-Output "$($route.name): created=$($created.success)"
}
