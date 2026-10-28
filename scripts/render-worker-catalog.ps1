<#
Render Cloudflare's GG_GATE_CATALOG from the bridge's immutable published bindings snapshot.

This deliberately cannot read draft registry gates.  `relyingSite` is deployment-specific and is
provided separately as an exact origin map; every authorization value comes from bindings.json.

Example (run over an SSH download of the VPS snapshot, not against a public endpoint):
  .\scripts\render-worker-catalog.ps1 `
    -BindingsPath .\bindings.json `
    -OriginsPath .\staging-relying-origins.json `
    -OutputPath .\GG_GATE_CATALOG.staging.json

Origins JSON shape:
  { "tenant/gate": "https://staging.example" }
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $BindingsPath,
    [Parameter(Mandatory = $true)] [string] $OriginsPath,
    [Parameter(Mandatory = $true)] [string] $OutputPath
)

$bindings = Get-Content -Raw -LiteralPath $BindingsPath | ConvertFrom-Json
$origins = Get-Content -Raw -LiteralPath $OriginsPath | ConvertFrom-Json -AsHashtable
if ($null -eq $bindings.gates) { throw "bindings snapshot has no gates" }

$catalog = @()
foreach ($gate in $bindings.gates) {
    $key = "$($gate.application_id)/$($gate.gate_id)"
    $origin = $origins[$key]
    if ([string]::IsNullOrWhiteSpace($origin)) { throw "missing exact relying-site origin for published gate $key" }
    $uri = [Uri] $origin
    if ($uri.Scheme -ne 'https' -or $uri.AbsoluteUri.TrimEnd('/') -ne $uri.GetLeftPart([System.UriPartial]::Authority)) {
        throw "relying-site origin for $key must be an exact HTTPS origin without a path"
    }
    # The Worker-origin map is deployment input, never policy authority. A hosted gate may only
    # be exposed at the exact relying-site identity frozen in its immutable published binding.
    # This also prevents an environment-only catalog change from retargeting wallet proofs.
    if ($gate.challenge_domain -cne $uri.GetLeftPart([System.UriPartial]::Authority)) {
        throw "relying-site origin for published gate $key must exactly match its published challenge_domain"
    }
    if ($gate.use_mode -eq 'telegram') { continue }
    if ($gate.proof_mode -ne 'credential') { throw "published gate $key uses unsupported hosted proof mode $($gate.proof_mode)" }
    if ([string]::IsNullOrWhiteSpace($gate.policy_hash) -or [int64]$gate.policy_version -lt 1) {
        throw "published gate $key has no valid policy version/hash"
    }
    $catalog += [ordered]@{
        tenant = [string] $gate.application_id
        gateId = [string] $gate.gate_id
        relyingSite = $uri.GetLeftPart([System.UriPartial]::Authority)
        network = [int] $gate.network
        resourceAddress = [string] $gate.resource_address
        thresholdRaw = [string] $gate.threshold_raw
        divisibility = [int] $gate.divisibility
        proofMode = [string] $gate.proof_mode
        policyVersion = "v$($gate.policy_version)"
        policyHash = [string] $gate.policy_hash
        sessionTtlSecs = [int64] $gate.session_ttl_secs
    }
}

$catalog | ConvertTo-Json -Depth 4 | Set-Content -NoNewline -LiteralPath $OutputPath
Write-Output "Wrote $($catalog.Count) published hosted gate(s) to $OutputPath"
