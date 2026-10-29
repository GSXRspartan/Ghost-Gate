[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $WorkerOrigin,
    [Parameter(Mandatory)] [string] $BridgeOrigin,
    [Parameter(Mandatory)] [string] $ClaimOrigin,
    [string] $Destination = (Join-Path $PSScriptRoot "..\\staging-web")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ExactHttpsOrigin([string] $Value, [string] $Name) {
    $uri = $null
    if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref] $uri) -or
        $uri.Scheme -ne "https" -or $uri.UserInfo -or $uri.Query -or $uri.Fragment -or
        $uri.AbsolutePath -ne "/") {
        throw "$Name must be one exact HTTPS origin with no path, credentials, query, or fragment."
    }
    return $uri.GetLeftPart([UriPartial]::Authority)
}

$worker = Get-ExactHttpsOrigin $WorkerOrigin "WorkerOrigin"
$bridge = Get-ExactHttpsOrigin $BridgeOrigin "BridgeOrigin"
$claim = Get-ExactHttpsOrigin $ClaimOrigin "ClaimOrigin"
$source = Join-Path $PSScriptRoot "..\\web"

if (Test-Path -LiteralPath $Destination) {
    throw "Destination already exists: $Destination. Refusing to overwrite a staging asset directory."
}

New-Item -ItemType Directory -Path $Destination | Out-Null
Copy-Item -Path (Join-Path $source "*") -Destination $Destination -Recurse

$placeholder = @'
<!-- <meta name="gg-trusted-bridges" content="https://bridge.your-tunnel-domain.example"> -->
<!-- <meta name="gg-trusted-claims" content="https://claim.your-tunnel-domain.example"> -->
'@
$replacement = "<meta name=`"gg-trusted-bridges`" content=`"$bridge`">`n<meta name=`"gg-trusted-claims`" content=`"$claim`">"
foreach ($relativeJoin in @("telegram\\join.html", "telegram\\join\\index.html")) {
    $join = Join-Path $Destination $relativeJoin
    $html = [IO.File]::ReadAllText($join)
    if (-not $html.Contains($placeholder)) {
        throw "The trusted-origin placeholders were not found in $join; no asset was modified."
    }
    [IO.File]::WriteAllText($join, $html.Replace($placeholder, $replacement), [Text.UTF8Encoding]::new($false))
}

Write-Output "Prepared staging assets at $Destination for $worker."
