[CmdletBinding()]
param(
    [ValidateRange(1, 120)]
    [int]$TimeoutSec = 20
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$targetOotleVersion = "0.49.2"
$targetNetworkName = "esmeralda"
$targetNetworkByte = 38

$indexers = @(
    [pscustomobject]@{ Name = "A"; BaseUrl = "https://esme-indexer-a.ootle.tari.com" },
    [pscustomobject]@{ Name = "B"; BaseUrl = "https://esme-indexer-b.ootle.tari.com" }
)

$nativeResource = "resource_0101010101010101010101010101010101010101010101010101010101010101"
$builtinFaucet = "component_0102030000000000000000000000000000000000000000000000000000000000"

function Invoke-JsonGet {
    param([Parameter(Mandatory)][string]$Uri)

    try {
        $response = Invoke-WebRequest -UseBasicParsing -Method Get -Uri $Uri -TimeoutSec $TimeoutSec -Headers @{
            Accept = "application/json"
        }
        $body = $response.Content | ConvertFrom-Json
        [pscustomobject]@{
            Ok          = $true
            StatusCode  = [int]$response.StatusCode
            ContentType = [string]$response.Headers["Content-Type"]
            Body        = $body
            Error       = $null
        }
    }
    catch {
        $statusCode = $null
        if ($null -ne $_.Exception.Response) {
            try { $statusCode = [int]$_.Exception.Response.StatusCode } catch { $statusCode = $null }
        }
        [pscustomobject]@{
            Ok          = $false
            StatusCode  = $statusCode
            ContentType = $null
            Body        = $null
            Error       = $_.Exception.Message
        }
    }
}

function Get-PropertyValue {
    param(
        [AllowNull()][object]$Object,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Test-ProvenState {
    param([AllowNull()][object]$Body)

    if ($null -eq $Body) { return $false }
    $state = Get-PropertyValue -Object $Body -Name "state"
    $up = Get-PropertyValue -Object $state -Name "up"
    $verified = Get-PropertyValue -Object $Body -Name "verified"
    $proof = Get-PropertyValue -Object $Body -Name "proof"
    return ($null -ne $up -and $verified -eq $true -and $null -ne $proof)
}

function Find-IdentityFields {
    param(
        [AllowNull()][object]$Value,
        [string]$Path = "root",
        [int]$Depth = 0
    )

    if ($null -eq $Value -or $Depth -gt 8) { return @() }
    if ($Value -is [string] -or $Value.GetType().IsPrimitive -or $Value -is [decimal]) { return @() }

    $found = @()
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [pscustomobject]) {
        $index = 0
        foreach ($item in $Value) {
            $found += @(Find-IdentityFields -Value $item -Path "$Path[$index]" -Depth ($Depth + 1))
            $index++
        }
        return $found
    }

    foreach ($property in $Value.PSObject.Properties) {
        $name = $property.Name.ToLowerInvariant()
        $childPath = "$Path.$($property.Name)"
        $child = $property.Value
        $isIdentity = $name -match '^(sidechain_?id|genesis.*(hash|id|root))$'
        if ($isIdentity -and $null -ne $child -and -not [string]::IsNullOrWhiteSpace([string]$child)) {
            $serialized = if ($child -is [string] -or $child.GetType().IsPrimitive) {
                [string]$child
            }
            else {
                $child | ConvertTo-Json -Compress -Depth 12
            }
            $found += [pscustomobject]@{
                Name  = $name
                Path  = $childPath
                Value = $serialized
            }
        }

        if ($null -ne $child -and $child -isnot [string] -and -not $child.GetType().IsPrimitive) {
            $found += @(Find-IdentityFields -Value $child -Path $childPath -Depth ($Depth + 1))
        }
    }
    return $found
}

function Format-Result {
    param([bool]$Passed)
    if ($Passed) { return "PASS" }
    return "BLOCKED"
}

$results = foreach ($indexer in $indexers) {
    $info = Invoke-JsonGet -Uri "$($indexer.BaseUrl)/info"
    $network = Invoke-JsonGet -Uri "$($indexer.BaseUrl)/network"
    $ready = Invoke-JsonGet -Uri "$($indexer.BaseUrl)/wait-until-ready"
    $native = Invoke-JsonGet -Uri "$($indexer.BaseUrl)/substates/$nativeResource`?include_proof=true"
    $faucet = Invoke-JsonGet -Uri "$($indexer.BaseUrl)/substates/$builtinFaucet`?include_proof=true"
    $checkpoint = Invoke-JsonGet -Uri "$($indexer.BaseUrl)/epoch-checkpoints/latest?shard=0&include_committees=true"

    $identities = @()
    if ($info.Ok) { $identities += @(Find-IdentityFields -Value $info.Body -Path "info") }
    if ($network.Ok) { $identities += @(Find-IdentityFields -Value $network.Body -Path "network") }
    if ($checkpoint.Ok) { $identities += @(Find-IdentityFields -Value $checkpoint.Body -Path "checkpoint") }
    $identities = @($identities | Sort-Object Name, Value -Unique)

    [pscustomobject]@{
        Name             = $indexer.Name
        BaseUrl          = $indexer.BaseUrl
        InfoOk           = $info.Ok
        NetworkOk        = $network.Ok
        ReadyOk          = $ready.Ok
        Version          = if ($info.Ok) { [string](Get-PropertyValue -Object $info.Body -Name "version") } else { $null }
        Network          = if ($network.Ok) { [string](Get-PropertyValue -Object $network.Body -Name "network") } else { $null }
        NetworkByte      = if ($network.Ok) { Get-PropertyValue -Object $network.Body -Name "network_byte" } else { $null }
        Epoch            = if ($network.Ok) { Get-PropertyValue -Object $network.Body -Name "epoch" } else { $null }
        NativeOk         = ($native.Ok -and (Test-ProvenState -Body $native.Body))
        FaucetOk         = ($faucet.Ok -and (Test-ProvenState -Body $faucet.Body))
        CheckpointOk     = $checkpoint.Ok
        Identities       = $identities
        InfoError        = $info.Error
        NetworkError     = $network.Error
        NativeError      = $native.Error
        FaucetError      = $faucet.Error
        CheckpointError  = $checkpoint.Error
    }
}

$bothReachable = @($results | Where-Object { -not ($_.InfoOk -and $_.NetworkOk -and $_.ReadyOk) }).Count -eq 0
$networkAgreement = $bothReachable -and
    @($results.Network | Sort-Object -Unique).Count -eq 1 -and
    @($results.NetworkByte | Sort-Object -Unique).Count -eq 1 -and
    @($results.Epoch | Sort-Object -Unique).Count -eq 1
$networkMatchesTarget = $networkAgreement -and
    @($results | Where-Object {
        $_.Network.ToLowerInvariant() -ne $targetNetworkName -or
        [int]$_.NetworkByte -ne $targetNetworkByte
    }).Count -eq 0
$versionAgreement = $bothReachable -and @($results.Version | Sort-Object -Unique).Count -eq 1
$versionsMatchTarget = $versionAgreement -and
    @($results | Where-Object { $_.Version -ne $targetOotleVersion }).Count -eq 0
$requiredState = @($results | Where-Object { -not ($_.NativeOk -and $_.FaucetOk) }).Count -eq 0

$leftIdentity = @($results[0].Identities | ForEach-Object { "$($_.Name)=$($_.Value)" })
$rightIdentity = @($results[1].Identities | ForEach-Object { "$($_.Name)=$($_.Value)" })
$commonIdentity = @($leftIdentity | Where-Object { $rightIdentity -contains $_ } | Sort-Object -Unique)
$identitySafe = $leftIdentity.Count -gt 0 -and $rightIdentity.Count -gt 0 -and $commonIdentity.Count -gt 0

$overall = $bothReachable -and $networkAgreement -and $networkMatchesTarget -and
    $versionAgreement -and $versionsMatchTarget -and $requiredState -and $identitySafe

Write-Output "Esmeralda Stage 3B readiness (target Ootle $targetOotleVersion)"
foreach ($result in $results) {
    $identity = if ($result.Identities.Count -gt 0) {
        ($result.Identities | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ","
    }
    else {
        "none"
    }
    Write-Output ("{0}: info={1} ready={2} network={3}/{4} epoch={5} version={6} native={7} faucet={8} identity={9}" -f
        $result.Name,
        (Format-Result -Passed $result.InfoOk),
        (Format-Result -Passed $result.ReadyOk),
        $result.Network,
        $result.NetworkByte,
        $result.Epoch,
        $result.Version,
        (Format-Result -Passed $result.NativeOk),
        (Format-Result -Passed $result.FaucetOk),
        $identity)
}

Write-Output ("agreement={0} expected-network={1} target-version={2} required-state={3} genesis/sidechain-identity={4}" -f
    (Format-Result -Passed ($networkAgreement -and $versionAgreement)),
    (Format-Result -Passed $networkMatchesTarget),
    (Format-Result -Passed $versionsMatchTarget),
    (Format-Result -Passed $requiredState),
    (Format-Result -Passed $identitySafe))

if ($overall) {
    Write-Output "STAGE 3B NETWORK GATE: PASS"
    exit 0
}

Write-Output "STAGE 3B NETWORK GATE: BLOCKED"
exit 1
