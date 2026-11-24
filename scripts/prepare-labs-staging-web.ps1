[CmdletBinding()]
param([string] $Destination = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
if (-not $Destination) { $Destination = Join-Path $RepoRoot "labs-staging-web" }
$Templates = Join-Path $RepoRoot "templates\labs-staging"

if (Test-Path -LiteralPath $Destination) {
    throw "Refusing to overwrite an existing staging asset directory: $Destination"
}
New-Item -ItemType Directory -Path $Destination | Out-Null
Copy-Item -Path (Join-Path $Templates "*") -Destination $Destination -Recurse
Write-Output "Prepared non-authorizing Labs staging assets at $Destination"
