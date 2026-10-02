# Copyright 2026 The Tari Project
# SPDX-License-Identifier: BSD-3-Clause

<#
.SYNOPSIS
Emits the auditable diff of the wallet minimum-value-promise change against the pinned reference.

.DESCRIPTION
The patched Ootle tree is a byte copy of tari-ootle-v0.42.0-reference with one narrow change: a
wallet output can declare the minimum value promise its bulletproof proves, which is what a
threshold access proof needs and what stock walletd hardcodes to 0.

This regenerates docs/wallet-mvp.patch from the two trees. It is the Windows-side twin of
scripts/wallet_mvp_patch.sh and emits the same plain unified-diff format, so the artifact does not
depend on which host produced it. Only the allow-list below is included, which is what keeps the
patch auditable: anything else that diverges from the reference is drift and is reported as an
error rather than silently absorbed.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# git emits UTF-8. Without this, PowerShell decodes the diff through the console's code page and the
# non-ASCII characters in the surrounding source (em dashes, arrows) become '?', which stops the hunks
# from applying to a pristine checkout.
$Utf8 = New-Object System.Text.UTF8Encoding $false
[Console]::OutputEncoding = $Utf8
$OutputEncoding = $Utf8

$RepoRoot = Split-Path -Parent $PSScriptRoot
$Workspace = Split-Path -Parent $RepoRoot
$Reference = Join-Path $Workspace 'tari-ootle-v0.42.0-reference'
$Patched = Join-Path $Workspace 'tari-ootle-v0.42.0-ghost-gate'
$Output = Join-Path $RepoRoot 'docs\wallet-mvp.patch'

if (-not (Test-Path -LiteralPath (Join-Path $Reference 'Cargo.toml'))) {
    throw "reference tree missing at $Reference"
}
if (-not (Test-Path -LiteralPath (Join-Path $Patched 'Cargo.toml'))) {
    throw "patched tree missing at $Patched"
}

# Every file the MVP change is allowed to touch.
$Files = @(
    'crates/wallet/sdk/src/apis/stealth_transfer/params.rs'
    'crates/wallet/sdk/src/apis/stealth_transfer/types.rs'
    'crates/wallet/sdk/src/apis/stealth_transfer/api.rs'
    'crates/wallet/sdk/src/apis/stealth_outputs.rs'
    'crates/wallet/sdk/src/apis/stealth_transfer/minimum_value_promise_tests.rs'
    'applications/tari_walletd/src/handlers/accounts.rs'
    'applications/tari_walletd/src/handlers/accounts/create_stealth_transfer_statement_handler_tests/mvp_integration_tests.rs'
    'utilities/traffic-sim/src/sim.rs'
)

$ReferenceMarker = 'tari-ootle-v0.42.0-reference/'
$PatchedMarker = 'tari-ootle-v0.42.0-ghost-gate/'

function ConvertTo-PatchPath([string]$line) {
    $index = $line.IndexOf(' ')
    if ($index -lt 0) { return $line }
    $head = $line.Substring(0, $index + 1)
    # git on Windows writes C-quoted paths with doubled backslashes into the ---/+++ headers. A
    # unified diff must carry plain forward-slash paths, so the quoting and escaping are undone and
    # the absolute prefix replaced with a/ or b/.
    $rest = $line.Substring($index + 1).Trim('"').Replace('\\', '/')

    if ($rest.StartsWith('/dev/null')) { return $head + '/dev/null' }

    $at = $rest.IndexOf($ReferenceMarker)
    if ($at -ge 0) { return $head + 'a/' + $rest.Substring($at + $ReferenceMarker.Length) }

    $at = $rest.IndexOf($PatchedMarker)
    if ($at -ge 0) { return $head + 'b/' + $rest.Substring($at + $PatchedMarker.Length) }

    return $line
}

function Get-NormalizedPatch([string]$relative) {
    $inReference = Join-Path $Reference $relative
    $inPatched = Join-Path $Patched $relative
    if (-not (Test-Path -LiteralPath $inReference)) { $inReference = $null }
    if (-not (Test-Path -LiteralPath $inPatched)) { $inPatched = $null }
    if ($null -eq $inReference -and $null -eq $inPatched) { return $null }
    if ($null -ne $inReference -and $null -ne $inPatched) {
        if ((Get-FileHash -LiteralPath $inReference).Hash -eq (Get-FileHash -LiteralPath $inPatched).Hash) {
            return $null
        }
    }

    # git writes diff/index headers we do not want; everything else (the hunks) is kept verbatim.
    # A file present on only one side is diffed against an empty placeholder, then its "---" side is
    # rewritten to /dev/null, which is the standard unified-diff spelling of an added file.
    $placeholder = $null
    if ($null -eq $inReference) {
        $placeholder = New-Item -ItemType File -Path (Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName()))
        $left = $placeholder.FullName
        $right = $inPatched
    }
    else {
        $left = $inReference
        $right = if ($null -eq $inPatched) { $placeholder } else { $inPatched }
        if ($null -eq $inPatched) {
            $placeholder = New-Item -ItemType File -Path (Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName()))
            $right = $placeholder.FullName
        }
    }

    # autocrlf/safecrlf off: this compares bytes, and the warning git otherwise prints about line
    # endings is noise that would otherwise be captured alongside the diff. Stderr goes to a file so
    # only the diff itself reaches $lines.
    $stderr = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
    $lines = & git -c core.autocrlf=false -c core.safecrlf=false diff --no-index -p --src-prefix=a/ --dst-prefix=b/ -- $left $right 2>$stderr
    $exit = $LASTEXITCODE
    if ($exit -gt 1) { throw "git diff failed for ${relative}: $(Get-Content -LiteralPath $stderr -Raw)" }
    Remove-Item -LiteralPath $stderr -Force -ErrorAction SilentlyContinue

    $kept = foreach ($line in $lines) {
        if ($line -match '^(diff --git |index )') { continue }
        if ($line -match '^--- ') {
            if ($null -eq $inReference) { '--- /dev/null' } else { ConvertTo-PatchPath $line }
        }
        elseif ($line -match '^\+\+\+ ') { ConvertTo-PatchPath $line }
        else { $line }
    }
    if ($null -ne $placeholder) { Remove-Item -LiteralPath $placeholder.FullName -Force }
    return ($kept -join "`n")
}

$chunks = foreach ($relative in $Files) { Get-NormalizedPatch $relative }
$chunks = @($chunks | Where-Object { $_ })

# Anything outside the allow-list that drifted is a bug in the change, not part of the patch.
$drift = @()
Get-ChildItem -LiteralPath $Patched -Recurse -File -Filter *.rs | ForEach-Object {
    $relative = $_.FullName.Substring($Patched.Length + 1).Replace('\', '/')
    if ($Files -contains $relative) { return }
    if ($relative -like 'target/*') { return }
    $inReference = Join-Path $Reference $relative
    if (-not (Test-Path -LiteralPath $inReference)) {
        $drift += "added   $relative"
    } elseif ((Get-FileHash -LiteralPath $_.FullName).Hash -ne (Get-FileHash -LiteralPath $inReference).Hash) {
        $drift += "modified $relative"
    }
}
if ($drift) {
    Write-Error ("the patched tree diverges from the reference outside the MVP allow-list:`n" + ($drift -join "`n"))
    exit 1
}

$header = @(
    'Ghost Gate -- wallet minimum-value-promise patch'
    ''
    'Extends tari-ootle v0.42.0 so a wallet transfer output can declare the minimum value promise'
    'its bulletproof proves. Stock walletd hardcodes this to 0, which makes a threshold access'
    'proof unreachable: there is no way for a wallet to build the output the proof is about.'
    ''
    'Applying:  git apply -p1 wallet-mvp.patch   (from a clean v0.42.0 checkout)'
    ''
) -join "`n"

[System.IO.File]::WriteAllText($Output, $header + ($chunks -join "`n") + "`n", $Utf8)

$changed = @($chunks).Count
$lines = (Get-Content -LiteralPath $Output).Count
Write-Output "wrote $Output"
Write-Output "  files changed: $changed"
Write-Output "  patch lines:   $lines"
Write-Output ''
Write-Output 'Changed files:'
foreach ($relative in $Files) {
    $inReference = Join-Path $Reference $relative
    $inPatched = Join-Path $Patched $relative
    $state =
        if (-not (Test-Path -LiteralPath $inReference)) { 'new     ' }
        elseif (-not (Test-Path -LiteralPath $inPatched)) { 'deleted ' }
        elseif ((Get-FileHash -LiteralPath $inReference).Hash -eq (Get-FileHash -LiteralPath $inPatched).Hash) { 'same    ' }
        else { 'modified' }
    if ($state -ne 'same    ') { Write-Output "  $state $relative" }
}