[CmdletBinding()]
param(
    [string] $OutputDirectory = (Join-Path $PSScriptRoot "..\\artifacts"),
    [string] $OotleSource = (Join-Path $PSScriptRoot "..\\..\\_ootle-v042-ghost-gate")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repository = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ootle = (Resolve-Path $OotleSource).Path
$commit = (git -C $repository rev-parse HEAD).Trim()
$short = $commit.Substring(0, 12)
$root = "ghost-gate-staging-source-$short"
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$scratch = Join-Path ([IO.Path]::GetTempPath()) "ghost-gate-package-$stamp-$PID"
$archive = Join-Path (Resolve-Path -LiteralPath (New-Item -ItemType Directory -Force -Path $OutputDirectory)).Path "$root.tar.gz"

if (Test-Path -LiteralPath $archive) { throw "Archive already exists: $archive" }
New-Item -ItemType Directory -Path $scratch | Out-Null
try {
    $stage = Join-Path $scratch $root
    $ghost = Join-Path $stage "ghost-gate-laptop"
    $ootleDestination = Join-Path $stage "_ootle-v042-ghost-gate"
    New-Item -ItemType Directory -Path $ghost, $ootleDestination -Force | Out-Null

    # `git archive` includes only the reviewed commit: no .git directory, local
    # dashboard data, source-tree node_modules, Cargo target trees, or untracked files.
    $gitArchive = Join-Path $scratch "ghost-gate.tar"
    & git -C $repository archive --format=tar --output=$gitArchive $commit
    if ($LASTEXITCODE -ne 0) { throw "git archive failed" }
    & tar -xf $gitArchive -C $ghost
    if ($LASTEXITCODE -ne 0) { throw "extracting the Ghost Gate source failed" }

    # The pinned Ootle reference is a sibling source tree, not a Git checkout.
    # Exclude all runtime/admin state and build products while retaining its .cargo
    # configuration, which is source-controlled upstream and needed by Cargo.
    $null = & robocopy $ootle $ootleDestination /E /R:0 /W:0 /NFL /NDL /NJH /NJS /XD target node_modules .git .wrangler /XF *.key *.pem keys.json .env .env.* *.sqlite *.sqlite3 *.db registry.json sessions.json reset_halt.json hosted_halt_revision generations.ndjson audit.ndjson bootstrap.token
    if ($LASTEXITCODE -gt 7) { throw "copying the pinned Ootle source failed (robocopy exit $LASTEXITCODE)" }

    $forbidden = Get-ChildItem -LiteralPath $stage -Recurse -Force -File | Where-Object {
        $_.Name -in @("keys.json", ".env", "registry.json", "sessions.json", "reset_halt.json", "hosted_halt_revision", "generations.ndjson", "audit.ndjson", "bootstrap.token") -or
        $_.Extension -in @(".key", ".pem", ".sqlite", ".sqlite3", ".db")
    }
    if ($forbidden) { throw "Refusing to archive state or credentials: $($forbidden.FullName -join ', ')" }

    @{ ghost_gate_commit = $commit; ootle_source = $ootle; created_utc = [DateTime]::UtcNow.ToString("o") } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $stage "SOURCE-MANIFEST.json") -Encoding utf8NoBOM
    & tar -czf $archive -C $scratch $root
    if ($LASTEXITCODE -ne 0) { throw "creating the source archive failed" }
} finally {
    if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Recurse -Force }
}

Get-FileHash -LiteralPath $archive -Algorithm SHA256
Write-Output "Created clean source archive: $archive"
