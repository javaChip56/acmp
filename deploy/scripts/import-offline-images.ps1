param(
    [string]$InputDirectory = ".\deploy\artifacts"
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$resolvedInputDirectory = Join-Path $repoRoot $InputDirectory

$archives = @(
    (Join-Path $resolvedInputDirectory "acmp-api-offline.tar"),
    (Join-Path $resolvedInputDirectory "acmp-minikms-offline.tar"),
    (Join-Path $resolvedInputDirectory "postgres-16.tar")
)

foreach ($archive in $archives)
{
    if (-not (Test-Path $archive))
    {
        throw "Required archive not found: $archive"
    }

    Write-Host "Loading image archive $archive"
    docker load -i $archive
}

Write-Host "Offline image import complete."
