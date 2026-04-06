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
    $loadOutput = docker load -i $archive
    $loadOutput | ForEach-Object { Write-Host $_ }

    foreach ($line in $loadOutput)
    {
        if ($line -match "Loaded image:\s+(?<image>\S+)")
        {
            $loadedImage = $Matches["image"]
            if ($loadedImage -match "^acmp-api:")
            {
                Write-Host "Tagging $loadedImage as acmp-api:offline"
                docker tag $loadedImage "acmp-api:offline"
            }
            elseif ($loadedImage -match "^acmp-minikms:")
            {
                Write-Host "Tagging $loadedImage as acmp-minikms:offline"
                docker tag $loadedImage "acmp-minikms:offline"
            }
        }
    }
}

Write-Host "Offline image import complete."
