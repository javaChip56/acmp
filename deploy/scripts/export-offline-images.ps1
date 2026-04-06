param(
    [string]$ApiImage = "acmp-api:offline",
    [string]$MiniKmsImage = "acmp-minikms:offline",
    [string]$PostgresImage = "postgres:16",
    [string]$OutputDirectory = ".\deploy\artifacts"
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$resolvedOutputDirectory = Join-Path $repoRoot $OutputDirectory

New-Item -ItemType Directory -Force -Path $resolvedOutputDirectory | Out-Null

Write-Host "Building API image: $ApiImage"
docker build -f (Join-Path $repoRoot "deploy\docker\api.Dockerfile") -t $ApiImage $repoRoot

Write-Host "Building MiniKMS image: $MiniKmsImage"
docker build -f (Join-Path $repoRoot "deploy\docker\minikms.Dockerfile") -t $MiniKmsImage $repoRoot

Write-Host "Pulling database image: $PostgresImage"
docker pull $PostgresImage

$apiArchive = Join-Path $resolvedOutputDirectory "acmp-api-offline.tar"
$miniKmsArchive = Join-Path $resolvedOutputDirectory "acmp-minikms-offline.tar"
$postgresArchive = Join-Path $resolvedOutputDirectory "postgres-16.tar"

Write-Host "Saving API image to $apiArchive"
docker save -o $apiArchive $ApiImage

Write-Host "Saving MiniKMS image to $miniKmsArchive"
docker save -o $miniKmsArchive $MiniKmsImage

Write-Host "Saving Postgres image to $postgresArchive"
docker save -o $postgresArchive $PostgresImage

Write-Host "Offline image export complete."
