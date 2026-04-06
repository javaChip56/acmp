# Offline Deployment

This guide describes how to run ACMP on a host that does not have internet access.

The pattern is:

1. build and export the required Docker images on a connected machine
2. copy the image archives and deployment files to the offline host
3. load the images on the offline host
4. start the offline compose stack

## Files

- [docker-compose.offline.yml](d:/Research/acmp/deploy/docker-compose.offline.yml)
- [.env.offline.example](d:/Research/acmp/deploy/.env.offline.example)
- [export-offline-images.ps1](d:/Research/acmp/deploy/scripts/export-offline-images.ps1)
- [import-offline-images.ps1](d:/Research/acmp/deploy/scripts/import-offline-images.ps1)

## On A Connected Build Machine

From the repository root:

```powershell
.\deploy\scripts\export-offline-images.ps1
```

This produces image archives under `deploy/artifacts`:

- `acmp-api-offline.tar`
- `acmp-minikms-offline.tar`
- `postgres-16.tar`

Copy these to the offline host together with:

- `deploy/docker-compose.offline.yml`
- `deploy/.env.offline.example`
- `deploy/scripts/import-offline-images.ps1`

## On The Offline Host

1. Copy `.env.offline.example` to `.env.offline`

```powershell
Copy-Item .\deploy\.env.offline.example .\deploy\.env.offline
```

2. Import the image archives:

```powershell
.\deploy\scripts\import-offline-images.ps1
```

3. Start the stack:

```powershell
docker compose --env-file .\deploy\.env.offline -f .\deploy\docker-compose.offline.yml up -d
```

4. Check readiness:

```powershell
Invoke-RestMethod http://localhost:8080/ready
Invoke-RestMethod http://localhost:8081/ready
```

## URLs

- Admin portal: `http://localhost:8080/admin/login.html`
- Swagger UI: `http://localhost:8080/swagger`
- API readiness: `http://localhost:8080/ready`
- MiniKMS readiness: `http://localhost:8081/ready`

## Notes

- The offline compose file does not build anything. It only uses preloaded images.
- The offline host does not need internet access as long as the required images have already been imported.
- The default image names in [.env.offline.example](d:/Research/acmp/deploy/.env.offline.example#L1) match the tags produced by [export-offline-images.ps1](d:/Research/acmp/deploy/scripts/export-offline-images.ps1#L1).
- If you retag the images, update `.env.offline` to match.

## Cleanup

Stop the stack:

```powershell
docker compose --env-file .\deploy\.env.offline -f .\deploy\docker-compose.offline.yml down
```

Remove the PostgreSQL data volume too:

```powershell
docker compose --env-file .\deploy\.env.offline -f .\deploy\docker-compose.offline.yml down -v
```
