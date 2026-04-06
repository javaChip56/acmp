# Release Checklist

This checklist is for operators or release owners preparing to use a tagged ACMP release.

## 0. Trigger The Right Pipeline

Use one of these two paths:

- Dry run
  Trigger the `Release Dry Run` GitHub Actions workflow manually and provide a version label such as `v1.2.0-dryrun`.
  Use this when you want to verify the release packaging flow without creating a real GitHub release.

- Real release
  Create and push a real `v*` tag from a commit that is already on `main`.
  Example:

```powershell
git checkout main
git pull
git tag v1.2.0
git push origin v1.2.0
```

The real publish workflow will then build the release assets, create or update the GitHub release, and attach the release artifacts.

## 1. Pick The Right Release Asset

Use the GitHub release asset that matches the deployment style:

- `acmp-api-<version>.tar.gz`
  Use this when you want the published API artifact and you will run deployment/build steps in a connected environment.

- `acmp-offline-bundle-<version>.tar.gz`
  Use this when the target host should not need internet access.
  This bundle includes:
  - prebuilt Docker image archives
  - offline Docker Compose file
  - environment templates
  - import script
  - deployment runbook

## 2. For Connected/Local Docker Deployment

Use:
- [local_deployment.md](d:/Research/acmp/docs/local_deployment.md)

Checklist:
- copy `deploy/.env.example` to `deploy/.env`
- update secrets and ports as needed
- run `docker compose --env-file .\deploy\.env -f .\deploy\docker-compose.yml up --build -d`
- verify:
  - `http://localhost:8080/ready`
  - `http://localhost:8081/ready`
- sign in to `/admin/login.html`

## 3. For Offline / Air-Gapped Deployment

Use:
- [offline_deployment.md](d:/Research/acmp/docs/offline_deployment.md)

Checklist:
- extract `acmp-offline-bundle-<version>.tar.gz`
- copy `deploy/.env.offline.example` to `deploy/.env.offline`
- update secrets and ports as needed
- run `.\deploy\scripts\import-offline-images.ps1`
- run `docker compose --env-file .\deploy\.env.offline -f .\deploy\docker-compose.offline.yml up -d`
- verify:
  - `http://localhost:8080/ready`
  - `http://localhost:8081/ready`
- sign in to `/admin/login.html`

## 4. Post-Deployment Validation

After startup:

- confirm the admin portal loads
- confirm embedded admin login works if enabled
- confirm the API health/readiness endpoints return `Ready`
- confirm MiniKMS health/readiness endpoints return `Ready`
- confirm seeded/demo data exists only where expected
- confirm persistence provider matches the intended deployment

## 5. If You Need Recipient Runtime Validation

Use:
- [recipient_runtime_setup.md](d:/Research/acmp/docs/recipient_runtime_setup.md)
- [hmac_service_library.md](d:/Research/acmp/docs/hmac_service_library.md)
- [hmac_client_library.md](d:/Research/acmp/docs/hmac_client_library.md)

Validate:
- package issuance succeeds
- recipient package loads successfully
- client package signs successfully
- protected endpoint accepts signed requests

## 6. Before Promoting Beyond Dev/Test

- replace development/default secrets
- review embedded identity bootstrap users
- confirm the correct persistence provider is being used
- confirm MiniKMS persistence is durable, not demo-mode in-memory
- confirm backup/restore expectations for the chosen deployment path
