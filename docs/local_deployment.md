# Local Deployment With Docker Compose

This repo includes a simple local deployment stack for:

- `MyCompany.AuthPlatform.Api`
- `MyCompany.Security.MiniKms`
- PostgreSQL

The compose example is aimed at local development and demos. It uses:

- PostgreSQL for API persistence
- PostgreSQL for MiniKMS state persistence
- PostgreSQL for MiniKMS-managed internal JWT key state
- embedded identity for the admin portal
- remote MiniKMS mode for the API

## Prerequisites

- Docker Desktop or a compatible Docker Engine with Compose v2

## Files

- [docker-compose.yml](d:/Research/acmp/deploy/docker-compose.yml)
- [.env.example](d:/Research/acmp/deploy/.env.example)
- [api.Dockerfile](d:/Research/acmp/deploy/docker/api.Dockerfile)
- [minikms.Dockerfile](d:/Research/acmp/deploy/docker/minikms.Dockerfile)

## First Run

From the repository root:

```powershell
Copy-Item .\deploy\.env.example .\deploy\.env
docker compose --env-file .\deploy\.env -f .\deploy\docker-compose.yml up --build -d
```

Check container status:

```powershell
docker compose --env-file .\deploy\.env -f .\deploy\docker-compose.yml ps
```

Check readiness:

```powershell
Invoke-RestMethod http://localhost:8080/ready
Invoke-RestMethod http://localhost:8081/ready
```

## URLs

- Admin portal: `http://localhost:8080/admin/login.html`
- Swagger UI: `http://localhost:8080/swagger`
- API readiness: `http://localhost:8080/ready`
- MiniKMS readiness: `http://localhost:8081/ready`

## Default Login

These come from the API defaults unless you override them through environment variables:

- `administrator.demo` / `AdministratorPass!123`
- `operator.demo` / `OperatorPass!123`
- `viewer.demo` / `ViewerPass!123`

## Notes On The Compose Configuration

- The stack uses one PostgreSQL database by default. The API, MiniKMS state store, and MiniKMS internal JWT managed state store use separate table names, so they can safely share the same database for local deployment.
- The API talks to MiniKMS through signed internal JWT service tokens.
- Both services are given the same bootstrap internal JWT signing key through `ACMP_INTERNAL_JWT_BOOTSTRAP_SIGNING_KEY`. This makes first startup deterministic before the managed state store is populated.
- `DemoMode__SeedOnStartup=true` is enabled for the API so the admin UI is immediately usable after startup.

## Stopping The Stack

```powershell
docker compose --env-file .\deploy\.env -f .\deploy\docker-compose.yml down
```

To remove the PostgreSQL data volume too:

```powershell
docker compose --env-file .\deploy\.env -f .\deploy\docker-compose.yml down -v
```

## Suggested Next Hardening Steps

- Replace the development secrets in `.env` before using the stack outside a local/dev environment.
- Move the embedded identity bootstrap users to managed admin-user provisioning for shared environments.
- Add reverse proxy / TLS termination if you want a browser-facing deployment beyond local use.
