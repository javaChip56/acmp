# ACMP

ACMP is an internal authentication credential management platform focused on HMAC-based service-to-service authentication.

It brings together:

- an administration API for managing clients, credentials, packages, audit data, and admin users
- a simple built-in web admin portal at `/admin`
- reusable HMAC libraries for protected services and outbound clients
- a MiniKMS service for protecting HMAC secrets and internal service-auth keys
- multiple persistence options for demo, development, and durable deployment

The current implementation targets .NET 8 and supports:

- `InMemoryDemo`
- `SqlServer`
- `Postgres`

## What The Project Does

At a high level, ACMP lets an administrator:

1. create and manage service clients
2. issue, rotate, revoke, and package HMAC credentials
3. manage admin users and role-based access
4. store protected secret material through MiniKMS
5. distribute encrypted credential packages that services and clients can load at runtime

The runtime libraries then let:

- a protected API validate inbound HMAC-signed requests
- an outbound client sign requests using a locally loaded encrypted package

## Architecture Overview

The solution is built around two main runtime processes:

- `MyCompany.AuthPlatform.Api`
  The main management host. It exposes the admin API, embedded identity flow, credential lifecycle operations, package issuance, audit access, and readiness endpoints.

- `MyCompany.Security.MiniKms`
  The internal key-management host. It protects HMAC secret material, manages HMAC master keys, manages internal JWT service-auth keys, and exposes internal readiness and key-lifecycle endpoints.

The API can use MiniKMS in two ways:

- local in-process key management for simpler development scenarios
- a separate MiniKMS process over signed internal JWT/service tokens for stronger separation of concerns

## How The Pieces Fit Together

1. An admin signs in to `MyCompany.AuthPlatform.Api`.
2. The API uses the application layer to create or manage clients and HMAC credentials.
3. Secret material is protected through MiniKMS before it is stored.
4. The API can issue encrypted credential packages for service-side validation or client-side signing.
5. The HMAC libraries load those packages at runtime and perform request signing or validation.

## Solution Components

### Runtime Hosts

- `src/MyCompany.AuthPlatform.Api`
  Runnable API host for the admin API, local web admin portal, demo mode, embedded identity, credential issuance, rotation, revocation, audit access, and package delivery.

- `src/MyCompany.Security.MiniKms`
  Runnable internal MiniKMS host with key lifecycle, soft-retire behavior, audit logging, persisted state, service-auth key rotation, and readiness checks.

### Application and Shared Logic

- `src/MyCompany.AuthPlatform.Application`
  Core application services and business rules for clients, credentials, admin users, auditing, package issuance, and secret protection workflows.

- `src/MyCompany.Shared.Contracts`
  Shared domain models, enums, and cross-project contracts.

### Packaging and HMAC Libraries

- `src/MyCompany.AuthPlatform.Packaging`
  Encrypted package creation and package-reading support for service-validation and client-signing package artifacts.

- `src/MyCompany.AuthPlatform.Hmac`
  Service-side HMAC validation library, including package-backed credential loading and ASP.NET Core middleware integration.

- `src/MyCompany.AuthPlatform.Hmac.Client`
  Client-side HMAC signing library, including package-backed signing support and an outbound `HttpClient` handler.

### Persistence

- `src/MyCompany.AuthPlatform.Persistence.Abstractions`
  Repository and unit-of-work contracts used by the application layer.

- `src/MyCompany.AuthPlatform.Persistence.InMemory`
  In-memory persistence provider for demo mode and lightweight local runs.

- `src/MyCompany.AuthPlatform.Persistence.SqlServer`
  SQL Server persistence provider and EF Core migrations.

- `src/MyCompany.AuthPlatform.Persistence.Postgres`
  PostgreSQL persistence provider and EF Core migrations.

### MiniKMS Support

- `src/MyCompany.Security.MiniKms.Client`
  Shared MiniKMS contracts, remote client, internal JWT token support, and MiniKMS-managed internal JWT key-state helpers.

### Tests

- `tests/MyCompany.AuthPlatform.Application.Tests`
  Application-layer unit tests.

- `tests/MyCompany.AuthPlatform.Hmac.Tests`
  HMAC runtime, package loader, and package-backed signing/validation tests.

- `tests/MyCompany.AuthPlatform.Api.IntegrationTests`
  Integration tests covering the API host, MiniKMS integration, database providers, package flows, and readiness behavior.

## Operating Modes

### Demo Mode

Demo mode is meant for demos and local exploration rather than durable deployment.

It typically uses:

- `Persistence:Provider = InMemoryDemo`
- embedded identity
- in-memory or demo-style MiniKMS persistence

See [demo_mode.md](d:/Research/acmp/docs/demo_mode.md).

### Durable Deployment

For non-demo use, the platform is designed to run with:

- SQL Server or PostgreSQL persistence for the main API
- file, SQL Server, or PostgreSQL state for MiniKMS
- a separate MiniKMS process when remote key management is desired

See:

- [sql_server_setup.md](d:/Research/acmp/docs/sql_server_setup.md)
- [postgres_setup.md](d:/Research/acmp/docs/postgres_setup.md)
- [minikms_service.md](d:/Research/acmp/docs/minikms_service.md)

## Getting Started

Build and test from the repository root:

```powershell
dotnet build .\Acmp.sln
dotnet test .\Acmp.sln
dotnet format .\Acmp.sln --verify-no-changes --severity warn
```

Run the main API host:

```powershell
dotnet run --project .\src\MyCompany.AuthPlatform.Api
```

Then open:

- `<local-url>/admin/index.html` for the built-in web admin
- `<local-url>/admin/login.html` for the admin sign-in page
- `<local-url>/swagger` for the API surface in development

Typical local URLs will look like:

- `https://localhost:7xxx/admin/login.html`
- `http://localhost:5xxx/admin/login.html`

Default development sign-ins from [appsettings.Development.json](d:/Research/acmp/src/MyCompany.AuthPlatform.Api/appsettings.Development.json#L1):

- `administrator.demo` / `AdministratorPass!123`
- `operator.demo` / `OperatorPass!123`
- `viewer.demo` / `ViewerPass!123`

Run the MiniKMS service:

```powershell
dotnet run --project .\src\MyCompany.Security.MiniKms
```

## Key Documentation

- [auth_platform_requirements_baseline.md](d:/Research/acmp/docs/auth_platform_requirements_baseline.md)
  Baseline product and scope requirements.

- [auth_platform_frs.md](d:/Research/acmp/docs/auth_platform_frs.md)
  Functional requirements specification.

- [auth_platform_ts.md](d:/Research/acmp/docs/auth_platform_ts.md)
  Technical specification and implementation design.

- [acmp.architecture.json](d:/Research/acmp/docs/acmp.architecture.json)
  CALM architecture model.

- [acmp-candidate-nodes.md](d:/Research/acmp/docs/acmp-candidate-nodes.md)
  Narrative CALM node and flow notes.

- [identity_provider_setup.md](d:/Research/acmp/docs/identity_provider_setup.md)
  Embedded identity and authentication setup notes.

- [minikms_service.md](d:/Research/acmp/docs/minikms_service.md)
  MiniKMS service configuration, persistence, readiness, and key-management runbook.

- [external_recipient_wrapping_key_design.md](d:/Research/acmp/docs/external_recipient_wrapping_key_design.md)
  Draft design for cross-platform recipient-owned package decryption keys that do not rely on X.509 certificate stores.

## Current Scope

The implemented platform is centered on HMAC and currently includes:

- client and credential lifecycle management
- HMAC secret issuance and protected persistence
- encrypted credential package issuance and runtime loading
- embedded admin identity with RBAC
- separate MiniKMS support
- MiniKMS-managed internal JWT service-auth key rotation
- SQL Server, PostgreSQL, file-based, and in-memory persistence paths where applicable

Future authentication modes such as OAuth, general JWT access-token platforms, and mTLS-focused authentication are intentionally outside the current release scope.
