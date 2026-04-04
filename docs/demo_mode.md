# Demo Mode

The repository now includes a runnable demo API host at
[MyCompany.AuthPlatform.Api](d:/Research/acmp/src/MyCompany.AuthPlatform.Api/MyCompany.AuthPlatform.Api.csproj).

## Run

From the repository root:

```powershell
dotnet run --project .\src\MyCompany.AuthPlatform.Api
```

The current default configuration uses:

- `Persistence:Provider = InMemoryDemo`
- `DemoMode:SeedOnStartup = true`
- `Authentication:Mode = EmbeddedIdentity`

## What Demo Mode Does

- starts the API with the in-memory persistence provider
- seeds a small sample dataset on startup
- stores all data in process memory only
- clears all data when the process stops or restarts
- authenticates requests through an embedded identity provider that issues bearer tokens
- enforces role authorization policies for viewer, operator, and administrator access

## Useful Endpoints

- `GET /health`
- `POST /api/auth/token`
- `GET /api/system/info`
- `GET /api/clients`
- `GET /api/clients/{clientId}`
- `GET /api/clients/{clientId}/credentials`
- `GET /api/credentials/{credentialId}`
- `POST /api/clients`
- `POST /api/clients/{clientId}/credentials/hmac`
- `POST /api/credentials/{credentialId}/rotate`
- `POST /api/credentials/{credentialId}/revoke`
- `GET /api/audit`

## Bootstrap Users

- `viewer.demo / ViewerPass!123`
- `operator.demo / OperatorPass!123`
- `administrator.demo / AdministratorPass!123`

Those users are bootstrapped into the local persisted admin-user store on startup when they do not already exist.

Use `POST /api/auth/token` with one of those accounts to get a bearer token, then send:

```http
Authorization: Bearer <access-token>
```

You can still supply `X-Correlation-Id` on API requests when you want to control audit correlation.

## Notes

- This is a demo host, not the full production host.
- The in-memory provider is intended for demonstrations only.
- The embedded identity provider is intended as an application-local identity source, with bootstrap users seeded into the persisted store for local and demo use.
- To switch the same host to a real identity provider, set `Authentication:Mode = JwtBearer` and configure the `Authentication:JwtBearer` section described in [identity_provider_setup.md](d:/Research/acmp/docs/identity_provider_setup.md).
