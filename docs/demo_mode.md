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
- `Authentication:Mode = DemoHeader`

## What Demo Mode Does

- starts the API with the in-memory persistence provider
- seeds a small sample dataset on startup
- stores all data in process memory only
- clears all data when the process stops or restarts
- authenticates requests through a demo header-backed ASP.NET Core authentication scheme
- enforces role authorization policies for viewer, operator, and administrator access

## Useful Endpoints

- `GET /health`
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

## Demo Headers

- `X-Demo-Role: AccessViewer` for read-only client and credential listing
- `X-Demo-Role: AccessOperator` for client creation, credential issuance, rotation, and revocation up to the standard grace-period limit
- `X-Demo-Role: AccessAdministrator` for the same write operations plus audit log access and extended grace periods beyond 14 days
- `X-Demo-Actor: your.name` to stamp a friendlier actor name into the audit log
- `X-Correlation-Id: value` to preserve a caller-supplied correlation id; one is generated automatically when omitted

If `X-Demo-Role` is omitted, the demo host authenticates the request as `AccessViewer`.

## Notes

- This is a demo host, not the full production host.
- The in-memory provider is intended for demonstrations only.
- Production-grade identity integration is not implemented yet; the current host uses demo headers as the authentication source for development and demos.
- To switch the same host to a real identity provider, set `Authentication:Mode = JwtBearer` and configure the `Authentication:JwtBearer` section described in [identity_provider_setup.md](d:/Research/acmp/docs/identity_provider_setup.md).
