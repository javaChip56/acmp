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

## What Demo Mode Does

- starts the API with the in-memory persistence provider
- seeds a small sample dataset on startup
- stores all data in process memory only
- clears all data when the process stops or restarts

## Useful Endpoints

- `GET /health`
- `GET /api/system/info`
- `GET /api/clients`
- `GET /api/clients/{clientId}/credentials`
- `GET /api/audit`

## Notes

- This is a demo host, not the full production host.
- The in-memory provider is intended for demonstrations only.
- Authentication and RBAC are documented but are not yet enforced by this host.
