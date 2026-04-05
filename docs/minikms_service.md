# MiniKMS Service

The solution now supports two MiniKMS provider modes for the main API:

- `LocalMiniKms`
- `RemoteMiniKms`

`RemoteMiniKms` is intended for the internal split-process deployment where the main API calls a separate MiniKMS service over an internal HTTP interface. The local provider remains available so the platform can still support future certificate-store, DPAPI, or other secure key-provider implementations behind the same `IMiniKms` abstraction.

## Run the MiniKMS service

From the repository root:

```powershell
dotnet run --project .\src\MyCompany.Security.MiniKms
```

The service uses the `MiniKms` config section in [appsettings.json](/d:/Research/acmp/src/MyCompany.Security.MiniKms/appsettings.json):

```json
{
  "MiniKms": {
    "DemoModeEnabled": false,
    "PersistenceProvider": "File",
    "ActiveKeyVersion": "kms-v1",
    "StateFilePath": "App_Data/minikms-state.json",
    "InternalJwt": {
      "KeySource": "MiniKmsState",
      "Issuer": "acmp-internal-services",
      "Audience": "mini-kms-internal",
      "ActiveKeyVersion": "svcjwt-v1",
      "Subject": "acmp-api",
      "TokenLifetimeMinutes": 5,
      "ManagedState": {
        "Provider": "File",
        "StateFilePath": "App_Data/minikms-internal-jwt-state.json"
      }
    },
    "SqlServer": {
      "ConnectionString": "Server=(localdb)\\MSSQLLocalDB;Database=AcmpMiniKms;Trusted_Connection=True;TrustServerCertificate=True"
    },
    "Postgres": {
      "ConnectionString": "Host=localhost;Port=5432;Database=acmp_minikms;Username=postgres;Password=postgres"
    },
    "MasterKeys": {
      "kms-v1": "QWNtcFNlY3JldE1hc3RlcktleUZvckttc3YxIUFCQ0Q="
    }
  }
}
```

Internal endpoints:

- `GET /health`
- `POST /internal/minikms/generate-secret`
- `POST /internal/minikms/encrypt`
- `POST /internal/minikms/decrypt`
- `GET /internal/minikms/keys`
- `POST /internal/minikms/keys`
- `POST /internal/minikms/keys/{keyVersion}/activate`
- `POST /internal/minikms/keys/{keyVersion}/retire`
- `GET /internal/minikms/audit`
- `GET /internal/minikms/service-auth/keys`
- `POST /internal/minikms/service-auth/keys`
- `POST /internal/minikms/service-auth/keys/{keyVersion}/activate`
- `POST /internal/minikms/service-auth/keys/{keyVersion}/retire`

The internal endpoints require a signed bearer token issued for the internal MiniKMS audience.
Actor attribution is taken from the token subject.

The MiniKMS service supports these persistence modes:

- `InMemoryDemo`
- `File`
- `SqlServer`
- `Postgres`

If `DemoModeEnabled` is `true`, the service always uses in-memory state regardless of the configured persistence provider. Otherwise it uses `PersistenceProvider`.

## Local split-process startup

Development launch profiles now line up by default:

- MiniKMS service: `https://localhost:7190`
- Main API remote MiniKMS profile: `https-remote-minikms`

Run them separately:

```powershell
dotnet run --project .\src\MyCompany.Security.MiniKms --launch-profile https
dotnet run --project .\src\MyCompany.AuthPlatform.Api --launch-profile https-remote-minikms
```

That starts the API in remote MiniKMS mode while keeping the API and key-management process split.

If you want an ephemeral demo-only MiniKMS process, set:

```powershell
$env:MiniKms__DemoModeEnabled = "true"
dotnet run --project .\src\MyCompany.Security.MiniKms --launch-profile https
```

If you want SQL-backed MiniKMS persistence instead of file-backed state, set one of these:

```powershell
$env:MiniKms__PersistenceProvider = "SqlServer"
$env:MiniKms__SqlServer__ConnectionString = "Server=(localdb)\MSSQLLocalDB;Database=AcmpMiniKms;Trusted_Connection=True;TrustServerCertificate=True"
```

or

```powershell
$env:MiniKms__PersistenceProvider = "Postgres"
$env:MiniKms__Postgres__ConnectionString = "Host=localhost;Port=5432;Database=acmp_minikms;Username=postgres;Password=postgres"
```

## Point the main API at the MiniKMS service

Update the main API config in [appsettings.json](/d:/Research/acmp/src/MyCompany.AuthPlatform.Api/appsettings.json):

```json
{
  "MiniKms": {
    "Provider": "RemoteMiniKms",
    "ActiveKeyVersion": "kms-v1",
    "Remote": {
      "BaseUrl": "https://localhost:7190",
      "TimeoutSeconds": 15,
      "InternalJwt": {
        "KeySource": "MiniKmsState",
        "Issuer": "acmp-internal-services",
        "Audience": "mini-kms-internal",
        "ActiveKeyVersion": "svcjwt-v1",
        "Subject": "acmp-api",
        "TokenLifetimeMinutes": 5,
        "ManagedState": {
          "Provider": "File",
          "StateFilePath": "..\\MyCompany.Security.MiniKms\\App_Data\\minikms-internal-jwt-state.json"
        }
      }
    }
  }
}
```

When `Provider` is `RemoteMiniKms`, the API keeps using the same application-layer secret protection flow, but the underlying `IMiniKms` implementation becomes an HTTP client to the separate MiniKMS service. In `MiniKmsState` mode, the bearer tokens used for API-to-MiniKMS authentication are signed from the MiniKMS-managed internal JWT key ring rather than from a static config secret.

## Rotate and soft-retire keys

Create a new key version:

```powershell
$token = "<signed bearer token for the mini-kms-internal audience>"
$headers = @{ "Authorization" = "Bearer $token" }

Invoke-RestMethod `
  -Method Post `
  -Uri https://localhost:7190/internal/minikms/keys `
  -Headers $headers `
  -Body (@{ keyVersion = "kms-v2"; activate = $false } | ConvertTo-Json) `
  -ContentType "application/json"
```

Activate it:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri https://localhost:7190/internal/minikms/keys/kms-v2/activate `
  -Headers $headers
```

Activating a new key automatically soft-retires the previous active key. Retired keys are no longer used for new encryption, but they remain available for decrypting previously wrapped material.

You can also soft-retire a non-active key explicitly:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri https://localhost:7190/internal/minikms/keys/kms-v2/retire `
  -Headers $headers
```

List known key versions:

```powershell
Invoke-RestMethod `
  -Method Get `
  -Uri https://localhost:7190/internal/minikms/keys `
  -Headers $headers
```

Read recent MiniKMS audit events:

```powershell
Invoke-RestMethod `
  -Method Get `
  -Uri https://localhost:7190/internal/minikms/audit?take=20 `
  -Headers $headers
```

## Rotate internal service-auth JWT keys

List the current internal JWT signing key versions:

```powershell
Invoke-RestMethod `
  -Method Get `
  -Uri https://localhost:7190/internal/minikms/service-auth/keys `
  -Headers $headers
```

Create a replacement internal JWT signing key version:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri https://localhost:7190/internal/minikms/service-auth/keys `
  -Headers $headers `
  -Body (@{ keyVersion = "svcjwt-v2"; activate = $false } | ConvertTo-Json) `
  -ContentType "application/json"
```

Activate it:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri https://localhost:7190/internal/minikms/service-auth/keys/svcjwt-v2/activate `
  -Headers $headers
```

The API will begin issuing new bearer tokens with the new active signing key version once it observes the updated MiniKMS-managed JWT key state.

## Notes

- `ActiveKeyVersion` remains explicit in the API config so the host can expose it in `/health` and use it as the default key version for new secrets.
- `MasterKeys` are only used by the local provider path in the main API. In remote mode, the actual wrapping keys live in the MiniKMS service process.
- The API-to-MiniKMS trust path now uses signed internal JWT/service tokens rather than a shared static API key.
- The internal JWT signing keys can now be externalized from appsettings into MiniKMS-managed state and rotated independently from the HMAC secret-wrapping master keys.
- In normal mode, MiniKMS persists key-ring state and audit history through the configured provider. `File` is the default local option, while `SqlServer` and `Postgres` are the intended durable deployment targets.
- In `MiniKmsState` mode, both the MiniKMS service and the main API must point at the same internal JWT managed-state provider so the API signs with the active MiniKMS-managed service-auth key version.
- MiniKMS key states are currently `Active`, `Available`, and `Retired`. Retired keys are decrypt-only.
- Future implementations such as Windows Certificate Store or DPAPI-backed providers can still be added without changing the application-layer contracts.
