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
    "ServiceApiKey": "dev-minikms-api-key",
    "ActiveKeyVersion": "kms-v1",
    "StateFilePath": "App_Data/minikms-state.json",
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

The internal endpoints require the `X-MiniKms-Api-Key` header.
They also accept an optional `X-MiniKms-Actor` header for audit attribution.

By default, the MiniKMS service now persists its key-ring state and audit trail to the configured `StateFilePath`. If `DemoModeEnabled` is set to `true`, the service switches to in-memory state instead.

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

## Point the main API at the MiniKMS service

Update the main API config in [appsettings.json](/d:/Research/acmp/src/MyCompany.AuthPlatform.Api/appsettings.json):

```json
{
  "MiniKms": {
    "Provider": "RemoteMiniKms",
    "ActiveKeyVersion": "kms-v1",
    "Remote": {
      "BaseUrl": "https://localhost:7190",
      "ApiKey": "dev-minikms-api-key",
      "TimeoutSeconds": 15
    }
  }
}
```

When `Provider` is `RemoteMiniKms`, the API keeps using the same application-layer secret protection flow, but the underlying `IMiniKms` implementation becomes an HTTP client to the separate MiniKMS service.

## Rotate and soft-retire keys

Create a new key version:

```powershell
$headers = @{ "X-MiniKms-Api-Key" = "dev-minikms-api-key" }

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
$headers["X-MiniKms-Actor"] = "ops-user"

Invoke-RestMethod `
  -Method Get `
  -Uri https://localhost:7190/internal/minikms/audit?take=20 `
  -Headers $headers
```

## Notes

- `ActiveKeyVersion` remains explicit in the API config so the host can expose it in `/health` and use it as the default key version for new secrets.
- `MasterKeys` are only used by the local provider path in the main API. In remote mode, the actual wrapping keys live in the MiniKMS service process.
- In normal mode, MiniKMS persists key-ring state and audit history to `StateFilePath`. In demo mode, the same behavior stays available but is held only in memory for the lifetime of the process.
- MiniKMS key states are currently `Active`, `Available`, and `Retired`. Retired keys are decrypt-only.
- Future implementations such as Windows Certificate Store or DPAPI-backed providers can still be added without changing the application-layer contracts.
