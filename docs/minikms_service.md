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
    "ServiceApiKey": "dev-minikms-api-key",
    "ActiveKeyVersion": "kms-v1",
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

The internal endpoints require the `X-MiniKms-Api-Key` header.

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

## Notes

- `ActiveKeyVersion` remains explicit in the API config so the host can expose it in `/health` and use it as the default key version for new secrets.
- `MasterKeys` are only used by the local provider path in the main API. In remote mode, the actual wrapping keys live in the MiniKMS service process.
- Future implementations such as Windows Certificate Store or DPAPI-backed providers can still be added without changing the application-layer contracts.
