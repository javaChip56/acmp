# Recipient Sample Host

This sample shows a minimal recipient API that:

- loads an encrypted HMAC validation package from disk
- reads package runtime settings from `appsettings.json`
- supports `ExternalRsaPublicKey` runtime decryption via a local PEM private key
- validates inbound ACMP HMAC requests on `/api/orders/create`

## Run

```powershell
dotnet run --project .\samples\MyCompany.AuthPlatform.RecipientSample
```

## Configure

Update [appsettings.json](d:/Research/acmp/samples/MyCompany.AuthPlatform.RecipientSample/appsettings.json#L1) with:

- the real package directory
- the expected HMAC `keyId` in `PreloadKeyIds`
- the actual recipient binding metadata
- the local PEM private key path

The runtime configuration shape matches the guide in [recipient_runtime_setup.md](d:/Research/acmp/docs/recipient_runtime_setup.md#L1).
