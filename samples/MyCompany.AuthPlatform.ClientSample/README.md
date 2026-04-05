# Client Sample

This sample shows how to use `MyCompany.AuthPlatform.Hmac.Client` to:

- load an encrypted client-signing package from disk
- read runtime settings from `appsettings.json`
- support `ExternalRsaPublicKey` decryption with a local PEM private key
- sign an outbound HTTP request with ACMP HMAC headers

## Run

```powershell
dotnet run --project .\samples\MyCompany.AuthPlatform.ClientSample
```

## Configure

Update [appsettings.json](d:/Research/acmp/samples/MyCompany.AuthPlatform.ClientSample/appsettings.json#L1) with:

- the real package directory
- the actual credential `KeyId`
- the correct package read options for the recipient binding
- the target API base URL

This sample is intended to call the recipient sample at [samples/MyCompany.AuthPlatform.RecipientSample/README.md](d:/Research/acmp/samples/MyCompany.AuthPlatform.RecipientSample/README.md#L1).
