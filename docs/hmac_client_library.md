# HMAC Client Library

This guide shows how to use [MyCompany.AuthPlatform.Hmac.Client](d:/Research/acmp/src/MyCompany.AuthPlatform.Hmac.Client/AcmpHmacSigningHandler.cs#L1) in an outbound caller.

Its job is to:

- load a client-signing package from disk
- decrypt and validate that package
- build the canonical string
- add ACMP HMAC headers to outbound HTTP requests

## Main Types

- [EncryptedFileClientCredentialStore](d:/Research/acmp/src/MyCompany.AuthPlatform.Hmac.Client/EncryptedFileClientCredentialStore.cs#L10)
  Loads and caches encrypted client-signing packages.

- [HmacRequestSigner](d:/Research/acmp/src/MyCompany.AuthPlatform.Hmac.Client/HmacRequestSigner.cs#L17)
  Signs canonical requests using the loaded package secret.

- [AcmpHmacSigningHandler](d:/Research/acmp/src/MyCompany.AuthPlatform.Hmac.Client/AcmpHmacSigningHandler.cs#L12)
  `HttpClient` delegating handler that adds the HMAC headers automatically.

- [AcmpHmacSigningHandlerOptions](d:/Research/acmp/src/MyCompany.AuthPlatform.Hmac.Client/AcmpHmacSigningHandler.cs#L5)
  Outbound signing options such as the target credential `KeyId`.

- [ClientPackageCacheOptions](d:/Research/acmp/src/MyCompany.AuthPlatform.Hmac.Client/EncryptedFileClientCredentialStore.cs#L5)
  Runtime configuration for encrypted-file client-signing mode.

## Configuration Shape

Example:

```json
{
  "AcmpHmac": {
    "Signing": {
      "KeyId": "key-uat-orders-0004-rsa",
      "ExpectedKeyVersion": "kms-v1",
      "PackageDirectory": "C:\\Acmp\\Packages",
      "CacheTimeToLive": "00:05:00",
      "PackageReadOptions": {
        "ExpectedBindingId": "11111111-2222-3333-4444-555555555555",
        "ExpectedBindingType": "ExternalRsaPublicKey",
        "ExpectedBindingKeyId": "orders-api-prod-rsa",
        "ExpectedBindingKeyVersion": "2026q2",
        "ExpectedPublicKeyFingerprint": "SHA256:BASE64_FINGERPRINT_HERE",
        "ExternalRsaPrivateKeyPath": "C:\\ProgramData\\OrdersApi\\Keys\\recipient-private-key.pem"
      }
    }
  }
}
```

The `KeyId` and optional `ExpectedKeyVersion` here refer to the HMAC credential being used for signing.

## Minimal `HttpClient` Setup

```csharp
using MyCompany.AuthPlatform.Hmac.Client;
using MyCompany.AuthPlatform.Packaging;

var signingPackageOptions = configuration
    .GetSection("AcmpHmac:Signing")
    .Get<ClientPackageCacheOptions>()
    ?? throw new InvalidOperationException("AcmpHmac:Signing configuration is required.");

var signingHandlerOptions = configuration
    .GetSection("AcmpHmac:Signing")
    .Get<AcmpHmacSigningHandlerOptions>()
    ?? throw new InvalidOperationException("AcmpHmac:Signing handler configuration is required.");

services.AddSingleton(signingPackageOptions);
services.AddSingleton(signingHandlerOptions);
services.AddSingleton<IX509CertificateResolver, CompositeX509CertificateResolver>();
services.AddSingleton<IHmacCredentialPackageReader, X509HmacCredentialPackageReader>();
services.AddSingleton<EncryptedFileClientCredentialStore>();
services.AddSingleton<HmacRequestSigner>();

services.AddHttpClient("OrdersApi", client =>
{
    client.BaseAddress = new Uri("https://localhost:7150");
})
.AddHttpMessageHandler(serviceProvider => new AcmpHmacSigningHandler(
    serviceProvider.GetRequiredService<HmacRequestSigner>(),
    serviceProvider.GetRequiredService<AcmpHmacSigningHandlerOptions>()));
```

If you want a nonce on every request, set:

```csharp
signingHandlerOptions.NonceGenerator = () => Guid.NewGuid().ToString("N");
```

## What The Handler Adds

The signing handler adds:

- `X-Key-Id`
- `X-Timestamp`
- `X-Signature`
- `X-Nonce` when configured

The request body is preserved after signing so the downstream transport still receives the original content.

## Failure Behavior

Signing fails securely when:

- the package cannot be loaded
- the package is expired or invalid
- the binding metadata does not match the configured runtime binding
- the canonical signing profile is unsupported
- the HMAC algorithm is unsupported

## Runnable Sample

For a runnable reference, see:

- [samples/MyCompany.AuthPlatform.ClientSample/Program.cs](d:/Research/acmp/samples/MyCompany.AuthPlatform.ClientSample/Program.cs#L1)
- [samples/MyCompany.AuthPlatform.ClientSample/README.md](d:/Research/acmp/samples/MyCompany.AuthPlatform.ClientSample/README.md#L1)

That sample is intended to call the recipient sample using the same package model.

## Related References

- [recipient_runtime_setup.md](d:/Research/acmp/docs/recipient_runtime_setup.md#L1)
- [samples/MyCompany.AuthPlatform.RecipientSample/README.md](d:/Research/acmp/samples/MyCompany.AuthPlatform.RecipientSample/README.md#L1)
