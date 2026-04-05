# Recipient Runtime Setup

This note shows how a recipient service or client host can load ACMP encrypted credential packages at runtime, including the `ExternalRsaPublicKey` binding that uses a local PEM private key instead of an X.509 certificate.

For a runnable reference host, see [samples/MyCompany.AuthPlatform.RecipientSample/README.md](d:/Research/acmp/samples/MyCompany.AuthPlatform.RecipientSample/README.md#L1).

## What The Recipient Needs

For `EncryptedFile` mode, the recipient host needs:

- a package directory that contains the issued `.acmppkg.json` files
- the expected HMAC `keyId`
- optionally the expected credential `keyVersion`
- the local decryption material for the package binding

For `ExternalRsaPublicKey`, that local decryption material is:

- the recipient private key PEM file
- the expected binding metadata from ACMP:
  - `bindingId`
  - `bindingType`
  - binding `keyId`
  - binding `keyVersion`
  - `publicKeyFingerprint`

## Runtime Options Model

Both encrypted-file stores now support nested package-read options:

- [ServicePackageCacheOptions](d:/Research/acmp/src/MyCompany.AuthPlatform.Hmac/EncryptedFileServiceCredentialStore.cs#L5)
- [ClientPackageCacheOptions](d:/Research/acmp/src/MyCompany.AuthPlatform.Hmac.Client/EncryptedFileClientCredentialStore.cs#L5)
- [HmacCredentialPackageReadOptions](d:/Research/acmp/src/MyCompany.AuthPlatform.Packaging/HmacCredentialPackageReader.cs#L46)

Those options can be created directly in code or bound from configuration.

## Example Configuration

Example app settings for a recipient service:

```json
{
  "AcmpHmac": {
    "Validation": {
      "PackageDirectory": "C:\\Acmp\\Packages",
      "CacheTimeToLive": "00:05:00",
      "PreloadKeyIds": [ "key-uat-orders-0004-rsa" ],
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

Example app settings for a client service:

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

## Service-Side Validation Example

```csharp
using MyCompany.AuthPlatform.Hmac;
using MyCompany.AuthPlatform.Packaging;

var servicePackageOptions = configuration
    .GetSection("AcmpHmac:Validation")
    .Get<ServicePackageCacheOptions>()
    ?? throw new InvalidOperationException("Missing AcmpHmac:Validation configuration.");

var reader = new X509HmacCredentialPackageReader(new CompositeX509CertificateResolver());
var credentialStore = new EncryptedFileServiceCredentialStore(servicePackageOptions, reader);
var validator = new HmacRequestValidator(credentialStore);

app.UseAcmpHmacValidation(new AcmpHmacValidationMiddlewareOptions
{
    RequiredScopeResolver = context => "orders.read"
});
```

For `ExternalRsaPublicKey`, the `CompositeX509CertificateResolver` will not be used during package decryption, because the reader will unwrap the package with the configured PEM private key path.

## Client-Side Signing Example

```csharp
using MyCompany.AuthPlatform.Hmac.Client;
using MyCompany.AuthPlatform.Packaging;

var signingPackageOptions = configuration
    .GetSection("AcmpHmac:Signing")
    .Get<ClientPackageCacheOptions>()
    ?? throw new InvalidOperationException("Missing AcmpHmac:Signing configuration.");

var signingOptions = configuration
    .GetSection("AcmpHmac:Signing")
    .Get<AcmpHmacSigningHandlerOptions>()
    ?? throw new InvalidOperationException("Missing AcmpHmac signing handler configuration.");

var reader = new X509HmacCredentialPackageReader(new CompositeX509CertificateResolver());
var credentialStore = new EncryptedFileClientCredentialStore(signingPackageOptions, reader);
var signer = new HmacRequestSigner(credentialStore);

services.AddHttpClient("orders-api")
    .AddHttpMessageHandler(_ => new AcmpHmacSigningHandler(signer, signingOptions));
```

At minimum, the signing handler needs:

- `KeyId`
- optionally `ExpectedKeyVersion`

The package decryption details still come from `ClientPackageCacheOptions.PackageReadOptions`.

## Expected Runtime Behavior

For `ExternalRsaPublicKey`, the runtime reader will reject the package when:

- the PEM private key file is missing
- the PEM private key file cannot be parsed
- the private key does not match the package `publicKeyFingerprint`
- the package `bindingId` does not match the configured binding
- the package binding `keyId` or `keyVersion` do not match
- the package credential `keyVersion` does not match the caller expectation

## Operational Notes

- Keep the private key on the recipient side only.
- Restrict file permissions on the PEM private key path.
- Update the runtime config when the recipient binding rotates.
- During binding rollover, deploy the new private key and new package together.
- Keep the old private key only while old packages may still need to be read.
