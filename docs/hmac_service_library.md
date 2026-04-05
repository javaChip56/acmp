# HMAC Service Library

This guide shows how to use [MyCompany.AuthPlatform.Hmac](d:/Research/acmp/src/MyCompany.AuthPlatform.Hmac/AcmpHmacValidationMiddleware.cs#L1) in a protected recipient API.

Its job is to:

- load a service-validation package from disk
- decrypt and validate that package
- validate inbound ACMP HMAC headers
- establish an authenticated principal for the request

## Main Types

- [EncryptedFileServiceCredentialStore](d:/Research/acmp/src/MyCompany.AuthPlatform.Hmac/EncryptedFileServiceCredentialStore.cs#L10)
  Loads and caches encrypted service-validation packages.

- [HmacRequestValidator](d:/Research/acmp/src/MyCompany.AuthPlatform.Hmac/HmacRequestValidator.cs#L20)
  Rebuilds the canonical request and validates the signature.

- [AcmpHmacValidationMiddleware](d:/Research/acmp/src/MyCompany.AuthPlatform.Hmac/AcmpHmacValidationMiddleware.cs#L14)
  ASP.NET Core middleware that turns successful validation into an authenticated principal.

- [ServicePackageCacheOptions](d:/Research/acmp/src/MyCompany.AuthPlatform.Hmac/EncryptedFileServiceCredentialStore.cs#L5)
  Runtime configuration for encrypted-file validation mode.

## Configuration Shape

Example:

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

For X.509-based package bindings, the `PackageReadOptions` can be omitted or limited to `ExpectedBindingType`/`ExpectedBindingId`.

## Minimal ASP.NET Core Setup

```csharp
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http.Json;
using MyCompany.AuthPlatform.Hmac;
using MyCompany.AuthPlatform.Packaging;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<JsonOptions>(options =>
{
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
});

var packageOptions = builder.Configuration
    .GetSection("AcmpHmac:Validation")
    .Get<ServicePackageCacheOptions>()
    ?? throw new InvalidOperationException("AcmpHmac:Validation configuration is required.");

builder.Services.AddSingleton(packageOptions);
builder.Services.AddSingleton<IX509CertificateResolver, CompositeX509CertificateResolver>();
builder.Services.AddSingleton<IHmacCredentialPackageReader, X509HmacCredentialPackageReader>();
builder.Services.AddSingleton<EncryptedFileServiceCredentialStore>();
builder.Services.AddSingleton(serviceProvider =>
    new HmacRequestValidator(
        serviceProvider.GetRequiredService<EncryptedFileServiceCredentialStore>(),
        new HmacValidationOptions
        {
            AllowedClockSkew = TimeSpan.FromMinutes(5),
            RequireNonce = true
        }));

var app = builder.Build();

app.UseAcmpHmacValidation(new AcmpHmacValidationMiddlewareOptions
{
    RequiredScopeResolver = context =>
        context.Request.Path.StartsWithSegments("/api/orders", StringComparison.OrdinalIgnoreCase)
            ? "orders.write"
            : null
});
```

For a runnable reference, see [samples/MyCompany.AuthPlatform.RecipientSample/Program.cs](d:/Research/acmp/samples/MyCompany.AuthPlatform.RecipientSample/Program.cs#L1).

## Resulting Principal

On success, the middleware sets `HttpContext.User` with claims such as:

- `acmp:key_id`
- `acmp:key_version`
- `scope`

Your endpoint code can read those claims directly.

## Failure Behavior

The middleware returns:

- `401` for missing or invalid HMAC authentication
- `403` for authenticated requests that do not have the required scope

Validation is fail-closed:

- missing package
- invalid package
- wrong binding
- expired package
- invalid signature

all result in rejection.

## Related References

- [recipient_runtime_setup.md](d:/Research/acmp/docs/recipient_runtime_setup.md#L1)
- [samples/MyCompany.AuthPlatform.RecipientSample/README.md](d:/Research/acmp/samples/MyCompany.AuthPlatform.RecipientSample/README.md#L1)
