using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using System.Net;
using MyCompany.AuthPlatform.Application;
using MyCompany.AuthPlatform.Hmac;
using MyCompany.AuthPlatform.Hmac.Client;
using MyCompany.AuthPlatform.Packaging;
using MyCompany.Shared.Contracts.Domain;
using Xunit;

namespace MyCompany.AuthPlatform.Hmac.Tests;

public sealed class EncryptedFileHmacRuntimeTests
{
    [Fact]
    public async Task ServiceCredentialStore_ReloadsReplacementPackage_WhenFileChanges()
    {
        using var certificate = CreateCertificate();
        using var tempDirectory = new TemporaryDirectory();
        var protector = new X509HmacCredentialPackageProtector(new FakeCertificateResolver(certificate));
        var reader = new X509HmacCredentialPackageReader(new FakeCertificateResolver(certificate));
        var store = new EncryptedFileServiceCredentialStore(
            new ServicePackageCacheOptions
            {
                PackageDirectory = tempDirectory.Path,
                CacheTimeToLive = TimeSpan.FromMinutes(5)
            },
            reader);

        await WritePackageAsync(
            protector,
            CreateServiceDefinition(certificate, "key-uat-orders-0002", "kms-v1", [0x01, 0x02, 0x03, 0x04]),
            tempDirectory.Path);

        var original = await store.GetByKeyIdAsync("key-uat-orders-0002");
        Assert.Equal("kms-v1", original.KeyVersion);

        await WritePackageAsync(
            protector,
            CreateServiceDefinition(certificate, "key-uat-orders-0002", "kms-v2", [0x09, 0x08, 0x07, 0x06]),
            tempDirectory.Path);

        var reloaded = await store.GetByKeyIdAsync("key-uat-orders-0002");

        Assert.Equal("kms-v2", reloaded.KeyVersion);
        Assert.Equal(Convert.ToBase64String([0x09, 0x08, 0x07, 0x06]), Convert.ToBase64String(reloaded.Secret));
    }

    [Fact]
    public async Task ServiceCredentialStore_UsesLastKnownGoodPackage_WhenReplacementIsInvalid()
    {
        using var certificate = CreateCertificate();
        using var tempDirectory = new TemporaryDirectory();
        var protector = new X509HmacCredentialPackageProtector(new FakeCertificateResolver(certificate));
        var reader = new X509HmacCredentialPackageReader(new FakeCertificateResolver(certificate));
        var store = new EncryptedFileServiceCredentialStore(
            new ServicePackageCacheOptions
            {
                PackageDirectory = tempDirectory.Path,
                CacheTimeToLive = TimeSpan.FromMinutes(5)
            },
            reader);

        await WritePackageAsync(
            protector,
            CreateServiceDefinition(certificate, "key-uat-orders-0003", "kms-v1", [0x11, 0x22, 0x33, 0x44]),
            tempDirectory.Path);

        var original = await store.GetByKeyIdAsync("key-uat-orders-0003");
        var packagePath = Path.Combine(tempDirectory.Path, "key-uat-orders-0003.service.acmppkg.json");
        await File.WriteAllTextAsync(packagePath, "{ invalid-json");
        File.SetLastWriteTimeUtc(packagePath, DateTime.UtcNow.AddSeconds(5));

        var fallback = await store.GetByKeyIdAsync("key-uat-orders-0003");

        Assert.Equal(original.KeyVersion, fallback.KeyVersion);
        Assert.Equal(Convert.ToBase64String(original.Secret), Convert.ToBase64String(fallback.Secret));
    }

    [Fact]
    public async Task ClientSigner_And_ServiceValidator_RoundTripUsingEncryptedPackages()
    {
        using var certificate = CreateCertificate();
        using var tempDirectory = new TemporaryDirectory();
        var resolver = new FakeCertificateResolver(certificate);
        var protector = new X509HmacCredentialPackageProtector(resolver);
        var reader = new X509HmacCredentialPackageReader(resolver);
        var keyId = "key-uat-orders-0004";
        var secret = new byte[] { 0x10, 0x20, 0x30, 0x40 };

        await WritePackageAsync(
            protector,
            CreateServiceDefinition(certificate, keyId, "kms-v1", secret),
            tempDirectory.Path);
        await WritePackageAsync(
            protector,
            CreateClientDefinition(certificate, keyId, "kms-v1", secret),
            tempDirectory.Path);

        var clientStore = new EncryptedFileClientCredentialStore(
            new ClientPackageCacheOptions
            {
                PackageDirectory = tempDirectory.Path,
                CacheTimeToLive = TimeSpan.FromMinutes(5)
            },
            reader);
        var serviceStore = new EncryptedFileServiceCredentialStore(
            new ServicePackageCacheOptions
            {
                PackageDirectory = tempDirectory.Path,
                CacheTimeToLive = TimeSpan.FromMinutes(5)
            },
            reader);

        var signer = new HmacRequestSigner(clientStore);
        var validator = new HmacRequestValidator(
            serviceStore,
            new HmacValidationOptions
            {
                AllowedClockSkew = TimeSpan.FromMinutes(5),
                RequireNonce = true
            });

        var body = """{"orderId":123}"""u8.ToArray();
        var signingResult = await signer.SignAsync(
            keyId,
            new HmacSigningRequest(
                "POST",
                "/api/orders/create",
                "?b=2&a=1&a=0&flag",
                body,
                "kms-v1",
                DateTimeOffset.UtcNow,
                "nonce-123"));

        var validationResult = await validator.ValidateAsync(
            new HmacValidationRequest(
                "POST",
                "/api/orders/create",
                "?b=2&a=1&a=0&flag",
                body,
                "kms-v1",
                signingResult.Headers),
            requiredScope: "orders.write");

        Assert.True(validationResult.IsValid);
        Assert.Null(validationResult.FailureCode);
        Assert.Equal(keyId, validationResult.KeyId);
        Assert.Equal("kms-v1", signingResult.KeyVersion);
    }

    [Fact]
    public async Task ServiceCredentialStore_RejectsUnexpectedKeyVersion()
    {
        using var certificate = CreateCertificate();
        using var tempDirectory = new TemporaryDirectory();
        var protector = new X509HmacCredentialPackageProtector(new FakeCertificateResolver(certificate));
        var reader = new X509HmacCredentialPackageReader(new FakeCertificateResolver(certificate));
        using var store = new EncryptedFileServiceCredentialStore(
            new ServicePackageCacheOptions
            {
                PackageDirectory = tempDirectory.Path,
                CacheTimeToLive = TimeSpan.FromMinutes(5)
            },
            reader);

        await WritePackageAsync(
            protector,
            CreateServiceDefinition(certificate, "key-uat-orders-0005", "kms-v1", [0x12, 0x34, 0x56, 0x78]),
            tempDirectory.Path);

        await Assert.ThrowsAsync<HmacCredentialPackageException>(() =>
            store.GetByKeyIdAsync("key-uat-orders-0005", "kms-v2"));
    }

    [Fact]
    public async Task ValidationMiddleware_SetsPrincipalForValidRequest()
    {
        using var certificate = CreateCertificate();
        using var tempDirectory = new TemporaryDirectory();
        var resolver = new FakeCertificateResolver(certificate);
        var protector = new X509HmacCredentialPackageProtector(resolver);
        var reader = new X509HmacCredentialPackageReader(resolver);
        var keyId = "key-uat-orders-0006";
        var secret = new byte[] { 0x21, 0x22, 0x23, 0x24 };

        await WritePackageAsync(protector, CreateServiceDefinition(certificate, keyId, "kms-v1", secret), tempDirectory.Path);
        await WritePackageAsync(protector, CreateClientDefinition(certificate, keyId, "kms-v1", secret), tempDirectory.Path);

        using var clientStore = new EncryptedFileClientCredentialStore(
            new ClientPackageCacheOptions { PackageDirectory = tempDirectory.Path, CacheTimeToLive = TimeSpan.FromMinutes(5) },
            reader);
        using var serviceStore = new EncryptedFileServiceCredentialStore(
            new ServicePackageCacheOptions { PackageDirectory = tempDirectory.Path, CacheTimeToLive = TimeSpan.FromMinutes(5) },
            reader);
        var signer = new HmacRequestSigner(clientStore);
        var validator = new HmacRequestValidator(serviceStore);
        var middlewareReached = false;
        var middleware = new AcmpHmacValidationMiddleware(
            context =>
            {
                middlewareReached = true;
                return Task.CompletedTask;
            },
            validator,
            new AcmpHmacValidationMiddlewareOptions
            {
                RequiredScopeResolver = _ => "orders.read"
            });

        var body = """{"orderId":456}"""u8.ToArray();
        var signingResult = await signer.SignAsync(
            keyId,
            new HmacSigningRequest("POST", "/api/orders/create", null, body, "kms-v1", DateTimeOffset.UtcNow, null));

        var context = new DefaultHttpContext();
        context.Request.Method = "POST";
        context.Request.Path = "/api/orders/create";
        context.Request.Body = new MemoryStream(body);
        context.Request.ContentLength = body.Length;
        context.Request.Headers["X-Key-Id"] = signingResult.Headers.KeyId;
        context.Request.Headers["X-Timestamp"] = signingResult.Headers.Timestamp;
        context.Request.Headers["X-Signature"] = signingResult.Headers.Signature;

        await middleware.InvokeAsync(context);

        Assert.True(middlewareReached);
        Assert.True(context.User.Identity?.IsAuthenticated);
        Assert.Contains(context.User.Claims, claim => claim.Type == "acmp:key_id" && claim.Value == keyId);
    }

    [Fact]
    public async Task SigningHandler_AddsExpectedHmacHeaders()
    {
        using var certificate = CreateCertificate();
        using var tempDirectory = new TemporaryDirectory();
        var resolver = new FakeCertificateResolver(certificate);
        var protector = new X509HmacCredentialPackageProtector(resolver);
        var reader = new X509HmacCredentialPackageReader(resolver);
        var keyId = "key-uat-orders-0007";

        await WritePackageAsync(
            protector,
            CreateClientDefinition(certificate, keyId, "kms-v1", [0x31, 0x32, 0x33, 0x34]),
            tempDirectory.Path);

        using var clientStore = new EncryptedFileClientCredentialStore(
            new ClientPackageCacheOptions { PackageDirectory = tempDirectory.Path, CacheTimeToLive = TimeSpan.FromMinutes(5) },
            reader);
        var signer = new HmacRequestSigner(clientStore);
        var terminalHandler = new RecordingHandler();
        using var handler = new AcmpHmacSigningHandler(
        signer,
        new AcmpHmacSigningHandlerOptions
        {
            KeyId = keyId,
            ExpectedKeyVersion = "kms-v1",
            NonceGenerator = () => "nonce-xyz"
        })
        {
            InnerHandler = terminalHandler
        };
        using var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://example.test")
        };

        var response = await httpClient.PostAsync("/api/orders/create?mode=full", new StringContent("""{"orderId":789}"""));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(terminalHandler.LastRequest);
        Assert.True(terminalHandler.LastRequest!.Headers.Contains("X-Key-Id"));
        Assert.True(terminalHandler.LastRequest.Headers.Contains("X-Timestamp"));
        Assert.True(terminalHandler.LastRequest.Headers.Contains("X-Signature"));
        Assert.True(terminalHandler.LastRequest.Headers.Contains("X-Nonce"));
    }

    private static async Task WritePackageAsync(
        X509HmacCredentialPackageProtector protector,
        HmacCredentialPackageDefinition definition,
        string directoryPath)
    {
        var issued = await protector.ProtectAsync(definition);
        var packagePath = Path.Combine(directoryPath, issued.FileName);
        await File.WriteAllBytesAsync(packagePath, issued.PackageBytes);
        File.SetLastWriteTimeUtc(packagePath, DateTime.UtcNow.AddMilliseconds(Random.Shared.Next(100, 900)));
    }

    private static HmacCredentialPackageDefinition CreateServiceDefinition(
        X509Certificate2 certificate,
        string keyId,
        string keyVersion,
        byte[] secret) =>
        new(
            CredentialPackageType.ServiceValidation,
            $"pkg-{Guid.NewGuid():N}",
            Guid.NewGuid(),
            keyId,
            keyVersion,
            CredentialStatus.Active,
            DeploymentEnvironment.Uat,
            DateTimeOffset.UtcNow.AddDays(7),
            DateTimeOffset.UtcNow,
            new HmacCredentialPackageProtectionBinding(
                certificate.Thumbprint ?? string.Empty,
                "CurrentUser",
                "My"),
            "HMACSHA256",
            ["orders.read", "orders.write"],
            secret,
            null);

    private static HmacCredentialPackageDefinition CreateClientDefinition(
        X509Certificate2 certificate,
        string keyId,
        string keyVersion,
        byte[] secret) =>
        new(
            CredentialPackageType.ClientSigning,
            $"pkg-{Guid.NewGuid():N}",
            Guid.NewGuid(),
            keyId,
            keyVersion,
            CredentialStatus.Active,
            DeploymentEnvironment.Uat,
            DateTimeOffset.UtcNow.AddDays(7),
            DateTimeOffset.UtcNow,
            new HmacCredentialPackageProtectionBinding(
                certificate.Thumbprint ?? string.Empty,
                "CurrentUser",
                "My"),
            "HMACSHA256",
            ["orders.read", "orders.write"],
            secret,
            "acmp-hmac-v1");

    private static X509Certificate2 CreateCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=acmp-hmac-runtime-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }

    private sealed class FakeCertificateResolver : IX509CertificateResolver
    {
        private readonly X509Certificate2 _certificate;

        public FakeCertificateResolver(X509Certificate2 certificate)
        {
            _certificate = certificate;
        }

        public X509Certificate2 Resolve(HmacCredentialPackageProtectionBinding protectionBinding) => _certificate;
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"acmp-hmac-tests-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }
}
