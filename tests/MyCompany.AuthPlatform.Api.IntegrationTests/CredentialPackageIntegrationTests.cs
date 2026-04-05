using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using MyCompany.AuthPlatform.Application;
using MyCompany.AuthPlatform.Api;
using MyCompany.AuthPlatform.Packaging;
using Xunit;

namespace MyCompany.AuthPlatform.Api.IntegrationTests;

public sealed class CredentialPackageIntegrationTests
{
    private static readonly Guid SeededActiveCredentialId = Guid.Parse("bd0dd9fc-90d2-4dc8-a99e-5f5d65d8b041");

    [Fact]
    public async Task IssueClientPackage_ReturnsDecryptableEnvelope()
    {
        using var certificate = CreateCertificate();
        using var factory = new PackageConfiguredApiFactory(certificate);
        using var client = factory.CreateClient();
        var token = await IssueTokenAsync(client, "operator.demo", "OperatorPass!123");

        var response = await SendAuthorizedPostAsync(
            client,
            $"/api/credentials/{SeededActiveCredentialId}/issue-client-package",
            new
            {
                bindingType = "X509StoreThumbprint",
                certificateThumbprint = certificate.Thumbprint,
                storeLocation = "CurrentUser",
                storeName = "My",
                certificatePath = (string?)null,
                privateKeyPath = (string?)null,
                certificatePem = (string?)null,
                reason = "Integration test client package issuance."
            },
            token);

        response.EnsureSuccessStatusCode();
        Assert.Equal("application/vnd.acmp.hmac-client-package+json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("ClientSigning", response.Headers.GetValues("X-Package-Type").Single());

        var packageBytes = await response.Content.ReadAsByteArrayAsync();
        using var packageDocument = JsonDocument.Parse(packageBytes);
        var packageRoot = packageDocument.RootElement;

        Assert.Equal("acmp.hmac.package.v1", packageRoot.GetProperty("schemaVersion").GetString());
        Assert.Equal("ClientSigning", packageRoot.GetProperty("packageType").GetString());
        Assert.Equal("key-uat-orders-0002", packageRoot.GetProperty("keyId").GetString());

        var payload = DecryptPayload(packageRoot, certificate);
        Assert.Equal("HMACSHA256", payload.GetProperty("hmacAlgorithm").GetString());
        Assert.Equal("acmp-hmac-v1", payload.GetProperty("canonicalSigningProfileId").GetString());
        var secret = Convert.FromBase64String(payload.GetProperty("secretBase64").GetString()!);
        Assert.Equal(32, secret.Length);

        var scopes = payload.GetProperty("scopes").EnumerateArray().Select(element => element.GetString()!).ToArray();
        Assert.Equal(["orders.read", "orders.write"], scopes);
    }

    [Fact]
    public async Task IssueServicePackage_WritesAuditEntryAccessibleToAdministrator()
    {
        using var certificate = CreateCertificate();
        using var factory = new PackageConfiguredApiFactory(certificate);
        using var client = factory.CreateClient();
        var operatorToken = await IssueTokenAsync(client, "operator.demo", "OperatorPass!123");

        var packageResponse = await SendAuthorizedPostAsync(
            client,
            $"/api/credentials/{SeededActiveCredentialId}/issue-encrypted-package",
            new
            {
                bindingType = "X509StoreThumbprint",
                certificateThumbprint = certificate.Thumbprint,
                storeLocation = "CurrentUser",
                storeName = "My",
                certificatePath = (string?)null,
                privateKeyPath = (string?)null,
                certificatePem = (string?)null,
                reason = "Integration test service package issuance."
            },
            operatorToken);

        packageResponse.EnsureSuccessStatusCode();
        Assert.Equal("application/vnd.acmp.hmac-service-package+json", packageResponse.Content.Headers.ContentType?.MediaType);
        Assert.Equal("ServiceValidation", packageResponse.Headers.GetValues("X-Package-Type").Single());

        var administratorToken = await IssueTokenAsync(client, "administrator.demo", "AdministratorPass!123");
        var auditResponse = await SendAuthorizedGetAsync(client, "/api/audit", administratorToken);
        auditResponse.EnsureSuccessStatusCode();

        var auditEntries = await auditResponse.Content.ReadFromJsonAsync<JsonArray>();
        Assert.NotNull(auditEntries);

        var packageAuditEntry = auditEntries!
            .OfType<JsonObject>()
            .FirstOrDefault(entry =>
                string.Equals(entry["action"]?.GetValue<string>(), "ServiceValidationPackageIssued", StringComparison.Ordinal) &&
                string.Equals(entry["targetId"]?.GetValue<string>(), SeededActiveCredentialId.ToString(), StringComparison.Ordinal));

        Assert.NotNull(packageAuditEntry);
    }

    [Fact]
    public async Task HealthEndpoint_ExposesMiniKmsProviderAndKeyVersion()
    {
        using var certificate = CreateCertificate();
        using var factory = new PackageConfiguredApiFactory(certificate);
        using var client = factory.CreateClient();

        var health = await client.GetFromJsonAsync<JsonObject>("/health");

        Assert.Equal("LocalMiniKms", health?["miniKmsProvider"]?.GetValue<string>());
        Assert.Equal("kms-v1", health?["miniKmsKeyVersion"]?.GetValue<string>());
    }

    private static JsonElement DecryptPayload(JsonElement packageRoot, X509Certificate2 certificate)
    {
        using var privateKey = certificate.GetRSAPrivateKey()
            ?? throw new InvalidOperationException("A private key was required to decrypt the package.");

        var encryptedDataKey = Convert.FromBase64String(packageRoot.GetProperty("cryptoMetadata").GetProperty("encryptedDataKey").GetString()!);
        var payloadNonce = Convert.FromBase64String(packageRoot.GetProperty("cryptoMetadata").GetProperty("payloadNonce").GetString()!);
        var ciphertext = Convert.FromBase64String(packageRoot.GetProperty("ciphertext").GetString()!);
        var authTag = Convert.FromBase64String(packageRoot.GetProperty("authTag").GetString()!);
        var contentEncryptionKey = privateKey.Decrypt(encryptedDataKey, RSAEncryptionPadding.OaepSHA256);
        var plaintext = new byte[ciphertext.Length];

        using (var aesGcm = new AesGcm(contentEncryptionKey, 16))
        {
            aesGcm.Decrypt(payloadNonce, ciphertext, authTag, plaintext);
        }

        CryptographicOperations.ZeroMemory(contentEncryptionKey);
        using var payloadDocument = JsonDocument.Parse(plaintext);
        return payloadDocument.RootElement.Clone();
    }

    private static X509Certificate2 CreateCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=acmp-package-api-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }

    private static async Task<string> IssueTokenAsync(HttpClient client, string username, string password)
    {
        var response = await client.PostAsJsonAsync("/api/auth/token", new
        {
            username,
            password
        });

        response.EnsureSuccessStatusCode();
        var payload = await response.Content.ReadFromJsonAsync<JsonObject>();
        return payload?["accessToken"]?.GetValue<string>()
            ?? throw new InvalidOperationException("Access token was not returned by the API.");
    }

    private static Task<HttpResponseMessage> SendAuthorizedGetAsync(HttpClient client, string path, string token)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client.SendAsync(request);
    }

    private static Task<HttpResponseMessage> SendAuthorizedPostAsync<TPayload>(HttpClient client, string path, TPayload payload, string token)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = JsonContent.Create(payload)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client.SendAsync(request);
    }

    private sealed class PackageConfiguredApiFactory : WebApplicationFactory<ApiEntryPoint>
    {
        private readonly X509Certificate2 _certificate;

        public PackageConfiguredApiFactory(X509Certificate2 certificate)
        {
            _certificate = certificate;
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.ConfigureAppConfiguration((_, configBuilder) =>
            {
                configBuilder.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Persistence:Provider"] = "InMemoryDemo",
                    ["DemoMode:SeedOnStartup"] = "true",
                    ["Authentication:Mode"] = "EmbeddedIdentity"
                });
            });
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IX509CertificateResolver>();
                services.AddSingleton<IX509CertificateResolver>(new FakeCertificateResolver(_certificate));
            });
        }
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
}
