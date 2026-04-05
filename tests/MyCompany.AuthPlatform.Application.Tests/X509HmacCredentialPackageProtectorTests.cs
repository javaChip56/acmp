using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using MyCompany.AuthPlatform.Application;
using MyCompany.AuthPlatform.Packaging;
using MyCompany.Shared.Contracts.Domain;
using Xunit;

namespace MyCompany.AuthPlatform.Application.Tests;

public sealed class X509HmacCredentialPackageProtectorTests
{
    [Fact]
    public async Task ProtectAsync_CreatesDecryptableClientPackageEnvelope()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=acmp-package-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

        var protector = new X509HmacCredentialPackageProtector(new FakeCertificateResolver(certificate));
        var definition = new HmacCredentialPackageDefinition(
            CredentialPackageType.ClientSigning,
            PackageId: "pkg-test-001",
            CredentialId: Guid.NewGuid(),
            KeyId: "key-uat-001",
            KeyVersion: "kms-v1",
            CredentialStatus: CredentialStatus.Active,
            Environment: DeploymentEnvironment.Uat,
            ExpiresAt: DateTimeOffset.UtcNow.AddDays(7),
            IssuedAt: DateTimeOffset.UtcNow,
            ProtectionBinding: new HmacCredentialPackageProtectionBinding(
                RecipientProtectionBindingTypes.X509StoreThumbprint,
                certificate.Thumbprint ?? string.Empty,
                "CurrentUser",
                "My",
                null,
                null,
                null),
            HmacAlgorithm: "HMACSHA256",
            Scopes: ["orders.read", "orders.write"],
            Secret: [0x10, 0x20, 0x30, 0x40],
            CanonicalSigningProfileId: "acmp-hmac-v1");

        var issued = await protector.ProtectAsync(definition);
        using var document = JsonDocument.Parse(issued.PackageBytes);
        var root = document.RootElement;

        Assert.Equal("acmp.hmac.package.v1", root.GetProperty("schemaVersion").GetString());
        Assert.Equal("ClientSigning", root.GetProperty("packageType").GetString());
        Assert.Equal("application/vnd.acmp.hmac-client-package+json", issued.ContentType);

        var encryptedDataKey = Convert.FromBase64String(root.GetProperty("cryptoMetadata").GetProperty("encryptedDataKey").GetString()!);
        var nonce = Convert.FromBase64String(root.GetProperty("cryptoMetadata").GetProperty("payloadNonce").GetString()!);
        var ciphertext = Convert.FromBase64String(root.GetProperty("ciphertext").GetString()!);
        var tag = Convert.FromBase64String(root.GetProperty("authTag").GetString()!);

        var contentKey = rsa.Decrypt(encryptedDataKey, RSAEncryptionPadding.OaepSHA256);
        var plaintext = new byte[ciphertext.Length];
        using (var aesGcm = new AesGcm(contentKey, 16))
        {
            aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
        }

        using var payloadDocument = JsonDocument.Parse(plaintext);
        var payload = payloadDocument.RootElement;

        Assert.Equal("HMACSHA256", payload.GetProperty("hmacAlgorithm").GetString());
        Assert.Equal("acmp-hmac-v1", payload.GetProperty("canonicalSigningProfileId").GetString());
        Assert.Equal(Convert.ToBase64String(definition.Secret), payload.GetProperty("secretBase64").GetString());
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
