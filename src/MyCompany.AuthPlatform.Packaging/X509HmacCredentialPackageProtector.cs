using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using MyCompany.AuthPlatform.Application;

namespace MyCompany.AuthPlatform.Packaging;

public sealed class X509HmacCredentialPackageProtector : IHmacCredentialPackageProtector
{
    private const string SchemaVersion = "acmp.hmac.package.v1";
    private const string ServiceContentType = "application/vnd.acmp.hmac-service-package+json";
    private const string ClientContentType = "application/vnd.acmp.hmac-client-package+json";
    private const string ContentEncryptionAlgorithm = "A256GCM";
    private const string KeyEncryptionAlgorithm = "RSA-OAEP-256";

    private readonly IX509CertificateResolver _certificateResolver;

    public X509HmacCredentialPackageProtector(IX509CertificateResolver certificateResolver)
    {
        _certificateResolver = certificateResolver;
    }

    public Task<IssuedCredentialPackage> ProtectAsync(
        HmacCredentialPackageDefinition definition,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (definition.Secret.Length == 0)
        {
            throw new ApplicationServiceException(500, "package_issuance_failed", "Credential secret material is not available for package issuance.");
        }

        var certificate = _certificateResolver.Resolve(definition.ProtectionBinding);
        using var rsa = certificate.GetRSAPublicKey()
            ?? throw new ApplicationServiceException(400, "package_binding_invalid", "The requested X.509 certificate does not expose an RSA public key.");

        var payload = CreatePayload(definition);
        var payloadBytes = JsonSerializer.SerializeToUtf8Bytes(payload);
        var contentEncryptionKey = RandomNumberGenerator.GetBytes(32);
        var payloadNonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[payloadBytes.Length];
        var authTag = new byte[16];

        using (var aesGcm = new AesGcm(contentEncryptionKey, 16))
        {
            aesGcm.Encrypt(payloadNonce, payloadBytes, ciphertext, authTag);
        }

        var encryptedDataKey = rsa.Encrypt(contentEncryptionKey, RSAEncryptionPadding.OaepSHA256);
        CryptographicOperations.ZeroMemory(contentEncryptionKey);

        var envelope = new PackageEnvelope(
            SchemaVersion,
            definition.PackageType.ToString(),
            definition.PackageId,
            definition.CredentialId,
            definition.KeyId,
            definition.KeyVersion,
            definition.CredentialStatus.ToString(),
            definition.Environment.ToString(),
            definition.ExpiresAt,
            definition.IssuedAt,
            new ProtectionBindingEnvelope(
                "X509Thumbprint",
                NormalizeThumbprint(definition.ProtectionBinding.CertificateThumbprint),
                definition.ProtectionBinding.StoreLocation,
                definition.ProtectionBinding.StoreName),
            new CryptoMetadataEnvelope(
                ContentEncryptionAlgorithm,
                KeyEncryptionAlgorithm,
                Convert.ToBase64String(payloadNonce),
                Convert.ToBase64String(encryptedDataKey)),
            Convert.ToBase64String(ciphertext),
            Convert.ToBase64String(authTag));

        var packageBytes = JsonSerializer.SerializeToUtf8Bytes(envelope, JsonOptions);
        var (fileName, contentType) = definition.PackageType switch
        {
            CredentialPackageType.ServiceValidation => ($"{definition.KeyId}.service.acmppkg.json", ServiceContentType),
            CredentialPackageType.ClientSigning => ($"{definition.KeyId}.client.acmppkg.json", ClientContentType),
            _ => throw new ApplicationServiceException(500, "package_issuance_failed", "Unsupported credential package type.")
        };

        return Task.FromResult(new IssuedCredentialPackage(
            definition.CredentialId,
            definition.KeyId,
            definition.PackageType.ToString(),
            fileName,
            contentType,
            definition.IssuedAt,
            definition.KeyVersion,
            definition.PackageId,
            packageBytes));
    }

    private static object CreatePayload(HmacCredentialPackageDefinition definition)
    {
        var secretBase64 = Convert.ToBase64String(definition.Secret);

        return definition.PackageType switch
        {
            CredentialPackageType.ServiceValidation => new
            {
                secretBase64,
                hmacAlgorithm = definition.HmacAlgorithm,
                scopes = definition.Scopes
            },
            CredentialPackageType.ClientSigning => new
            {
                secretBase64,
                hmacAlgorithm = definition.HmacAlgorithm,
                canonicalSigningProfileId = definition.CanonicalSigningProfileId ?? "acmp-hmac-v1",
                scopes = definition.Scopes
            },
            _ => throw new ApplicationServiceException(500, "package_issuance_failed", "Unsupported credential package type.")
        };
    }

    private static string NormalizeThumbprint(string? thumbprint) =>
        string.Concat((thumbprint ?? string.Empty).Where(ch => !char.IsWhiteSpace(ch))).ToUpperInvariant();

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    private sealed record PackageEnvelope(
        string SchemaVersion,
        string PackageType,
        string PackageId,
        Guid CredentialId,
        string KeyId,
        string KeyVersion,
        string CredentialStatus,
        string Environment,
        DateTimeOffset ExpiresAt,
        DateTimeOffset IssuedAt,
        ProtectionBindingEnvelope ProtectionBinding,
        CryptoMetadataEnvelope CryptoMetadata,
        string Ciphertext,
        string AuthTag);

    private sealed record ProtectionBindingEnvelope(
        string BindingType,
        string CertificateThumbprint,
        string StoreLocation,
        string StoreName);

    private sealed record CryptoMetadataEnvelope(
        string ContentEncryptionAlgorithm,
        string KeyEncryptionAlgorithm,
        string PayloadNonce,
        string EncryptedDataKey);
}
