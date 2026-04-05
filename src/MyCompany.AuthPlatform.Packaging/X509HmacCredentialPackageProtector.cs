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

        using var wrappingKey = ResolveWrappingKey(definition.ProtectionBinding, out var certificate);

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

        var encryptedDataKey = wrappingKey.Encrypt(contentEncryptionKey, RSAEncryptionPadding.OaepSHA256);
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
            CreateProtectionBindingEnvelope(definition.ProtectionBinding, certificate),
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

    private RSA ResolveWrappingKey(
        HmacCredentialPackageProtectionBinding binding,
        out X509Certificate2? certificate)
    {
        if (string.Equals(binding.BindingType, RecipientProtectionBindingTypes.ExternalRsaPublicKey, StringComparison.Ordinal))
        {
            certificate = null;
            var publicKeyPem = binding.PublicKeyPem?.Trim();
            if (string.IsNullOrWhiteSpace(publicKeyPem))
            {
                throw new ApplicationServiceException(400, "package_binding_invalid", "The requested external RSA public-key binding does not include public key material.");
            }

            try
            {
                var rsa = RSA.Create();
                rsa.ImportFromPem(publicKeyPem);
                return rsa;
            }
            catch (Exception exception) when (exception is ArgumentException or CryptographicException)
            {
                throw new ApplicationServiceException(400, "package_binding_invalid", "The requested external RSA public-key binding could not be parsed.");
            }
        }

        certificate = _certificateResolver.Resolve(binding);
        return certificate.GetRSAPublicKey()
            ?? throw new ApplicationServiceException(400, "package_binding_invalid", "The requested X.509 certificate does not expose an RSA public key.");
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

    private static ProtectionBindingEnvelope CreateProtectionBindingEnvelope(
        HmacCredentialPackageProtectionBinding binding,
        X509Certificate2? certificate)
    {
        var bindingType = binding.BindingType?.Trim();

        if (string.Equals(bindingType, RecipientProtectionBindingTypes.X509StoreThumbprint, StringComparison.Ordinal))
        {
            return new ProtectionBindingEnvelope(
                RecipientProtectionBindingTypes.X509StoreThumbprint,
                binding.BindingId,
                NormalizeThumbprint(binding.CertificateThumbprint),
                binding.StoreLocation,
                binding.StoreName,
                null,
                null,
                null,
                null,
                null,
                KeyEncryptionAlgorithm);
        }

        if (string.Equals(bindingType, RecipientProtectionBindingTypes.X509File, StringComparison.Ordinal))
        {
            return new ProtectionBindingEnvelope(
                RecipientProtectionBindingTypes.X509File,
                binding.BindingId,
                NormalizeThumbprint(certificate?.Thumbprint),
                null,
                null,
                binding.CertificatePath,
                binding.PrivateKeyPath,
                null,
                null,
                null,
                KeyEncryptionAlgorithm);
        }

        if (string.Equals(bindingType, RecipientProtectionBindingTypes.ExternalRsaPublicKey, StringComparison.Ordinal))
        {
            return new ProtectionBindingEnvelope(
                RecipientProtectionBindingTypes.ExternalRsaPublicKey,
                binding.BindingId,
                null,
                null,
                null,
                null,
                null,
                binding.PublicKeyFingerprint,
                binding.KeyId,
                binding.KeyVersion,
                KeyEncryptionAlgorithm);
        }

        throw new ApplicationServiceException(400, "package_binding_invalid", "The requested protection binding type is not supported.");
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
        Guid? BindingId,
        string? CertificateThumbprint,
        string? StoreLocation,
        string? StoreName,
        string? CertificatePath,
        string? PrivateKeyPath,
        string? PublicKeyFingerprint,
        string? KeyId,
        string? KeyVersion,
        string KeyEncryptionAlgorithm);

    private sealed record CryptoMetadataEnvelope(
        string ContentEncryptionAlgorithm,
        string KeyEncryptionAlgorithm,
        string PayloadNonce,
        string EncryptedDataKey);
}
