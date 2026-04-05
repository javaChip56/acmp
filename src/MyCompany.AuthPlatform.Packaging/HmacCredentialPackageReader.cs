using System.Buffers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace MyCompany.AuthPlatform.Packaging;

public sealed class HmacCredentialPackageException : Exception
{
    public HmacCredentialPackageException(string message)
        : base(message)
    {
    }

    public HmacCredentialPackageException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

public sealed record ServiceValidationCredentialPackage(
    Guid CredentialId,
    string PackageId,
    string KeyId,
    string KeyVersion,
    string Environment,
    DateTimeOffset ExpiresAt,
    DateTimeOffset IssuedAt,
    string HmacAlgorithm,
    IReadOnlyList<string> Scopes,
    byte[] Secret);

public sealed record ClientSigningCredentialPackage(
    Guid CredentialId,
    string PackageId,
    string KeyId,
    string KeyVersion,
    string Environment,
    DateTimeOffset ExpiresAt,
    DateTimeOffset IssuedAt,
    string HmacAlgorithm,
    string CanonicalSigningProfileId,
    IReadOnlyList<string> Scopes,
    byte[] Secret);

public sealed class HmacCredentialPackageReadOptions
{
    public Guid? ExpectedBindingId { get; set; }

    public string? ExpectedBindingType { get; set; }

    public string? ExpectedBindingKeyId { get; set; }

    public string? ExpectedBindingKeyVersion { get; set; }

    public string? ExpectedPublicKeyFingerprint { get; set; }

    public string? ExternalRsaPrivateKeyPath { get; set; }
}

public interface IHmacCredentialPackageReader
{
    Task<ServiceValidationCredentialPackage> ReadServiceValidationPackageAsync(
        string packagePath,
        string expectedKeyId,
        string? expectedKeyVersion = null,
        HmacCredentialPackageReadOptions? readOptions = null,
        CancellationToken cancellationToken = default);

    Task<ClientSigningCredentialPackage> ReadClientSigningPackageAsync(
        string packagePath,
        string expectedKeyId,
        string? expectedKeyVersion = null,
        HmacCredentialPackageReadOptions? readOptions = null,
        CancellationToken cancellationToken = default);
}

public sealed class X509HmacCredentialPackageReader : IHmacCredentialPackageReader
{
    private const string SupportedSchemaVersion = "acmp.hmac.package.v1";
    private const string ServiceValidationPackageType = "ServiceValidation";
    private const string ClientSigningPackageType = "ClientSigning";
    private const string ContentEncryptionAlgorithm = "A256GCM";
    private const string KeyEncryptionAlgorithm = "RSA-OAEP-256";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private readonly IX509CertificateResolver _certificateResolver;

    public X509HmacCredentialPackageReader(IX509CertificateResolver certificateResolver)
    {
        _certificateResolver = certificateResolver;
    }

    public async Task<ServiceValidationCredentialPackage> ReadServiceValidationPackageAsync(
        string packagePath,
        string expectedKeyId,
        string? expectedKeyVersion = null,
        HmacCredentialPackageReadOptions? readOptions = null,
        CancellationToken cancellationToken = default)
    {
        var envelope = await ReadEnvelopeAsync(packagePath, expectedKeyId, expectedKeyVersion, readOptions, ServiceValidationPackageType, cancellationToken);
        var payload = DeserializePayload<ServicePayload>(envelope.PlaintextPayload);
        var secret = DecodeBase64(RequireText(payload.SecretBase64, "payload.secretBase64"), "payload.secretBase64");
        var scopes = NormalizeScopes(payload.Scopes);

        return new ServiceValidationCredentialPackage(
            envelope.Envelope.CredentialId,
            RequireText(envelope.Envelope.PackageId, "packageId"),
            RequireText(envelope.Envelope.KeyId, "keyId"),
            RequireText(envelope.Envelope.KeyVersion, "keyVersion"),
            RequireText(envelope.Envelope.Environment, "environment"),
            envelope.Envelope.ExpiresAt,
            envelope.Envelope.IssuedAt,
            RequireText(payload.HmacAlgorithm, "payload.hmacAlgorithm"),
            scopes,
            secret);
    }

    public async Task<ClientSigningCredentialPackage> ReadClientSigningPackageAsync(
        string packagePath,
        string expectedKeyId,
        string? expectedKeyVersion = null,
        HmacCredentialPackageReadOptions? readOptions = null,
        CancellationToken cancellationToken = default)
    {
        var envelope = await ReadEnvelopeAsync(packagePath, expectedKeyId, expectedKeyVersion, readOptions, ClientSigningPackageType, cancellationToken);
        var payload = DeserializePayload<ClientPayload>(envelope.PlaintextPayload);
        var secret = DecodeBase64(RequireText(payload.SecretBase64, "payload.secretBase64"), "payload.secretBase64");
        var scopes = NormalizeScopes(payload.Scopes);

        return new ClientSigningCredentialPackage(
            envelope.Envelope.CredentialId,
            RequireText(envelope.Envelope.PackageId, "packageId"),
            RequireText(envelope.Envelope.KeyId, "keyId"),
            RequireText(envelope.Envelope.KeyVersion, "keyVersion"),
            RequireText(envelope.Envelope.Environment, "environment"),
            envelope.Envelope.ExpiresAt,
            envelope.Envelope.IssuedAt,
            RequireText(payload.HmacAlgorithm, "payload.hmacAlgorithm"),
            RequireText(payload.CanonicalSigningProfileId, "payload.canonicalSigningProfileId"),
            scopes,
            secret);
    }

    private async Task<ValidatedEnvelope> ReadEnvelopeAsync(
        string packagePath,
        string expectedKeyId,
        string? expectedKeyVersion,
        HmacCredentialPackageReadOptions? readOptions,
        string expectedPackageType,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(packagePath))
        {
            throw new HmacCredentialPackageException("A package path is required.");
        }

        if (!File.Exists(packagePath))
        {
            throw new HmacCredentialPackageException($"The package file '{packagePath}' could not be found.");
        }

        var packageBytes = await File.ReadAllBytesAsync(packagePath, cancellationToken);
        Envelope envelope;

        try
        {
            envelope = JsonSerializer.Deserialize<Envelope>(packageBytes, JsonOptions)
                ?? throw new HmacCredentialPackageException("The package file could not be parsed.");
        }
        catch (JsonException exception)
        {
            throw new HmacCredentialPackageException("The package file is not valid JSON.", exception);
        }

        ValidateEnvelope(envelope, expectedKeyId, expectedKeyVersion, readOptions, expectedPackageType);
        using var privateKey = ResolvePrivateKey(envelope.ProtectionBinding!, readOptions);

        var encryptedDataKey = DecodeBase64(
            RequireText(envelope.CryptoMetadata!.EncryptedDataKey, "cryptoMetadata.encryptedDataKey"),
            "cryptoMetadata.encryptedDataKey");
        var payloadNonce = DecodeBase64(
            RequireText(envelope.CryptoMetadata.PayloadNonce, "cryptoMetadata.payloadNonce"),
            "cryptoMetadata.payloadNonce");
        var ciphertext = DecodeBase64(RequireText(envelope.Ciphertext, "ciphertext"), "ciphertext");
        var authTag = DecodeBase64(RequireText(envelope.AuthTag, "authTag"), "authTag");

        byte[] contentEncryptionKey;
        try
        {
            contentEncryptionKey = privateKey.Decrypt(encryptedDataKey, RSAEncryptionPadding.OaepSHA256);
        }
        catch (CryptographicException exception)
        {
            throw new HmacCredentialPackageException("The package data key could not be unwrapped with the configured certificate.", exception);
        }

        var plaintext = new byte[ciphertext.Length];

        try
        {
            using var aesGcm = new AesGcm(contentEncryptionKey, 16);
            aesGcm.Decrypt(payloadNonce, ciphertext, authTag, plaintext);
        }
        catch (CryptographicException exception)
        {
            throw new HmacCredentialPackageException("The package authentication tag could not be validated.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(contentEncryptionKey);
        }

        return new ValidatedEnvelope(envelope, plaintext);
    }

    private static TPayload DeserializePayload<TPayload>(byte[] plaintext)
    {
        try
        {
            return JsonSerializer.Deserialize<TPayload>(plaintext, JsonOptions)
                ?? throw new HmacCredentialPackageException("The decrypted package payload could not be parsed.");
        }
        catch (JsonException exception)
        {
            throw new HmacCredentialPackageException("The decrypted package payload is not valid JSON.", exception);
        }
    }

    private RSA ResolvePrivateKey(ProtectionBinding binding, HmacCredentialPackageReadOptions? readOptions)
    {
        var bindingType = RequireText(binding.BindingType, "protectionBinding.bindingType");
        if (string.Equals(bindingType, MyCompany.AuthPlatform.Application.RecipientProtectionBindingTypes.ExternalRsaPublicKey, StringComparison.Ordinal))
        {
            var privateKeyPath = NormalizeOptionalText(readOptions?.ExternalRsaPrivateKeyPath);
            if (privateKeyPath is null)
            {
                throw new HmacCredentialPackageException("ExternalRsaPublicKey package bindings require a configured PEM private key path at runtime.");
            }

            if (!File.Exists(privateKeyPath))
            {
                throw new HmacCredentialPackageException($"The configured external RSA private key file '{privateKeyPath}' could not be found.");
            }

            try
            {
                var rsa = RSA.Create();
                rsa.ImportFromPem(File.ReadAllText(privateKeyPath));
                var packageFingerprint = RequireText(binding.PublicKeyFingerprint, "protectionBinding.publicKeyFingerprint");
                var actualFingerprint = ComputePublicKeyFingerprint(rsa);

                if (!string.Equals(actualFingerprint, packageFingerprint, StringComparison.Ordinal))
                {
                    rsa.Dispose();
                    throw new HmacCredentialPackageException("The configured external RSA private key does not match the package public-key fingerprint.");
                }

                return rsa;
            }
            catch (HmacCredentialPackageException)
            {
                throw;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or CryptographicException)
            {
                throw new HmacCredentialPackageException("The configured external RSA private key could not be loaded.", exception);
            }
        }

        var normalizedThumbprint = NormalizeThumbprint(binding.CertificateThumbprint);
        var certificate = _certificateResolver.Resolve(new MyCompany.AuthPlatform.Application.HmacCredentialPackageProtectionBinding(
            bindingType,
            BindingId: binding.BindingId,
            normalizedThumbprint,
            string.Equals(bindingType, MyCompany.AuthPlatform.Application.RecipientProtectionBindingTypes.X509StoreThumbprint, StringComparison.Ordinal)
                ? RequireText(binding.StoreLocation, "protectionBinding.storeLocation")
                : null,
            string.Equals(bindingType, MyCompany.AuthPlatform.Application.RecipientProtectionBindingTypes.X509StoreThumbprint, StringComparison.Ordinal)
                ? RequireText(binding.StoreName, "protectionBinding.storeName")
                : null,
            string.Equals(bindingType, MyCompany.AuthPlatform.Application.RecipientProtectionBindingTypes.X509File, StringComparison.Ordinal)
                ? RequireText(binding.CertificatePath, "protectionBinding.certificatePath")
                : null,
            string.Equals(bindingType, MyCompany.AuthPlatform.Application.RecipientProtectionBindingTypes.X509File, StringComparison.Ordinal)
                ? NormalizeOptionalText(binding.PrivateKeyPath)
                : null,
            CertificatePem: null,
            PublicKeyPem: null,
            PublicKeyFingerprint: binding.PublicKeyFingerprint,
            KeyId: binding.KeyId,
            KeyVersion: binding.KeyVersion));

        if (!string.Equals(NormalizeThumbprint(certificate.Thumbprint), normalizedThumbprint, StringComparison.Ordinal))
        {
            throw new HmacCredentialPackageException("The resolved X.509 certificate does not match the package thumbprint binding.");
        }

        return certificate.GetRSAPrivateKey()
            ?? throw new HmacCredentialPackageException("The configured X.509 certificate does not provide an RSA private key.");
    }

    private static void ValidateEnvelope(
        Envelope envelope,
        string expectedKeyId,
        string? expectedKeyVersion,
        HmacCredentialPackageReadOptions? readOptions,
        string expectedPackageType)
    {
        if (!string.Equals(envelope.SchemaVersion, SupportedSchemaVersion, StringComparison.Ordinal))
        {
            throw new HmacCredentialPackageException("The package schema version is not supported.");
        }

        if (!string.Equals(envelope.PackageType, expectedPackageType, StringComparison.Ordinal))
        {
            throw new HmacCredentialPackageException("The package type does not match the expected usage mode.");
        }

        if (!string.Equals(envelope.KeyId, expectedKeyId, StringComparison.Ordinal))
        {
            throw new HmacCredentialPackageException("The package key identifier does not match the expected file identity.");
        }

        if (!string.IsNullOrWhiteSpace(expectedKeyVersion) &&
            !string.Equals(envelope.KeyVersion, expectedKeyVersion.Trim(), StringComparison.Ordinal))
        {
            throw new HmacCredentialPackageException("The package key version does not match the expected credential version.");
        }

        if (!string.Equals(envelope.CredentialStatus, "Active", StringComparison.Ordinal))
        {
            throw new HmacCredentialPackageException("The package credential status is not valid for runtime use.");
        }

        if (envelope.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            throw new HmacCredentialPackageException("The package has expired.");
        }

        _ = RequireText(envelope.PackageId, "packageId");
        _ = RequireText(envelope.KeyVersion, "keyVersion");
        _ = RequireText(envelope.Environment, "environment");

        if (envelope.ProtectionBinding is null)
        {
            throw new HmacCredentialPackageException("The package protection binding is missing.");
        }

        ValidateProtectionBinding(envelope.ProtectionBinding, readOptions);

        if (envelope.CryptoMetadata is null)
        {
            throw new HmacCredentialPackageException("The package crypto metadata is missing.");
        }

        if (!string.Equals(envelope.CryptoMetadata.ContentEncryptionAlgorithm, ContentEncryptionAlgorithm, StringComparison.Ordinal))
        {
            throw new HmacCredentialPackageException("The package content-encryption algorithm is not supported.");
        }

        if (!string.Equals(envelope.CryptoMetadata.KeyEncryptionAlgorithm, KeyEncryptionAlgorithm, StringComparison.Ordinal))
        {
            throw new HmacCredentialPackageException("The package key-encryption algorithm is not supported.");
        }
    }

    private static void ValidateProtectionBinding(ProtectionBinding binding, HmacCredentialPackageReadOptions? readOptions)
    {
        if (readOptions is null)
        {
            return;
        }

        var bindingType = RequireText(binding.BindingType, "protectionBinding.bindingType");
        if (!string.IsNullOrWhiteSpace(readOptions.ExpectedBindingType) &&
            !string.Equals(bindingType, readOptions.ExpectedBindingType.Trim(), StringComparison.Ordinal))
        {
            throw new HmacCredentialPackageException("The package binding type does not match the configured runtime binding type.");
        }

        if (readOptions.ExpectedBindingId.HasValue &&
            binding.BindingId != readOptions.ExpectedBindingId)
        {
            throw new HmacCredentialPackageException("The package binding identifier does not match the configured runtime binding.");
        }

        if (!string.IsNullOrWhiteSpace(readOptions.ExpectedBindingKeyId) &&
            !string.Equals(binding.KeyId, readOptions.ExpectedBindingKeyId.Trim(), StringComparison.Ordinal))
        {
            throw new HmacCredentialPackageException("The package binding key identifier does not match the configured runtime binding.");
        }

        if (!string.IsNullOrWhiteSpace(readOptions.ExpectedBindingKeyVersion) &&
            !string.Equals(binding.KeyVersion, readOptions.ExpectedBindingKeyVersion.Trim(), StringComparison.Ordinal))
        {
            throw new HmacCredentialPackageException("The package binding key version does not match the configured runtime binding.");
        }

        if (!string.IsNullOrWhiteSpace(readOptions.ExpectedPublicKeyFingerprint) &&
            !string.Equals(binding.PublicKeyFingerprint, readOptions.ExpectedPublicKeyFingerprint.Trim(), StringComparison.Ordinal))
        {
            throw new HmacCredentialPackageException("The package binding public-key fingerprint does not match the configured runtime binding.");
        }
    }

    private static IReadOnlyList<string> NormalizeScopes(string[]? scopes)
    {
        var normalized = (scopes ?? Array.Empty<string>())
            .Where(scope => !string.IsNullOrWhiteSpace(scope))
            .Select(scope => scope.Trim())
            .Distinct(StringComparer.Ordinal)
            .OrderBy(scope => scope, StringComparer.Ordinal)
            .ToArray();

        if (normalized.Length == 0)
        {
            throw new HmacCredentialPackageException("The decrypted package payload does not contain any scopes.");
        }

        return normalized;
    }

    private static byte[] DecodeBase64(string encodedValue, string fieldName)
    {
        try
        {
            return Convert.FromBase64String(encodedValue);
        }
        catch (FormatException exception)
        {
            throw new HmacCredentialPackageException($"'{fieldName}' is not valid base64 content.", exception);
        }
    }

    private static string RequireText(string? value, string fieldName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new HmacCredentialPackageException($"The required field '{fieldName}' is missing.");
        }

        return value.Trim();
    }

    private static string? NormalizeOptionalText(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static string NormalizeThumbprint(string? thumbprint) =>
        string.Concat((thumbprint ?? string.Empty).Where(ch => !char.IsWhiteSpace(ch))).ToUpperInvariant();

    private static string ComputePublicKeyFingerprint(RSA rsa)
    {
        var subjectPublicKeyInfo = rsa.ExportSubjectPublicKeyInfo();
        var hash = SHA256.HashData(subjectPublicKeyInfo);
        return $"SHA256:{Convert.ToBase64String(hash)}";
    }

    private sealed record ValidatedEnvelope(Envelope Envelope, byte[] PlaintextPayload);

    private sealed class Envelope
    {
        public string? SchemaVersion { get; set; }

        public string? PackageType { get; set; }

        public string? PackageId { get; set; }

        public Guid CredentialId { get; set; }

        public string? KeyId { get; set; }

        public string? KeyVersion { get; set; }

        public string? CredentialStatus { get; set; }

        public string? Environment { get; set; }

        public DateTimeOffset ExpiresAt { get; set; }

        public DateTimeOffset IssuedAt { get; set; }

        public ProtectionBinding? ProtectionBinding { get; set; }

        public CryptoMetadata? CryptoMetadata { get; set; }

        public string? Ciphertext { get; set; }

        public string? AuthTag { get; set; }
    }

    private sealed class ProtectionBinding
    {
        public string? BindingType { get; set; }

        public Guid? BindingId { get; set; }

        public string? CertificateThumbprint { get; set; }

        public string? StoreLocation { get; set; }

        public string? StoreName { get; set; }

        public string? CertificatePath { get; set; }

        public string? PrivateKeyPath { get; set; }

        public string? PublicKeyFingerprint { get; set; }

        public string? KeyId { get; set; }

        public string? KeyVersion { get; set; }
    }

    private sealed class CryptoMetadata
    {
        public string? ContentEncryptionAlgorithm { get; set; }

        public string? KeyEncryptionAlgorithm { get; set; }

        public string? PayloadNonce { get; set; }

        public string? EncryptedDataKey { get; set; }
    }

    private class ServicePayload
    {
        public string? SecretBase64 { get; set; }

        public string? HmacAlgorithm { get; set; }

        public string[]? Scopes { get; set; }
    }

    private sealed class ClientPayload : ServicePayload
    {
        public string? CanonicalSigningProfileId { get; set; }
    }
}
