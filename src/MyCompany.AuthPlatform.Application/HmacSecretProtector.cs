using System.Security.Cryptography;
using MyCompany.Shared.Contracts.Domain;

namespace MyCompany.AuthPlatform.Application;

public sealed record HmacSecretProtectionResult(
    byte[] EncryptedSecret,
    byte[] EncryptedDataKey,
    string EncryptionAlgorithm,
    byte[] Iv,
    byte[] Tag);

public interface IHmacSecretProtector
{
    byte[] GenerateSecret(int size = 32);

    HmacSecretProtectionResult Protect(byte[] plaintextSecret, string keyVersion);

    byte[] Unprotect(HmacCredentialDetail detail);
}

public sealed class AesGcmHmacSecretProtector : IHmacSecretProtector
{
    private const string EncryptionAlgorithm = "LOCAL-AES256GCM";
    private const int GcmTagSize = 16;
    private const int NonceSize = 12;

    private readonly IReadOnlyDictionary<string, byte[]> _masterKeys;

    public AesGcmHmacSecretProtector(IReadOnlyDictionary<string, byte[]> masterKeys)
    {
        if (masterKeys is null || masterKeys.Count == 0)
        {
            throw new ArgumentException("At least one HMAC secret master key must be configured.", nameof(masterKeys));
        }

        _masterKeys = masterKeys.ToDictionary(
            pair => pair.Key,
            pair =>
            {
                if (pair.Value is null || pair.Value.Length != 32)
                {
                    throw new ArgumentException($"Master key '{pair.Key}' must be exactly 32 bytes.");
                }

                return pair.Value.ToArray();
            },
            StringComparer.Ordinal);
    }

    public byte[] GenerateSecret(int size = 32)
    {
        if (size <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(size), "Secret size must be greater than zero.");
        }

        return RandomNumberGenerator.GetBytes(size);
    }

    public HmacSecretProtectionResult Protect(byte[] plaintextSecret, string keyVersion)
    {
        ArgumentNullException.ThrowIfNull(plaintextSecret);

        if (plaintextSecret.Length == 0)
        {
            throw new ArgumentException("Plaintext secret material is required.", nameof(plaintextSecret));
        }

        var masterKey = ResolveMasterKey(keyVersion);
        var contentEncryptionKey = RandomNumberGenerator.GetBytes(32);
        var secretNonce = RandomNumberGenerator.GetBytes(NonceSize);
        var secretCiphertext = new byte[plaintextSecret.Length];
        var secretTag = new byte[GcmTagSize];

        try
        {
            using (var aesGcm = new AesGcm(contentEncryptionKey, GcmTagSize))
            {
                aesGcm.Encrypt(secretNonce, plaintextSecret, secretCiphertext, secretTag);
            }

            var wrappedKeyNonce = RandomNumberGenerator.GetBytes(NonceSize);
            var wrappedKeyCiphertext = new byte[contentEncryptionKey.Length];
            var wrappedKeyTag = new byte[GcmTagSize];
            using (var keyWrapper = new AesGcm(masterKey, GcmTagSize))
            {
                keyWrapper.Encrypt(wrappedKeyNonce, contentEncryptionKey, wrappedKeyCiphertext, wrappedKeyTag);
            }

            var wrappedDataKey = new byte[wrappedKeyNonce.Length + wrappedKeyTag.Length + wrappedKeyCiphertext.Length];
            Buffer.BlockCopy(wrappedKeyNonce, 0, wrappedDataKey, 0, wrappedKeyNonce.Length);
            Buffer.BlockCopy(wrappedKeyTag, 0, wrappedDataKey, wrappedKeyNonce.Length, wrappedKeyTag.Length);
            Buffer.BlockCopy(wrappedKeyCiphertext, 0, wrappedDataKey, wrappedKeyNonce.Length + wrappedKeyTag.Length, wrappedKeyCiphertext.Length);

            return new HmacSecretProtectionResult(
                secretCiphertext,
                wrappedDataKey,
                EncryptionAlgorithm,
                secretNonce,
                secretTag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(contentEncryptionKey);
        }
    }

    public byte[] Unprotect(HmacCredentialDetail detail)
    {
        ArgumentNullException.ThrowIfNull(detail);

        if (!string.Equals(detail.EncryptionAlgorithm, EncryptionAlgorithm, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"Unsupported credential secret encryption algorithm '{detail.EncryptionAlgorithm}'.");
        }

        if (detail.Iv is null || detail.Iv.Length != NonceSize)
        {
            throw new InvalidOperationException("The credential secret IV is missing or invalid.");
        }

        if (detail.Tag is null || detail.Tag.Length != GcmTagSize)
        {
            throw new InvalidOperationException("The credential secret authentication tag is missing or invalid.");
        }

        if (detail.EncryptedDataKey.Length <= NonceSize + GcmTagSize)
        {
            throw new InvalidOperationException("The wrapped content-encryption key is missing or invalid.");
        }

        var masterKey = ResolveMasterKey(detail.KeyVersion);
        var wrappedKeyNonce = detail.EncryptedDataKey[..NonceSize];
        var wrappedKeyTag = detail.EncryptedDataKey[NonceSize..(NonceSize + GcmTagSize)];
        var wrappedKeyCiphertext = detail.EncryptedDataKey[(NonceSize + GcmTagSize)..];
        var contentEncryptionKey = new byte[wrappedKeyCiphertext.Length];

        try
        {
            using (var keyWrapper = new AesGcm(masterKey, GcmTagSize))
            {
                keyWrapper.Decrypt(wrappedKeyNonce, wrappedKeyCiphertext, wrappedKeyTag, contentEncryptionKey);
            }

            var plaintextSecret = new byte[detail.EncryptedSecret.Length];
            using (var aesGcm = new AesGcm(contentEncryptionKey, GcmTagSize))
            {
                aesGcm.Decrypt(detail.Iv, detail.EncryptedSecret, detail.Tag, plaintextSecret);
            }

            return plaintextSecret;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(contentEncryptionKey);
        }
    }

    private byte[] ResolveMasterKey(string? keyVersion)
    {
        var normalizedKeyVersion = string.IsNullOrWhiteSpace(keyVersion)
            ? throw new InvalidOperationException("A credential key version is required for HMAC secret protection.")
            : keyVersion.Trim();

        if (!_masterKeys.TryGetValue(normalizedKeyVersion, out var masterKey))
        {
            throw new InvalidOperationException($"No HMAC secret master key is configured for key version '{normalizedKeyVersion}'.");
        }

        return masterKey;
    }
}
