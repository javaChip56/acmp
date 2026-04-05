using System.Security.Cryptography;
using MyCompany.Shared.Contracts.Domain;

namespace MyCompany.AuthPlatform.Application;

public sealed record EncryptedSecretPackage(
    byte[] EncryptedSecret,
    byte[] EncryptedDataKey,
    string KeyVersion,
    string EncryptionAlgorithm,
    byte[] Iv,
    byte[] Tag);

public sealed record HmacSecretProtectionResult(
    byte[] EncryptedSecret,
    byte[] EncryptedDataKey,
    string EncryptionAlgorithm,
    byte[] Iv,
    byte[] Tag);

public interface IMasterKeyProvider
{
    string GetActiveKeyVersion();

    byte[] EncryptDataKey(byte[] dataKey, string keyVersion);

    byte[] DecryptDataKey(byte[] encryptedDataKey, string keyVersion);
}

public interface IMiniKms
{
    string ProviderName { get; }

    string ActiveKeyVersion { get; }

    byte[] GenerateRandomSecret(int sizeInBytes = 32);

    EncryptedSecretPackage Encrypt(byte[] plaintext, string? keyVersion = null);

    byte[] Decrypt(EncryptedSecretPackage package);
}

public interface IHmacSecretProtector
{
    byte[] GenerateSecret(int size = 32);

    HmacSecretProtectionResult Protect(byte[] plaintextSecret, string keyVersion);

    byte[] Unprotect(HmacCredentialDetail detail);
}

public sealed class ConfiguredMasterKeyProvider : IMasterKeyProvider
{
    private const int GcmTagSize = 16;
    private const int NonceSize = 12;

    private readonly IReadOnlyDictionary<string, byte[]> _masterKeys;
    private readonly string _activeKeyVersion;

    public ConfiguredMasterKeyProvider(
        IReadOnlyDictionary<string, byte[]> masterKeys,
        string activeKeyVersion)
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

        if (string.IsNullOrWhiteSpace(activeKeyVersion))
        {
            throw new ArgumentException("An active master-key version must be configured.", nameof(activeKeyVersion));
        }

        _activeKeyVersion = activeKeyVersion.Trim();
        _ = ResolveMasterKey(_activeKeyVersion);
    }

    public string GetActiveKeyVersion() => _activeKeyVersion;

    public byte[] EncryptDataKey(byte[] dataKey, string keyVersion)
    {
        ArgumentNullException.ThrowIfNull(dataKey);

        if (dataKey.Length == 0)
        {
            throw new ArgumentException("Data key material is required.", nameof(dataKey));
        }

        var masterKey = ResolveMasterKey(keyVersion);
        var wrappedKeyNonce = RandomNumberGenerator.GetBytes(NonceSize);
        var wrappedKeyCiphertext = new byte[dataKey.Length];
        var wrappedKeyTag = new byte[GcmTagSize];

        using (var keyWrapper = new AesGcm(masterKey, GcmTagSize))
        {
            keyWrapper.Encrypt(wrappedKeyNonce, dataKey, wrappedKeyCiphertext, wrappedKeyTag);
        }

        var wrappedDataKey = new byte[wrappedKeyNonce.Length + wrappedKeyTag.Length + wrappedKeyCiphertext.Length];
        Buffer.BlockCopy(wrappedKeyNonce, 0, wrappedDataKey, 0, wrappedKeyNonce.Length);
        Buffer.BlockCopy(wrappedKeyTag, 0, wrappedDataKey, wrappedKeyNonce.Length, wrappedKeyTag.Length);
        Buffer.BlockCopy(wrappedKeyCiphertext, 0, wrappedDataKey, wrappedKeyNonce.Length + wrappedKeyTag.Length, wrappedKeyCiphertext.Length);
        return wrappedDataKey;
    }

    public byte[] DecryptDataKey(byte[] encryptedDataKey, string keyVersion)
    {
        ArgumentNullException.ThrowIfNull(encryptedDataKey);

        if (encryptedDataKey.Length <= NonceSize + GcmTagSize)
        {
            throw new InvalidOperationException("The wrapped content-encryption key is missing or invalid.");
        }

        var masterKey = ResolveMasterKey(keyVersion);
        var wrappedKeyNonce = encryptedDataKey[..NonceSize];
        var wrappedKeyTag = encryptedDataKey[NonceSize..(NonceSize + GcmTagSize)];
        var wrappedKeyCiphertext = encryptedDataKey[(NonceSize + GcmTagSize)..];
        var contentEncryptionKey = new byte[wrappedKeyCiphertext.Length];

        using (var keyWrapper = new AesGcm(masterKey, GcmTagSize))
        {
            keyWrapper.Decrypt(wrappedKeyNonce, wrappedKeyCiphertext, wrappedKeyTag, contentEncryptionKey);
        }

        return contentEncryptionKey;
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

public sealed class LocalMiniKms : IMiniKms
{
    private const string EncryptionAlgorithm = "MINIKMS-LOCAL-AES256GCM";
    private const int GcmTagSize = 16;
    private const int NonceSize = 12;

    private readonly IMasterKeyProvider _masterKeyProvider;

    public LocalMiniKms(IMasterKeyProvider masterKeyProvider)
    {
        _masterKeyProvider = masterKeyProvider ?? throw new ArgumentNullException(nameof(masterKeyProvider));
    }

    public string ProviderName => "LocalMiniKms";

    public string ActiveKeyVersion => _masterKeyProvider.GetActiveKeyVersion();

    public byte[] GenerateRandomSecret(int sizeInBytes = 32)
    {
        if (sizeInBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(sizeInBytes), "Secret size must be greater than zero.");
        }

        return RandomNumberGenerator.GetBytes(sizeInBytes);
    }

    public EncryptedSecretPackage Encrypt(byte[] plaintext, string? keyVersion = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);

        if (plaintext.Length == 0)
        {
            throw new ArgumentException("Plaintext secret material is required.", nameof(plaintext));
        }

        var resolvedKeyVersion = string.IsNullOrWhiteSpace(keyVersion)
            ? ActiveKeyVersion
            : keyVersion.Trim();
        var contentEncryptionKey = RandomNumberGenerator.GetBytes(32);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[GcmTagSize];

        try
        {
            using (var aesGcm = new AesGcm(contentEncryptionKey, GcmTagSize))
            {
                aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);
            }

            var encryptedDataKey = _masterKeyProvider.EncryptDataKey(contentEncryptionKey, resolvedKeyVersion);
            return new EncryptedSecretPackage(
                ciphertext,
                encryptedDataKey,
                resolvedKeyVersion,
                EncryptionAlgorithm,
                nonce,
                tag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(contentEncryptionKey);
        }
    }

    public byte[] Decrypt(EncryptedSecretPackage package)
    {
        ArgumentNullException.ThrowIfNull(package);

        if (!string.Equals(package.EncryptionAlgorithm, EncryptionAlgorithm, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"Unsupported MiniKMS encryption algorithm '{package.EncryptionAlgorithm}'.");
        }

        if (package.Iv.Length != NonceSize)
        {
            throw new InvalidOperationException("The MiniKMS secret IV is missing or invalid.");
        }

        if (package.Tag.Length != GcmTagSize)
        {
            throw new InvalidOperationException("The MiniKMS secret authentication tag is missing or invalid.");
        }

        var contentEncryptionKey = _masterKeyProvider.DecryptDataKey(package.EncryptedDataKey, package.KeyVersion);

        try
        {
            var plaintext = new byte[package.EncryptedSecret.Length];
            using (var aesGcm = new AesGcm(contentEncryptionKey, GcmTagSize))
            {
                aesGcm.Decrypt(package.Iv, package.EncryptedSecret, package.Tag, plaintext);
            }

            return plaintext;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(contentEncryptionKey);
        }
    }
}

public sealed class MiniKmsHmacSecretProtector : IHmacSecretProtector
{
    private readonly IMiniKms _miniKms;

    public MiniKmsHmacSecretProtector(IMiniKms miniKms)
    {
        _miniKms = miniKms ?? throw new ArgumentNullException(nameof(miniKms));
    }

    public byte[] GenerateSecret(int size = 32) => _miniKms.GenerateRandomSecret(size);

    public HmacSecretProtectionResult Protect(byte[] plaintextSecret, string keyVersion)
    {
        var encryptedPackage = _miniKms.Encrypt(plaintextSecret, keyVersion);
        return new HmacSecretProtectionResult(
            encryptedPackage.EncryptedSecret,
            encryptedPackage.EncryptedDataKey,
            encryptedPackage.EncryptionAlgorithm,
            encryptedPackage.Iv,
            encryptedPackage.Tag);
    }

    public byte[] Unprotect(HmacCredentialDetail detail)
    {
        ArgumentNullException.ThrowIfNull(detail);

        if (detail.Iv is null || detail.Tag is null)
        {
            throw new InvalidOperationException("The protected HMAC credential detail is missing required encryption fields.");
        }

        return _miniKms.Decrypt(new EncryptedSecretPackage(
            detail.EncryptedSecret,
            detail.EncryptedDataKey,
            detail.KeyVersion,
            detail.EncryptionAlgorithm,
            detail.Iv,
            detail.Tag));
    }
}

public sealed class AesGcmHmacSecretProtector : IHmacSecretProtector
{
    private readonly MiniKmsHmacSecretProtector _inner;

    public AesGcmHmacSecretProtector(IReadOnlyDictionary<string, byte[]> masterKeys)
    {
        var activeKeyVersion = masterKeys.Keys.OrderBy(key => key, StringComparer.Ordinal).First();
        _inner = new MiniKmsHmacSecretProtector(
            new LocalMiniKms(new ConfiguredMasterKeyProvider(masterKeys, activeKeyVersion)));
    }

    public byte[] GenerateSecret(int size = 32) => _inner.GenerateSecret(size);

    public HmacSecretProtectionResult Protect(byte[] plaintextSecret, string keyVersion) =>
        _inner.Protect(plaintextSecret, keyVersion);

    public byte[] Unprotect(HmacCredentialDetail detail) => _inner.Unprotect(detail);
}
