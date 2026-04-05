using System.Security.Cryptography;
using MyCompany.AuthPlatform.Application;
using MyCompany.Security.MiniKms.Client;

namespace MyCompany.Security.MiniKms;

internal interface IRotatingMasterKeyProvider : IMasterKeyProvider
{
    IReadOnlyList<MiniKmsKeyVersionSummary> ListKeyVersions();

    MiniKmsKeyVersionSummary AddKeyVersion(string? keyVersion, byte[]? masterKey, bool activate);

    MiniKmsKeyVersionSummary ActivateKeyVersion(string keyVersion);

    MiniKmsKeyVersionSummary RetireKeyVersion(string keyVersion);
}

internal sealed class RotatingMasterKeyProvider : IRotatingMasterKeyProvider
{
    private readonly object _sync = new();
    private readonly Dictionary<string, KeyRecord> _keyRecords;
    private string _activeKeyVersion;

    public RotatingMasterKeyProvider(
        IReadOnlyDictionary<string, byte[]> masterKeys,
        string activeKeyVersion)
    {
        if (masterKeys is null || masterKeys.Count == 0)
        {
            throw new ArgumentException("At least one MiniKMS master key must be configured.", nameof(masterKeys));
        }

        if (string.IsNullOrWhiteSpace(activeKeyVersion))
        {
            throw new ArgumentException("An active MiniKMS key version is required.", nameof(activeKeyVersion));
        }

        _activeKeyVersion = activeKeyVersion.Trim();
        _keyRecords = masterKeys.ToDictionary(
            pair => pair.Key,
            pair => new KeyRecord(pair.Value, DateTimeOffset.UtcNow, null, null),
            StringComparer.Ordinal);

        if (!_keyRecords.ContainsKey(_activeKeyVersion))
        {
            throw new InvalidOperationException($"No MiniKMS master key is configured for active key version '{_activeKeyVersion}'.");
        }

        _keyRecords[_activeKeyVersion] = _keyRecords[_activeKeyVersion] with { ActivatedAt = DateTimeOffset.UtcNow };
    }

    public string GetActiveKeyVersion()
    {
        lock (_sync)
        {
            return _activeKeyVersion;
        }
    }

    public byte[] EncryptDataKey(byte[] dataKey, string keyVersion)
    {
        return CreateSnapshot().EncryptDataKey(dataKey, keyVersion);
    }

    public byte[] DecryptDataKey(byte[] encryptedDataKey, string keyVersion)
    {
        return CreateSnapshot().DecryptDataKey(encryptedDataKey, keyVersion);
    }

    public IReadOnlyList<MiniKmsKeyVersionSummary> ListKeyVersions()
    {
        lock (_sync)
        {
            return _keyRecords
                .OrderBy(pair => pair.Key, StringComparer.Ordinal)
                .Select(pair => new MiniKmsKeyVersionSummary(
                    pair.Key,
                    ResolveStatus(pair.Key, pair.Value),
                    string.Equals(pair.Key, _activeKeyVersion, StringComparison.Ordinal),
                    pair.Value.CreatedAt,
                    pair.Value.ActivatedAt,
                    pair.Value.RetiredAt))
                .ToArray();
        }
    }

    public MiniKmsKeyVersionSummary AddKeyVersion(string? keyVersion, byte[]? masterKey, bool activate)
    {
        var resolvedKeyVersion = string.IsNullOrWhiteSpace(keyVersion)
            ? $"kms-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}"
            : keyVersion.Trim();
        var resolvedMasterKey = masterKey ?? RandomNumberGenerator.GetBytes(32);

        if (resolvedMasterKey.Length != 32)
        {
            throw new ArgumentException("MiniKMS master keys must be exactly 32 bytes.", nameof(masterKey));
        }

        lock (_sync)
        {
            if (_keyRecords.ContainsKey(resolvedKeyVersion))
            {
                throw new InvalidOperationException($"MiniKMS key version '{resolvedKeyVersion}' already exists.");
            }

            var now = DateTimeOffset.UtcNow;
            _keyRecords[resolvedKeyVersion] = new KeyRecord(
                resolvedMasterKey.ToArray(),
                now,
                activate ? now : null,
                null);
            if (activate)
            {
                RetireCurrentActiveKey(now);
                _activeKeyVersion = resolvedKeyVersion;
            }

            return new MiniKmsKeyVersionSummary(
                resolvedKeyVersion,
                activate ? "Active" : "Available",
                activate,
                now,
                activate ? now : null,
                null);
        }
    }

    public MiniKmsKeyVersionSummary ActivateKeyVersion(string keyVersion)
    {
        var resolvedKeyVersion = string.IsNullOrWhiteSpace(keyVersion)
            ? throw new ArgumentException("A MiniKMS key version is required.", nameof(keyVersion))
            : keyVersion.Trim();

        lock (_sync)
        {
            if (!_keyRecords.TryGetValue(resolvedKeyVersion, out var record))
            {
                throw new InvalidOperationException($"MiniKMS key version '{resolvedKeyVersion}' does not exist.");
            }

            var now = DateTimeOffset.UtcNow;
            RetireCurrentActiveKey(now);
            _activeKeyVersion = resolvedKeyVersion;
            _keyRecords[resolvedKeyVersion] = record with
            {
                ActivatedAt = now,
                RetiredAt = null
            };
            return new MiniKmsKeyVersionSummary(
                resolvedKeyVersion,
                "Active",
                true,
                record.CreatedAt,
                now,
                null);
        }
    }

    public MiniKmsKeyVersionSummary RetireKeyVersion(string keyVersion)
    {
        var resolvedKeyVersion = string.IsNullOrWhiteSpace(keyVersion)
            ? throw new ArgumentException("A MiniKMS key version is required.", nameof(keyVersion))
            : keyVersion.Trim();

        lock (_sync)
        {
            if (!_keyRecords.TryGetValue(resolvedKeyVersion, out var record))
            {
                throw new InvalidOperationException($"MiniKMS key version '{resolvedKeyVersion}' does not exist.");
            }

            if (string.Equals(resolvedKeyVersion, _activeKeyVersion, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("The active MiniKMS key version cannot be retired directly. Activate a replacement key first.");
            }

            var now = DateTimeOffset.UtcNow;
            var retiredRecord = record with { RetiredAt = now };
            _keyRecords[resolvedKeyVersion] = retiredRecord;
            return new MiniKmsKeyVersionSummary(
                resolvedKeyVersion,
                "Retired",
                false,
                record.CreatedAt,
                record.ActivatedAt,
                now);
        }
    }

    private ConfiguredMasterKeyProvider CreateSnapshot()
    {
        lock (_sync)
        {
            return new ConfiguredMasterKeyProvider(
                _keyRecords.ToDictionary(
                    pair => pair.Key,
                    pair => pair.Value.MasterKey.ToArray(),
                    StringComparer.Ordinal),
                _activeKeyVersion);
        }
    }

    private void RetireCurrentActiveKey(DateTimeOffset retiredAt)
    {
        if (_keyRecords.TryGetValue(_activeKeyVersion, out var currentRecord))
        {
            _keyRecords[_activeKeyVersion] = currentRecord with { RetiredAt = retiredAt };
        }
    }

    private string ResolveStatus(string keyVersion, KeyRecord record)
    {
        if (string.Equals(keyVersion, _activeKeyVersion, StringComparison.Ordinal))
        {
            return "Active";
        }

        return record.RetiredAt.HasValue ? "Retired" : "Available";
    }

    private sealed record KeyRecord(
        byte[] MasterKey,
        DateTimeOffset CreatedAt,
        DateTimeOffset? ActivatedAt,
        DateTimeOffset? RetiredAt);
}
