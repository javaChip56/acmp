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

internal interface IMiniKmsAuditLog
{
    void Write(string action, string outcome, string actor, string? keyVersion, string details);

    IReadOnlyList<MiniKmsAuditEntry> List(int take);
}

internal sealed class RotatingMasterKeyProvider : IRotatingMasterKeyProvider, IMiniKmsAuditLog
{
    private const int MaxAuditEntries = 500;

    private readonly object _sync = new();
    private readonly IMiniKmsStateStore _stateStore;
    private MiniKmsStateSnapshot _snapshot;

    public RotatingMasterKeyProvider(IMiniKmsStateStore stateStore)
    {
        _stateStore = stateStore ?? throw new ArgumentNullException(nameof(stateStore));
        _snapshot = _stateStore.Load();
    }

    public string GetActiveKeyVersion()
    {
        lock (_sync)
        {
            return _snapshot.ActiveKeyVersion;
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
            return _snapshot.KeyRecords
                .OrderBy(pair => pair.Key, StringComparer.Ordinal)
                .Select(pair => new MiniKmsKeyVersionSummary(
                    pair.Key,
                    ResolveStatus(pair.Key, pair.Value),
                    string.Equals(pair.Key, _snapshot.ActiveKeyVersion, StringComparison.Ordinal),
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
            if (_snapshot.KeyRecords.ContainsKey(resolvedKeyVersion))
            {
                throw new InvalidOperationException($"MiniKMS key version '{resolvedKeyVersion}' already exists.");
            }

            var now = DateTimeOffset.UtcNow;
            _snapshot.KeyRecords[resolvedKeyVersion] = new MiniKmsKeyRecord(
                resolvedMasterKey.ToArray(),
                now,
                activate ? now : null,
                null);
            if (activate)
            {
                RetireCurrentActiveKey(now);
                _snapshot = _snapshot with { ActiveKeyVersion = resolvedKeyVersion };
            }
            SaveSnapshot();

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
            if (!_snapshot.KeyRecords.TryGetValue(resolvedKeyVersion, out var record))
            {
                throw new InvalidOperationException($"MiniKMS key version '{resolvedKeyVersion}' does not exist.");
            }

            var now = DateTimeOffset.UtcNow;
            RetireCurrentActiveKey(now);
            _snapshot = _snapshot with { ActiveKeyVersion = resolvedKeyVersion };
            _snapshot.KeyRecords[resolvedKeyVersion] = record with
            {
                ActivatedAt = now,
                RetiredAt = null
            };
            SaveSnapshot();
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
            if (!_snapshot.KeyRecords.TryGetValue(resolvedKeyVersion, out var record))
            {
                throw new InvalidOperationException($"MiniKMS key version '{resolvedKeyVersion}' does not exist.");
            }

            if (string.Equals(resolvedKeyVersion, _snapshot.ActiveKeyVersion, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("The active MiniKMS key version cannot be retired directly. Activate a replacement key first.");
            }

            var now = DateTimeOffset.UtcNow;
            var retiredRecord = record with { RetiredAt = now };
            _snapshot.KeyRecords[resolvedKeyVersion] = retiredRecord;
            SaveSnapshot();
            return new MiniKmsKeyVersionSummary(
                resolvedKeyVersion,
                "Retired",
                false,
                record.CreatedAt,
                record.ActivatedAt,
                now);
        }
    }

    public void Write(string action, string outcome, string actor, string? keyVersion, string details)
    {
        var entry = new MiniKmsAuditEntry(
            Guid.NewGuid().ToString("N"),
            DateTimeOffset.UtcNow,
            action,
            outcome,
            string.IsNullOrWhiteSpace(actor) ? "system" : actor.Trim(),
            string.IsNullOrWhiteSpace(keyVersion) ? null : keyVersion.Trim(),
            details);

        lock (_sync)
        {
            _snapshot.AuditEntries.Insert(0, entry);
            if (_snapshot.AuditEntries.Count > MaxAuditEntries)
            {
                _snapshot.AuditEntries.RemoveRange(MaxAuditEntries, _snapshot.AuditEntries.Count - MaxAuditEntries);
            }

            SaveSnapshot();
        }
    }

    public IReadOnlyList<MiniKmsAuditEntry> List(int take)
    {
        var boundedTake = take <= 0 ? 50 : Math.Min(take, 200);
        lock (_sync)
        {
            return _snapshot.AuditEntries.Take(boundedTake).Select(entry => entry with { }).ToArray();
        }
    }

    private ConfiguredMasterKeyProvider CreateSnapshot()
    {
        lock (_sync)
        {
            return new ConfiguredMasterKeyProvider(
                _snapshot.KeyRecords.ToDictionary(
                    pair => pair.Key,
                    pair => pair.Value.MasterKey.ToArray(),
                    StringComparer.Ordinal),
                _snapshot.ActiveKeyVersion);
        }
    }

    private void RetireCurrentActiveKey(DateTimeOffset retiredAt)
    {
        if (_snapshot.KeyRecords.TryGetValue(_snapshot.ActiveKeyVersion, out var currentRecord))
        {
            _snapshot.KeyRecords[_snapshot.ActiveKeyVersion] = currentRecord with { RetiredAt = retiredAt };
        }
    }

    private string ResolveStatus(string keyVersion, MiniKmsKeyRecord record)
    {
        if (string.Equals(keyVersion, _snapshot.ActiveKeyVersion, StringComparison.Ordinal))
        {
            return "Active";
        }

        return record.RetiredAt.HasValue ? "Retired" : "Available";
    }

    private void SaveSnapshot()
    {
        _stateStore.Save(_snapshot);
    }
}
